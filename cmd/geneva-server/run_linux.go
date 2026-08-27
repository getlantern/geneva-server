//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/control"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/netdev"
	"github.com/getlantern/geneva-server/internal/nfqueue"
	"github.com/getlantern/geneva-server/internal/nftables"
)

// slogLogger adapts slog to the runtime's Debugf/Errorf logger.
type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Debugf(f string, a ...any) { s.l.Debug(fmt.Sprintf(f, a...)) }
func (s slogLogger) Errorf(f string, a ...any) { s.l.Error(fmt.Sprintf(f, a...)) }

func runServer(ctx context.Context, o *options) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dna, err := o.resolveStrategy()
	if err != nil {
		return err
	}
	eng, err := engine.New(dna)
	if err != nil {
		return err
	}
	log.Info("engine ready", "mode", o.mode, "strategy", eng.DNA())

	// eval mode captures a per-market canary pool from live traffic.
	var pool *canary.Pool
	var observer nfqueue.Observer
	if o.mode == "eval" {
		pool = canary.NewPool(o.market, o.canaryCapacity)
		observer = pool
	}

	// Signals cancel the root context so cleanup (nft teardown) always runs.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Disable NIC offloads on the steered interface so NFQUEUE yields real,
	// MTU-sized, fully-checksummed packets that reinjection can put back on the
	// wire intact.
	if o.iface != "" {
		summary, err := netdev.DisableOffload(ctx, o.ethtoolPath, o.iface)
		if err != nil {
			return err
		}
		log.Info("NIC offloads adjusted", "iface", o.iface, "result", summary)
	}

	// Program the steering rules. They are torn down on any exit path.
	nft := nftables.New(nftables.Config{
		Table:    o.table,
		Port:     o.port,
		OutQueue: o.outQueue,
		InQueue:  o.inQueue,
		Mark:     o.mark,
		NFTPath:  o.nftPath,
	})
	if !o.noNFT {
		if err := nft.Install(ctx); err != nil {
			return err
		}
		log.Info("nftables steering installed", "table", o.table, "port", o.port)
		defer func() {
			// Use a fresh context: the root one is already cancelled at shutdown.
			rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := nft.Remove(rmCtx); err != nil {
				log.Error("nftables teardown failed", "err", err)
			} else {
				log.Info("nftables steering removed")
			}
		}()
	}

	// NFQUEUE runtime.
	rt, err := nfqueue.New(eng, nfqueue.Config{
		OutQueue: o.outQueue,
		InQueue:  o.inQueue,
		Mark:     o.mark,
		Observer: observer,
		Logger:   slogLogger{l: log},
	})
	if err != nil {
		return err
	}

	// Control/health surface.
	ctrl := control.New(control.Providers{
		Mode:        o.mode,
		Version:     version,
		Commit:      commit,
		Engine:      eng,
		Canary:      pool,
		Verdicts:    func() any { return rt.Snapshot() },
		AllowReload: o.mode == "eval",
	})
	httpSrv := &http.Server{
		Addr:              o.controlAddr,
		Handler:           ctrl.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Info("control surface listening", "addr", o.controlAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("control surface failed", "err", err)
			stop() // bring the whole process down; a dead control plane is fatal
		}
	}()
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()

	log.Info("nfqueue runtime starting", "out_queue", o.outQueue, "in_queue", o.inQueue)
	err = rt.Run(ctx)
	if errors.Is(err, context.Canceled) {
		log.Info("shutting down")
		return nil
	}
	return err
}
