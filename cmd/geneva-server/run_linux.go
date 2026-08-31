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
	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/control"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/netdev"
	"github.com/getlantern/geneva-server/internal/nfqueue"
	"github.com/getlantern/geneva-server/internal/nftables"
	"github.com/getlantern/geneva-server/internal/telemetry"
)

// slogLogger adapts slog to the runtime's Debugf/Errorf logger.
type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Debugf(f string, a ...any) { s.l.Debug(fmt.Sprintf(f, a...)) }
func (s slogLogger) Errorf(f string, a ...any) { s.l.Error(fmt.Sprintf(f, a...)) }

func runServer(o *runCmd) error {
	ctx := context.Background()
	started := time.Now()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dna, err := o.resolveStrategy()
	if err != nil {
		return err
	}
	eng, err := engine.New(dna)
	if err != nil {
		return err
	}
	log.Info("engine ready", "mode", o.Mode, "strategy", eng.DNA())

	// eval mode captures a per-market canary pool from live traffic.
	var pool *canary.Pool
	observers := make([]nfqueue.Observer, 0, 2)
	if o.Mode == "eval" {
		pool = canary.NewPool(o.Market, o.CanaryCapacity)
		observers = append(observers, pool)
	}

	// The inbound censor classifier runs in both modes: a prod box's IP gets
	// burned the same way a test box's does, and the fleet-wide burn rate is
	// what sizes the clean-IP budget for exploration.
	censorObs := censor.New()
	observers = append(observers, censorObs)
	observer := nfqueue.Observers(observers...)

	// Signals cancel the root context so cleanup (nft teardown) always runs.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Disable NIC offloads on the steered interface so NFQUEUE yields real,
	// MTU-sized, fully-checksummed packets that reinjection can put back on the
	// wire intact.
	if o.Iface != "" {
		summary, err := netdev.DisableOffload(ctx, o.EthtoolPath, o.Iface)
		if err != nil {
			return err
		}
		log.Info("NIC offloads adjusted", "iface", o.Iface, "result", summary)
	}

	// Program the steering rules. They are torn down on any exit path.
	nft := nftables.New(nftables.Config{
		Table:    o.Table,
		Port:     o.Port,
		OutQueue: o.OutQueue,
		InQueue:  o.InQueue,
		Mark:     uint32(o.Mark),
		NFTPath:  o.NFTPath,
	})
	if !o.NoNFT {
		if err := nft.Install(ctx); err != nil {
			return err
		}
		log.Info("nftables steering installed", "table", o.Table, "port", o.Port)
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
		OutQueue: o.OutQueue,
		InQueue:  o.InQueue,
		Mark:     uint32(o.Mark),
		Observer: observer,
		Logger:   slogLogger{l: log},
	})
	if err != nil {
		return err
	}

	// Metric export is opt-in: with no OTLP endpoint configured there is no
	// collector on the box to export to, so the provider is never built.
	if telemetry.Enabled() {
		shutdown, err := telemetry.Init(ctx)
		if err != nil {
			return fmt.Errorf("init telemetry: %w", err)
		}
		defer shutdown()
		if err := telemetry.Register(telemetry.Providers{
			Mode:    o.Mode,
			Market:  o.Market,
			Engine:  eng,
			Censor:  censorObs,
			Started: started,
			Verdicts: func() telemetry.Verdicts {
				s := rt.Snapshot()
				return telemetry.Verdicts{
					Accepted:    s.Accepted,
					Dropped:     s.Dropped,
					Modified:    s.Modified,
					Reinjected:  s.Reinjected,
					InjectFails: s.InjectFails,
				}
			},
		}); err != nil {
			return fmt.Errorf("register metrics: %w", err)
		}
		log.Info("metric export enabled", "service", telemetry.ServiceName)
	} else {
		log.Info("metric export disabled: no OTEL_EXPORTER_OTLP_* endpoint configured")
	}

	// Control/health surface.
	ctrl := control.New(control.Providers{
		Mode:       o.Mode,
		Version:    version,
		Commit:     commit,
		Engine:     eng,
		Canary:     pool,
		Verdicts:   func() any { return rt.Snapshot() },
		InboundTCP: func() any { return censorObs.Snapshot() },
	})
	httpSrv := &http.Server{
		Addr:              o.ControlAddr,
		Handler:           ctrl.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Bound the whole request read: strategy uploads call io.ReadAll, so a
		// slow client must not be able to hold a handler open indefinitely.
		ReadTimeout: 30 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		log.Info("control surface listening", "addr", o.ControlAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("control surface failed", "err", err)
			serveErr <- err
			stop() // bring the whole process down; a dead control plane is fatal
		}
	}()
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()

	log.Info("nfqueue runtime starting", "out_queue", o.OutQueue, "in_queue", o.InQueue)
	err = rt.Run(ctx)

	// If the control listener failed, surface that as the exit error rather than
	// reporting a clean shutdown: the process must not exit 0 when the control
	// surface never came up.
	select {
	case serr := <-serveErr:
		return fmt.Errorf("control surface failed: %w", serr)
	default:
	}

	if errors.Is(err, context.Canceled) {
		log.Info("shutting down")
		return nil
	}
	return err
}
