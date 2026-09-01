//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/control"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/nfqueue"
	"github.com/getlantern/geneva-server/internal/steering"
	"github.com/getlantern/geneva-server/internal/telemetry"
)

// slogLogger adapts slog to the runtime's Debugf/Errorf logger.
type slogLogger struct{ l *slog.Logger }

// Debugf checks the level before formatting. The runtime's debug path is the
// NFQUEUE read timeout, which fires continuously on an idle queue, so at the
// default Info level the Sprintf would be pure waste on every tick.
func (s slogLogger) Debugf(f string, a ...any) {
	if !s.l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	s.l.Debug(fmt.Sprintf(f, a...))
}

func (s slogLogger) Errorf(f string, a ...any) { s.l.Error(fmt.Sprintf(f, a...)) }

// steeringLogger adapts slog to the steering controller's Infof/Errorf logger.
// The controller's messages are lifecycle events, not per-packet, so they are
// formatted unconditionally.
type steeringLogger struct{ l *slog.Logger }

func (s steeringLogger) Infof(f string, a ...any)  { s.l.Info(fmt.Sprintf(f, a...)) }
func (s steeringLogger) Errorf(f string, a ...any) { s.l.Error(fmt.Sprintf(f, a...)) }

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

	// The controller owns both halves of "what reaches userspace": the NIC's
	// offload state and the steering rules. It installs rules only for the
	// packets the strategy's triggers can match, and nothing at all when the
	// strategy can match nothing — which is what keeps an unassigned eval box
	// and a rolled-back prod box off the data path entirely.
	ctrl := steering.New(eng, steering.Config{
		Mode:        o.Mode,
		Table:       o.Table,
		Port:        o.Port,
		OutQueue:    o.OutQueue,
		InQueue:     o.InQueue,
		Mark:        uint32(o.Mark),
		NFTPath:     o.NFTPath,
		EthtoolPath: o.EthtoolPath,
		Iface:       o.Iface,
		NoNFT:       o.NoNFT,

		ObserveInbound: o.ObserveInbound,
	}, steeringLogger{l: log})
	if err := ctrl.Start(ctx); err != nil {
		return err
	}
	defer func() {
		// Use a fresh context: the root one is already cancelled at shutdown.
		rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := ctrl.Close(rmCtx); err != nil {
			log.Error("steering teardown failed", "err", err)
		}
	}()

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

	// Profiling is opt-in and separate from the control surface: it is a
	// benchmarking tool, and the control surface is unauthenticated on a box
	// that carries traffic. The handlers are registered on a mux of our own
	// rather than through the package's blank-import side effect, so nothing is
	// reachable unless this flag is set.
	if o.PprofAddr != "" {
		pprofMux := http.NewServeMux()
		pprofMux.HandleFunc("/debug/pprof/", pprof.Index)
		pprofMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		pprofMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		pprofMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		pprofMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		pprofSrv := &http.Server{Addr: o.PprofAddr, Handler: pprofMux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Warn("pprof enabled", "addr", o.PprofAddr)
			if err := pprofSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("pprof listener failed", "err", err)
			}
		}()
		defer func() {
			shCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = pprofSrv.Shutdown(shCtx)
		}()
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
	api := control.New(control.Providers{
		Mode:       o.Mode,
		Version:    version,
		Commit:     commit,
		Engine:     eng,
		Canary:     pool,
		Verdicts:   func() any { return rt.Snapshot() },
		InboundTCP: func() any { return censorObs.Snapshot() },
		// A strategy change is not just an engine swap: it can put the box on
		// or take it off the data path, so it has to go through the controller.
		Apply:    ctrl.Apply,
		Steering: func() any { return ctrl.State() },
	})
	httpSrv := &http.Server{
		Addr:              o.ControlAddr,
		Handler:           api.Handler(),
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
