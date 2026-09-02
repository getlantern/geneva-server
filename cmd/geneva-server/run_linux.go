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
	"github.com/getlantern/geneva-server/internal/flowtrack"
	"github.com/getlantern/geneva-server/internal/nfqueue"
	"github.com/getlantern/geneva-server/internal/nftables"
	"github.com/getlantern/geneva-server/internal/steering"
	"github.com/getlantern/geneva-server/internal/telemetry"
)

// slogLogger adapts slog to the printf-style loggers the runtime and the
// steering controller want; one adapter satisfies both interfaces.
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

// Infof formats unconditionally: its callers log lifecycle events, not
// per-packet ones.
func (s slogLogger) Infof(f string, a ...any)  { s.l.Info(fmt.Sprintf(f, a...)) }
func (s slogLogger) Errorf(f string, a ...any) { s.l.Error(fmt.Sprintf(f, a...)) }

// censorReadInterval is how often the kernel classification counters are read.
// One nft invocation per read, feeding a metric exported on a much slower
// cadence, so this only has to be quick enough that two consecutive /healthz
// calls do not return the same numbers.
const censorReadInterval = 2 * time.Second

func runServer(o *runCmd) (runResult error) {
	ctx := context.Background()
	started := time.Now()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	dna, err := o.resolveStrategy()
	if err != nil {
		return err
	}
	eng := engine.NewRegistry()
	log.Info("engine registry ready", "mode", o.Mode)

	// eval mode captures a per-market canary pool from live traffic.
	var pool *canary.Pool
	observers := make([]nfqueue.Observer, 0, 2)
	if o.Mode == "eval" {
		pool = canary.NewPool(o.Market, o.CanaryCapacity)
		observers = append(observers, pool)
	}

	// Signals cancel the root context so cleanup (nft teardown) always runs.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fatalCause := make(chan error, 1)
	reportFatal := func(err error) {
		select {
		case fatalCause <- err:
		default:
		}
		stop()
	}

	// The controller owns both halves of "what reaches userspace": the NIC's
	// offload state and the steering rules. It installs rules only for the
	// packets the strategy's triggers can match, and nothing at all when the
	// strategy can match nothing — which is what keeps an unassigned eval box
	// and a rolled-back prod box off the data path entirely.
	ctrl := steering.New(eng, steering.Config{
		Mode: o.Mode,
		NFT: nftables.Config{
			Table:     o.Table,
			Port:      o.Port,
			OutQueue:  o.OutQueue,
			InQueue:   o.InQueue,
			BypassUID: uint32(o.ReinjectBypassUID),
			NFTPath:   o.NFTPath,
			Censor:    o.CensorCounters,
		},
		EthtoolPath: o.EthtoolPath,
		Iface:       o.Iface,
		NoNFT:       o.NoNFT,

		ObserveInbound:            o.ObserveInbound,
		StateFile:                 o.AdapterStateFile,
		Connections:               flowtrack.Counter{},
		MaxGenerations:            o.MaxGenerations,
		MaxScopedGenerations:      o.MaxScopedGenerations,
		MaxEveryPacketGenerations: o.MaxEveryPacketGenerations,
		RuntimeVersion:            version,
		Fatal: func(err error) {
			log.Error("fatal steering integrity failure", "err", err)
			reportFatal(err)
		},
	}, slogLogger{l: log})
	// The inbound censor classifier runs in both modes: a prod box's IP gets
	// burned the same way a test box's does, and the fleet-wide burn rate is
	// what sizes the clean-IP budget for exploration.
	//
	// Where those counts come from is the interesting part. Steering is scoped
	// to what the strategy can act on, so an outbound-only strategy delivers no
	// inbound packet to userspace, and a classifier fed by NFQUEUE would see
	// nothing at all. The kernel counters classify what arrives without queueing
	// any of it, which is both the complete answer and the free one. The
	// userspace classifier stays as the fallback for a box that turns them off,
	// where it sees whatever the strategy happened to steer.
	var censorSrc censor.Source
	if o.CensorCounters {
		censorSrc = censor.NewKernelSource(ctrl.CensorCounts, censorReadInterval)
	} else {
		obs := censor.New()
		observers = append(observers, obs)
		censorSrc = obs
	}
	observer := nfqueue.Observers(observers...)

	// NFQUEUE runtime.
	rt, err := nfqueue.New(eng, nfqueue.Config{
		OutQueue:         o.OutQueue,
		InQueue:          o.InQueue,
		MaxQueueLen:      o.QueueMaxLen,
		Observer:         observer,
		Logger:           slogLogger{l: log},
		IntegrityFailure: ctrl.IntegrityFailure,
	})
	if err != nil {
		return err
	}
	// Queue ownership and required kernel fail-open configuration must be
	// acknowledged before any active steering can exist.
	if err := rt.Open(); err != nil {
		_ = rt.Close()
		return err
	}
	if err := ctrl.Start(ctx, dna); err != nil {
		startErr := err
		var teardownErr error
		for attempt := 1; attempt <= 3; attempt++ {
			rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			teardownErr = ctrl.Close(rmCtx)
			cancel()
			if teardownErr == nil {
				return errors.Join(startErr, rt.Close())
			}
			if attempt < 3 {
				time.Sleep(50 * time.Millisecond)
			}
		}
		// Do not explicitly release the queues while kernel steering might remain.
		// The command is terminating, so process teardown becomes the last-resort
		// fail-open boundary after reporting the unconfirmed cleanup.
		return errors.Join(startErr, fmt.Errorf("startup steering cleanup could not be confirmed: %w", teardownErr))
	}
	// Queue descriptors stay owned until teardown has read back the absence of
	// steering. On a failed removal, retry while the queues remain bound; never
	// deliberately create a foreign-listener/no-listener window.
	defer func() {
		var teardownErr error
		for attempt := 1; attempt <= 3; attempt++ {
			rmCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			teardownErr = ctrl.Close(rmCtx)
			cancel()
			if teardownErr == nil {
				if err := rt.Close(); err != nil {
					log.Error("NFQUEUE close failed", "err", err)
				}
				return
			}
			log.Error("steering teardown failed while queues remain bound", "attempt", attempt, "err", teardownErr)
			if attempt < 3 {
				time.Sleep(50 * time.Millisecond)
			}
		}
		// The process is already terminating. Leave the descriptors open until
		// kernel process cleanup rather than releasing them ahead of live rules.
		log.Error("unable to confirm steering removal; retaining NFQUEUE ownership until process exit", "err", teardownErr)
		runResult = errors.Join(runResult,
			fmt.Errorf("shutdown steering cleanup could not be confirmed: %w", teardownErr))
	}()

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
			Censor:  censorSrc,
			Started: started,
			Verdicts: func() telemetry.Verdicts {
				s := rt.Snapshot()
				return telemetry.Verdicts{
					Accepted:    s.Accepted,
					Dropped:     s.Dropped,
					Modified:    s.Modified,
					Reinjected:  s.Reinjected,
					InjectFails: s.InjectFails,
					Overruns:    s.Overruns,
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
		InboundTCP: func() any { return censorSrc.Snapshot() },
		// A strategy change is not just an engine swap: it can put the box on
		// or take it off the data path, so it has to go through the controller.
		Apply:    ctrl.Apply,
		Steering: func() any { return ctrl.State() },
		Health: func() error {
			state := ctrl.State()
			if state.Unsafe {
				return errors.New(state.IntegrityFailure)
			}
			return nil
		},
		Adapter:        ctrl,
		LegacyStrategy: o.LegacyStrategyAPI,
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
	runResult = runtimeExitError(err, fatalCause, serveErr)
	if runResult == nil {
		log.Info("shutting down")
	}
	return runResult
}

// runtimeExitError preserves the difference systemd needs: operator shutdown
// is clean, while an integrity fatal or failed control listener exits nonzero.
func runtimeExitError(runErr error, fatalCause <-chan error, serveErr <-chan error) error {
	select {
	case fatalErr := <-fatalCause:
		return fmt.Errorf("fatal steering integrity failure: %w", fatalErr)
	default:
	}

	// If the control listener failed, surface that as the exit error rather than
	// reporting a clean shutdown: the process must not exit 0 when the control
	// surface never came up.
	select {
	case serr := <-serveErr:
		return fmt.Errorf("control surface failed: %w", serr)
	default:
	}

	if errors.Is(runErr, context.Canceled) {
		return nil
	}
	return runErr
}
