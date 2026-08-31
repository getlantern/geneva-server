//go:build linux

// Package nfqueue is the privileged runtime: it pulls the proxy's packets out of
// two NFQUEUE queues (one per direction), applies the Geneva strategy through
// the engine, and issues the correct verdict — accept, drop, overwrite, or
// raw-socket reinjection.
//
// Directions are separated by queue rather than inferred per packet: the
// nftables rules send egress to the out-queue and ingress to the in-queue, so
// each callback knows its direction unambiguously.
//
// Outbound packets can fan out (duplicate/fragment) or change size (tamper), so
// a matched outbound packet is dropped in the queue and its replacements are
// reinjected through the raw socket. Inbound is single-in/single-out (branching
// is rejected at parse time), so it is handled entirely with the in-queue
// verdict: accept, drop, or overwrite-and-accept.
package nfqueue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	nfq "github.com/florianl/go-nfqueue/v2"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva/strategy"
)

// Observer is notified of every packet before manipulation, for eval-mode canary
// capture. It must be safe for concurrent use and must not retain the slice.
type Observer interface {
	Observe(raw []byte, dir strategy.Direction)
}

// Logger is the minimal logging surface the runtime needs.
type Logger interface {
	Debugf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Errorf(string, ...any) {}

// Config configures the runtime.
type Config struct {
	OutQueue uint16
	InQueue  uint16
	Mark     uint32
	// MaxPacketLen bounds how many bytes the kernel copies per packet. 0xffff
	// covers any IPv4 packet.
	MaxPacketLen uint32
	Observer     Observer
	Logger       Logger
}

// Stats counts verdicts and reinjection outcomes.
type Stats struct {
	Accepted    atomic.Uint64
	Dropped     atomic.Uint64
	Modified    atomic.Uint64
	Reinjected  atomic.Uint64
	InjectFails atomic.Uint64
}

// Snapshot is a value copy of Stats.
type Snapshot struct {
	Accepted    uint64 `json:"accepted"`
	Dropped     uint64 `json:"dropped"`
	Modified    uint64 `json:"modified"`
	Reinjected  uint64 `json:"reinjected"`
	InjectFails uint64 `json:"inject_fails"`
}

// Runtime binds the engine to the two queues and the reinjector.
type Runtime struct {
	eng        *engine.Engine
	reinjector *Reinjector
	cfg        Config
	log        Logger
	Stats      Stats
}

// New builds a runtime. The reinjector is created here so a missing capability
// fails fast at startup rather than on the first packet.
func New(eng *engine.Engine, cfg Config) (*Runtime, error) {
	if cfg.MaxPacketLen == 0 {
		cfg.MaxPacketLen = 0xffff
	}
	if cfg.Logger == nil {
		cfg.Logger = nopLogger{}
	}
	r, err := NewReinjector(cfg.Mark)
	if err != nil {
		return nil, err
	}
	return &Runtime{eng: eng, reinjector: r, cfg: cfg, log: cfg.Logger}, nil
}

// Snapshot returns the current verdict counters.
func (rt *Runtime) Snapshot() Snapshot {
	return Snapshot{
		Accepted:    rt.Stats.Accepted.Load(),
		Dropped:     rt.Stats.Dropped.Load(),
		Modified:    rt.Stats.Modified.Load(),
		Reinjected:  rt.Stats.Reinjected.Load(),
		InjectFails: rt.Stats.InjectFails.Load(),
	}
}

// Run opens both queues, registers the callbacks, and blocks until ctx is
// cancelled. It always releases the queues and the raw socket before returning.
func (rt *Runtime) Run(ctx context.Context) error {
	outQ, err := rt.open(rt.cfg.OutQueue)
	if err != nil {
		return fmt.Errorf("open out-queue %d: %w", rt.cfg.OutQueue, err)
	}
	defer func() { _ = outQ.Close() }()

	inQ, err := rt.open(rt.cfg.InQueue)
	if err != nil {
		return fmt.Errorf("open in-queue %d: %w", rt.cfg.InQueue, err)
	}
	defer func() { _ = inQ.Close() }()
	defer func() { _ = rt.reinjector.Close() }()

	if err := outQ.RegisterWithErrorFunc(ctx, rt.hook(outQ, strategy.DirectionOutbound), rt.errHook); err != nil {
		return fmt.Errorf("register out-queue: %w", err)
	}
	if err := inQ.RegisterWithErrorFunc(ctx, rt.hook(inQ, strategy.DirectionInbound), rt.errHook); err != nil {
		return fmt.Errorf("register in-queue: %w", err)
	}

	<-ctx.Done()
	return ctx.Err()
}

func (rt *Runtime) open(queue uint16) (*nfq.Nfqueue, error) {
	return nfq.Open(&nfq.Config{
		NfQueue:      queue,
		MaxPacketLen: rt.cfg.MaxPacketLen,
		MaxQueueLen:  0xffff,
		Copymode:     nfq.NfQnlCopyPacket,
	})
}

func (rt *Runtime) errHook(e error) int {
	// A read timeout is expected and not fatal — log it quietly. Everything else
	// is logged at error level. Either way the queue stays open.
	if errors.Is(e, os.ErrDeadlineExceeded) {
		rt.log.Debugf("nfqueue read timeout: %v", e)
	} else {
		rt.log.Errorf("nfqueue error: %v", e)
	}
	return 0
}

func (rt *Runtime) hook(q *nfq.Nfqueue, dir strategy.Direction) nfq.HookFunc {
	return func(a nfq.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID
		if a.Payload == nil || len(*a.Payload) == 0 {
			// Counted like any other accept: this path is indistinguishable from
			// a pass-through as far as the flow is concerned, and leaving it out
			// makes the verdict counters undercount what was actually accepted.
			rt.accept(q, id)
			return 0
		}
		raw := *a.Payload

		if rt.cfg.Observer != nil {
			rt.cfg.Observer.Observe(raw, dir)
		}

		res, err := rt.eng.Process(raw, dir)
		if err != nil {
			// Fail open: a strategy or decode error must never black-hole the
			// proxy's traffic.
			rt.log.Errorf("process %s packet: %v", dir, err)
			rt.accept(q, id)
			return 0
		}

		if dir == strategy.DirectionOutbound {
			rt.verdictOutbound(q, id, res)
		} else {
			rt.verdictInbound(q, id, res)
		}
		return 0
	}
}

// verdictOutbound: unchanged packets are accepted as-is; everything else drops
// the original and reinjects the replacement packets (possibly none, for a drop).
//
// If a strategy produced replacement packets but every reinjection failed, the
// original is accepted instead of dropped: dropping it would black-hole the
// flow, and failing open keeps the proxy serving.
func (rt *Runtime) verdictOutbound(q *nfq.Nfqueue, id uint32, res engine.Result) {
	if res.Outcome == engine.OutcomeUnchanged {
		rt.accept(q, id)
		return
	}
	injected := 0
	for _, p := range res.Packets {
		if err := rt.reinjector.Inject(p); err != nil {
			rt.log.Errorf("reinject: %v", err)
			rt.Stats.InjectFails.Add(1)
			continue
		}
		injected++
		rt.Stats.Reinjected.Add(1)
	}
	if len(res.Packets) > 0 && injected == 0 {
		rt.log.Errorf("all %d replacement packets failed to reinject; accepting original to avoid black-hole", len(res.Packets))
		rt.accept(q, id)
		return
	}
	_ = q.SetVerdict(id, nfq.NfDrop)
	rt.Stats.Dropped.Add(1)
}

// verdictInbound handles the single-in/single-out inbound path with in-queue
// verdicts only — no reinjection.
func (rt *Runtime) verdictInbound(q *nfq.Nfqueue, id uint32, res engine.Result) {
	switch res.Outcome {
	case engine.OutcomeUnchanged:
		rt.accept(q, id)
	case engine.OutcomeDropped:
		_ = q.SetVerdict(id, nfq.NfDrop)
		rt.Stats.Dropped.Add(1)
	case engine.OutcomeTampered:
		if err := q.SetVerdictWithOption(id, nfq.NfAccept, nfq.WithAlteredPacket(res.Packets[0])); err != nil {
			rt.log.Errorf("mod-accept inbound: %v", err)
			rt.accept(q, id)
			return
		}
		rt.Stats.Modified.Add(1)
	default:
		// Branching is rejected for inbound at parse time; if it somehow
		// produced multiple packets, accept the original unchanged rather than
		// guess. This is defensive and should not occur.
		rt.log.Errorf("inbound strategy produced %d packets; accepting original", len(res.Packets))
		rt.accept(q, id)
	}
}

func (rt *Runtime) accept(q *nfq.Nfqueue, id uint32) {
	_ = q.SetVerdict(id, nfq.NfAccept)
	rt.Stats.Accepted.Add(1)
}
