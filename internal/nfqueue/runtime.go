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
// Verdicts are issued in the queue wherever the queue can express them, because
// syscalls are what this package costs. A CPU profile of a tamper-every-packet
// strategy put 41% of the sidecar's time in syscalls and under 10% in the Geneva
// engine, so the useful optimizations are all about doing fewer of them:
//
//   - Unchanged: a bare accept.
//   - One packet out (tamper, the common manipulation): overwrite-and-accept in
//     the queue. No raw socket, and — because the packet resumes where it was
//     queued instead of being injected at the top of the stack — no second trip
//     through netfilter and no routing lookup.
//   - More than one packet out (duplicate/fragment): all but the last are
//     injected through the raw socket, and the last replaces the queued packet.
//     Injecting the earlier ones first preserves the order the strategy chose,
//     since the overwritten packet is only released once this callback returns.
//   - Dropped: a bare drop.
//
// Inbound is single-in/single-out (branching is rejected at parse time), so it
// never needs the raw socket at all.
package nfqueue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/getlantern/geneva/strategy"
	"golang.org/x/sys/unix"

	"github.com/getlantern/geneva-server/internal/engine"
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
//
// The counters are per mechanism, not per intent, and a manipulated packet
// therefore lands in different ones depending on how it reached the wire:
//
//   - Modified: replaced in the queue by an overwrite-and-accept verdict. This
//     is the normal path for a strategy that produces one packet.
//   - Reinjected + Dropped: put on the wire through the raw socket while the
//     queued original was dropped. This is the normal path for the extra packets
//     of a fan-out strategy, and the fallback path when an overwrite verdict is
//     refused.
//
// So "how many packets did the strategy change" is Modified plus the fan-out
// share of Reinjected, and neither counter alone answers it. They are kept
// per-mechanism deliberately: a packet counted in both would make Accepted +
// Dropped + Modified stop reconciling with PacketsIn, which is what makes a
// bypassed or lost packet visible.
type Stats struct {
	Accepted    atomic.Uint64
	Dropped     atomic.Uint64
	Modified    atomic.Uint64
	Reinjected  atomic.Uint64
	InjectFails atomic.Uint64
	// Overruns counts socket-buffer overflows. The packets lost to one were
	// accepted by the queue rules' bypass flag, so the proxy kept serving —
	// they simply never reached the strategy.
	Overruns atomic.Uint64
	// Truncated counts packets the kernel copied only part of. They are
	// accepted unmodified, since manipulating a prefix would put a corrupt
	// packet on the wire, and a nonzero count means the copy length is too
	// small for the traffic on this box.
	Truncated atomic.Uint64
}

// Snapshot is a value copy of Stats.
type Snapshot struct {
	Accepted    uint64 `json:"accepted"`
	Dropped     uint64 `json:"dropped"`
	Modified    uint64 `json:"modified"`
	Reinjected  uint64 `json:"reinjected"`
	InjectFails uint64 `json:"inject_fails"`
	Overruns    uint64 `json:"overruns"`
	Truncated   uint64 `json:"truncated"`
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
		Overruns:    rt.Stats.Overruns.Load(),
		Truncated:   rt.Stats.Truncated.Load(),
	}
}

// Run opens both queues and pumps them until ctx is cancelled. It always
// releases the queues and the raw socket before returning.
//
// One goroutine per queue, and one read buffer and one Scratch per goroutine:
// each queue is processed strictly in order, which is what lets the verdict
// batching hold accepts back safely and lets the engine reuse its working
// memory without synchronization.
func (rt *Runtime) Run(ctx context.Context) error {
	outQ, err := openQueue(rt.cfg.OutQueue, rt.cfg.MaxPacketLen, maxQueueLen)
	if err != nil {
		return fmt.Errorf("open out-queue %d: %w", rt.cfg.OutQueue, err)
	}
	defer func() { _ = outQ.Close() }()

	inQ, err := openQueue(rt.cfg.InQueue, rt.cfg.MaxPacketLen, maxQueueLen)
	if err != nil {
		return fmt.Errorf("open in-queue %d: %w", rt.cfg.InQueue, err)
	}
	defer func() { _ = inQ.Close() }()
	defer func() { _ = rt.reinjector.Close() }()

	// A context of our own, cancelled the moment either pump gives up. Without
	// it, one pump failing would leave the other looping: interrupt makes its
	// read return a deadline error, which pump treats as the ordinary idle-queue
	// case and retries — against a deadline still in the past, so it spins and
	// wg.Wait below never returns.
	pumpCtx, stopPumps := context.WithCancel(ctx)
	defer stopPumps()

	errs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs <- rt.pump(pumpCtx, outQ, strategy.DirectionOutbound) }()
	go func() { defer wg.Done(); errs <- rt.pump(pumpCtx, inQ, strategy.DirectionInbound) }()

	var runErr error
	select {
	case <-ctx.Done():
		runErr = ctx.Err()
	case runErr = <-errs:
	}
	stopPumps()

	// Wake both readers and wait for them before the deferred Close runs. A
	// reader still draining the socket would swallow teardown traffic and leave
	// shutdown hanging until something killed the process.
	outQ.interrupt()
	inQ.interrupt()
	wg.Wait()
	return runErr
}

// pump reads one queue until the context is cancelled.
func (rt *Runtime) pump(ctx context.Context, q *queue, dir strategy.Direction) error {
	scratch := &engine.Scratch{}
	handle := func(p packet) error {
		rt.handle(q, dir, p, scratch)
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := q.read(ctx, handle)
		switch {
		case err == nil:
		case errors.Is(err, unix.ENOBUFS):
			// The socket buffer overflowed and the kernel dropped packets.
			// Those packets were accepted by the bypass flag, so the proxy is
			// unharmed; the strategy simply did not see them.
			rt.Stats.Overruns.Add(1)
			rt.log.Errorf("nfqueue socket overrun: packets bypassed the strategy")
		case errors.Is(err, unix.EAGAIN), errors.Is(err, os.ErrDeadlineExceeded):
			// Expected on an idle queue.
			rt.log.Debugf("nfqueue read: %v", err)
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			return fmt.Errorf("read %s queue: %w", dir, err)
		}
	}
}

// handle runs one packet through the engine and issues its verdict.
func (rt *Runtime) handle(q *queue, dir strategy.Direction, p packet, scratch *engine.Scratch) {
	if p.truncated {
		// Fail open: a prefix of a packet cannot be manipulated or reinjected.
		rt.Stats.Truncated.Add(1)
		rt.accept(q, p.id)
		return
	}
	if len(p.payload) == 0 {
		// Counted like any other accept: this path is indistinguishable from a
		// pass-through as far as the flow is concerned, and leaving it out
		// makes the verdict counters undercount what was actually accepted.
		rt.accept(q, p.id)
		return
	}

	if rt.cfg.Observer != nil {
		rt.cfg.Observer.Observe(p.payload, dir)
	}

	res, err := rt.eng.Process(p.payload, dir, scratch)
	if err != nil {
		// Fail open: a strategy or decode error must never black-hole the
		// proxy's traffic.
		rt.log.Errorf("process %s packet: %v", dir, err)
		rt.accept(q, p.id)
		return
	}

	if dir == strategy.DirectionOutbound {
		rt.verdictOutbound(q, p.id, res)
	} else {
		rt.verdictInbound(q, p.id, res)
	}
}

// verdictOutbound issues the outbound verdict, using the queue itself for
// everything but the extra packets a fan-out strategy produces.
//
// If a strategy produced replacement packets but none of them could be
// delivered, the original is accepted instead of dropped: dropping it would
// black-hole the flow, and failing open keeps the proxy serving.
func (rt *Runtime) verdictOutbound(q *queue, id uint32, res engine.Result) {
	if res.Outcome == engine.OutcomeUnchanged {
		rt.accept(q, id)
		return
	}
	if len(res.Packets) == 0 {
		rt.drop(q, id)
		return
	}

	// Everything except the last replacement goes out through the raw socket,
	// in order; the last one replaces the queued packet.
	extras := res.Packets[:len(res.Packets)-1]
	last := res.Packets[len(res.Packets)-1]
	injected := 0
	for _, p := range extras {
		if err := rt.reinjector.Inject(p); err != nil {
			rt.log.Errorf("reinject: %v", err)
			rt.Stats.InjectFails.Add(1)
			continue
		}
		injected++
		rt.Stats.Reinjected.Add(1)
	}
	if err := q.verdict(id, nfAccept, last); err != nil {
		// The queued packet could not be replaced. Fall back to the older path
		// — inject the replacement and drop the original — so a kernel that
		// rejects the modified verdict still applies the strategy.
		rt.log.Errorf("mod-accept outbound: %v", err)
		if err := rt.reinjector.Inject(last); err != nil {
			rt.log.Errorf("reinject after mod-accept failure: %v", err)
			rt.Stats.InjectFails.Add(1)
			if injected == 0 {
				rt.log.Errorf("no replacement packet reached the wire; accepting original to avoid black-hole")
				rt.accept(q, id)
				return
			}
		} else {
			// Counted as a reinjection rather than a modification: the packet
			// reached the wire through the raw socket, and the original is
			// dropped just below. See the Stats doc for why these stay
			// per-mechanism instead of both being incremented.
			rt.Stats.Reinjected.Add(1)
		}
		rt.drop(q, id)
		return
	}
	rt.Stats.Modified.Add(1)
}

// verdictInbound handles the single-in/single-out inbound path with in-queue
// verdicts only — no reinjection.
func (rt *Runtime) verdictInbound(q *queue, id uint32, res engine.Result) {
	switch res.Outcome {
	case engine.OutcomeUnchanged:
		rt.accept(q, id)
	case engine.OutcomeDropped:
		rt.drop(q, id)
	case engine.OutcomeTampered:
		if err := q.verdict(id, nfAccept, res.Packets[0]); err != nil {
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

// accept defers the accept into the queue's batch; it is flushed at the end of
// the read, or ahead of any individual verdict for a later packet.
func (rt *Runtime) accept(q *queue, id uint32) {
	q.accept(id)
	rt.Stats.Accepted.Add(1)
}

func (rt *Runtime) drop(q *queue, id uint32) {
	if err := q.verdict(id, nfDrop, nil); err != nil {
		rt.log.Errorf("drop verdict: %v", err)
	}
	rt.Stats.Dropped.Add(1)
}
