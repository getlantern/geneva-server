// Package engine embeds the getlantern/geneva strategy library and turns raw
// IPv4/TCP packet bytes (as delivered by NFQUEUE) into a verdict plus the
// replacement packets to reinject.
//
// The engine is deliberately decoupled from the genetic algorithm: it only
// parses, validates, and applies a strategy. Strategy evolution, fitness, and
// selection live in the GA brain (a separate lantern-cloud worker).
//
// The geneva library owns checksum and TCP-sequence recomputation, and it
// preserves fields that a tamper action intentionally corrupts. The engine
// therefore reinjects the library's serialized bytes verbatim and must never
// recompute or "fix up" a checksum itself — doing so would clobber a
// deliberately malformed segment that is the whole point of a Geneva strategy.
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/getlantern/geneva"
	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Outcome classifies what a strategy did to a single packet, for observability
// and the overhead measurements the GA pre-screen reads.
type Outcome int

const (
	// OutcomeUnchanged means no action tree matched, or a matching tree passed
	// the packet through byte-for-byte.
	OutcomeUnchanged Outcome = iota
	// OutcomeDropped means the strategy discarded the packet (zero packets out).
	OutcomeDropped
	// OutcomeTampered means one packet came out but its bytes differ from the input.
	OutcomeTampered
	// OutcomeExpanded means more than one packet came out (duplicate/fragment trees).
	OutcomeExpanded
)

func (o Outcome) String() string {
	switch o {
	case OutcomeUnchanged:
		return "unchanged"
	case OutcomeDropped:
		return "dropped"
	case OutcomeTampered:
		return "tampered"
	case OutcomeExpanded:
		return "expanded"
	default:
		return "unknown"
	}
}

// Result is the outcome of processing one packet.
type Result struct {
	// Outcome classifies the transformation for metrics.
	Outcome Outcome
	// Packets holds the serialized replacement packets, in order. It is empty
	// for a dropped packet and holds exactly the input bytes for an unchanged
	// packet. Each entry is a complete IPv4 packet ready for reinjection.
	//
	// The entries alias the Scratch passed to Process and are only valid until
	// the next Process call with that Scratch.
	Packets [][]byte
}

// Stats are cumulative counters used for health and overhead pre-screening.
// Overhead is derived by the caller from PacketsIn vs PacketsOut / BytesIn vs
// BytesOut. All fields are accessed atomically.
type Stats struct {
	PacketsIn  atomic.Uint64
	PacketsOut atomic.Uint64
	BytesIn    atomic.Uint64
	BytesOut   atomic.Uint64
	Unchanged  atomic.Uint64
	Dropped    atomic.Uint64
	Tampered   atomic.Uint64
	Expanded   atomic.Uint64
	Errors     atomic.Uint64
	// Swaps counts strategies installed in place after the initial load, so a
	// hot swap is observable without putting the DNA (or a candidate id) into a
	// telemetry label.
	Swaps atomic.Uint64
}

// Snapshot is a plain-value copy of Stats for serialization.
type Snapshot struct {
	PacketsIn      uint64  `json:"packets_in"`
	PacketsOut     uint64  `json:"packets_out"`
	BytesIn        uint64  `json:"bytes_in"`
	BytesOut       uint64  `json:"bytes_out"`
	Unchanged      uint64  `json:"unchanged"`
	Dropped        uint64  `json:"dropped"`
	Tampered       uint64  `json:"tampered"`
	Expanded       uint64  `json:"expanded"`
	Errors         uint64  `json:"errors"`
	Swaps          uint64  `json:"swaps"`
	PacketOverhead float64 `json:"packet_overhead"`
	ByteOverhead   float64 `json:"byte_overhead"`
}

func (s *Stats) snapshot() Snapshot {
	in := s.PacketsIn.Load()
	out := s.PacketsOut.Load()
	bin := s.BytesIn.Load()
	bout := s.BytesOut.Load()
	snap := Snapshot{
		PacketsIn: in, PacketsOut: out, BytesIn: bin, BytesOut: bout,
		Unchanged: s.Unchanged.Load(), Dropped: s.Dropped.Load(),
		Tampered: s.Tampered.Load(), Expanded: s.Expanded.Load(),
		Errors: s.Errors.Load(), Swaps: s.Swaps.Load(),
	}
	if in > 0 {
		snap.PacketOverhead = float64(out)/float64(in) - 1
	}
	if bin > 0 {
		snap.ByteOverhead = float64(bout)/float64(bin) - 1
	}
	return snap
}

// Engine applies a single strategy to packets. The strategy can be swapped
// atomically at runtime via SetStrategy — in either mode — so a new strategy
// takes effect on the next packet without a restart.
type Engine struct {
	mu    sync.Mutex // serializes swaps; reads use the atomic pointer
	cur   atomic.Pointer[loaded]
	Stats Stats
}

type loaded struct {
	dna string
	s   *strategy.Strategy
}

// New builds an engine with the given strategy DNA. An empty DNA yields a
// pass-through engine (valid: the empty strategy matches nothing).
func New(dna string) (*Engine, error) {
	e := &Engine{}
	if err := e.SetStrategy(dna); err != nil {
		return nil, err
	}
	return e, nil
}

// ErrInvalidStrategy marks a strategy the caller supplied as unparseable or
// invalid. The control surface uses it to tell a client error (a bad PUT body,
// worth a 4xx) from an infrastructure failure applying a valid strategy (a
// 5xx); anything that rejects a DNA on its content should wrap it.
var ErrInvalidStrategy = errors.New("invalid strategy")

// SetStrategy parses, validates, and atomically installs a new strategy. It is
// safe to call concurrently with Process; in-flight packets finish against the
// previous strategy and subsequent packets use the new one.
func (e *Engine) SetStrategy(dna string) error {
	s, err := geneva.NewStrategy(dna)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrInvalidStrategy, err)
	}
	if err := geneva.Validate(s); err != nil {
		return fmt.Errorf("%w: validate: %w", ErrInvalidStrategy, err)
	}
	e.mu.Lock()
	// The initial load from New is not a swap, so the counter reads as the
	// number of in-place replacements rather than of installs.
	replaced := e.cur.Load() != nil
	e.cur.Store(&loaded{dna: dna, s: s})
	e.mu.Unlock()
	if replaced {
		e.Stats.Swaps.Add(1)
	}
	return nil
}

// DNA returns the currently installed strategy DNA.
func (e *Engine) DNA() string {
	if l := e.cur.Load(); l != nil {
		return l.dna
	}
	return ""
}

// Process decodes a raw IPv4 packet, applies the current strategy for the given
// direction, and returns the verdict and replacement packets. raw must begin at
// the IPv4 header, exactly as NFQUEUE delivers it.
//
// scratch carries the per-packet working memory. It may be nil, in which case
// Process allocates; the NFQUEUE runtime passes one per queue goroutine, which
// is what keeps the hot path from allocating a fresh 1500-byte buffer, a decode
// copy and an output slice for every packet on the wire. A CPU profile of a
// tamper-every-packet strategy spent ~30% of its time in the garbage collector
// and the scheduler feeding it.
func (e *Engine) Process(raw []byte, dir strategy.Direction, scratch *Scratch) (Result, error) {
	e.Stats.PacketsIn.Add(1)
	e.Stats.BytesIn.Add(uint64(len(raw)))

	l := e.cur.Load()
	if l == nil {
		return Result{}, errors.New("engine has no strategy")
	}
	if scratch == nil {
		scratch = &Scratch{}
	}

	// Decode a private copy: the tamper actions mutate the decoded layers in
	// place, and raw is the kernel's buffer, which classify still needs
	// unmodified to tell "unchanged" from "tampered".
	//
	// NoCopy is what makes the copy above the only one: without it gopacket
	// takes a second copy of the same bytes. Lazy defers decoding a layer until
	// a trigger or action actually reads it, which for a strategy that only
	// looks at TCP flags means the payload is never touched.
	buf := scratch.packet(len(raw))
	copy(buf, raw)
	pkt := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if errLayer := pkt.ErrorLayer(); errLayer != nil {
		e.Stats.Errors.Add(1)
		return Result{}, fmt.Errorf("decode packet: %w", errLayer.Error())
	}

	out, err := l.s.Apply(pkt, dir)
	if err != nil {
		e.Stats.Errors.Add(1)
		return Result{}, fmt.Errorf("apply strategy: %w", err)
	}

	res := classify(raw, out, scratch)
	e.record(res)
	return res, nil
}

// ProcessGeneration lets a single Engine satisfy nfqueue.Processor in tests
// and legacy callers. A standalone Engine represents generation 1.
func (e *Engine) ProcessGeneration(id uint32, raw []byte, dir strategy.Direction, scratch *Scratch) (Result, error) {
	if id != 1 {
		return Result{}, fmt.Errorf("%w: %d", ErrGenerationNotFound, id)
	}
	return e.Process(raw, dir, scratch)
}

// Scratch is one packet's worth of reusable working memory, owned by a single
// goroutine. The NFQUEUE runtime keeps one per queue, since each queue's
// callback is serialized on one goroutine.
//
// The Result returned by Process aliases this memory: its Packets stay valid
// only until the next Process call with the same Scratch. That is exactly the
// lifetime the runtime needs — it issues the verdict, which copies into the
// netlink message, before reading another packet.
type Scratch struct {
	buf  []byte
	pkts [][]byte
}

// packet returns a buffer of exactly n bytes, growing the backing array only
// when a packet is larger than anything seen before.
func (s *Scratch) packet(n int) []byte {
	if cap(s.buf) < n {
		// Round up to the next MTU-ish size so a run of slightly larger packets
		// does not reallocate on each one.
		s.buf = make([]byte, n, max(n, 2048))
	}
	return s.buf[:n]
}

// outputs returns a zero-length slice with room for n packets.
func (s *Scratch) outputs(n int) [][]byte {
	if cap(s.pkts) < n {
		s.pkts = make([][]byte, 0, max(n, 4))
	}
	return s.pkts[:0]
}

// classify decides the outcome and collects the serialized output packets.
//
// The output bytes are not copied: they are either the scratch buffer the packet
// was decoded into or buffers the geneva library allocated while serializing,
// and both outlive the caller's verdict. See Scratch for the lifetime contract.
func classify(raw []byte, out []gopacket.Packet, scratch *Scratch) Result {
	switch len(out) {
	case 0:
		return Result{Outcome: OutcomeDropped}
	case 1:
		data := out[0].Data()
		outcome := OutcomeTampered
		if bytes.Equal(raw, data) {
			outcome = OutcomeUnchanged
		}
		return Result{Outcome: outcome, Packets: append(scratch.outputs(1), data)}
	default:
		packets := scratch.outputs(len(out))
		for _, p := range out {
			packets = append(packets, p.Data())
		}
		return Result{Outcome: OutcomeExpanded, Packets: packets}
	}
}

func (e *Engine) record(r Result) {
	e.Stats.PacketsOut.Add(uint64(len(r.Packets)))
	for _, p := range r.Packets {
		e.Stats.BytesOut.Add(uint64(len(p)))
	}
	switch r.Outcome {
	case OutcomeUnchanged:
		e.Stats.Unchanged.Add(1)
	case OutcomeDropped:
		e.Stats.Dropped.Add(1)
	case OutcomeTampered:
		e.Stats.Tampered.Add(1)
	case OutcomeExpanded:
		e.Stats.Expanded.Add(1)
	}
}

// Snapshot returns a value copy of the cumulative stats with overhead ratios.
func (e *Engine) Snapshot() Snapshot { return e.Stats.snapshot() }
