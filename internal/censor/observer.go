// Package censor classifies inbound TCP packets on the steered port to expose
// the one censorship signal the client side cannot report.
//
// Clients behind a censor report only what they observe: a completed session's
// success and throughput. A connection the censor kills during the handshake
// produces no report at all — the client simply sees a dial failure, which is
// indistinguishable from the client never having dialled, from a routing
// problem, or from the client going offline. Silence is not evidence.
//
// The box, however, sees the censor's work directly: SYNs that arrive and are
// never followed by data, and RSTs injected mid-flow. The ratio of inbound
// "syn" to inbound "data" per market is therefore the cheapest available
// estimate of a test box's IP having been burned — and clean test-box IP supply
// is the binding cost of GA exploration, so that estimate is what an adaptive
// exploration posture has to budget against.
//
// Deliberately stateless: no per-flow table. Tracking handshake completion by
// 4-tuple would be a strictly better signal, but it means unbounded per-packet
// state on a box whose whole job is to stay out of the proxy's way. The
// syn-versus-data ratio needs nothing but the current packet's flags and is
// sufficient to see a burn trend.
package censor

import (
	"sync/atomic"

	"github.com/getlantern/geneva/strategy"
)

// Event classifies an observed TCP packet.
type Event int

// The events, in classification precedence order.
const (
	// EventRST is a reset — censor-injected or a client abort. Both matter.
	EventRST Event = iota
	// EventSYN is a connection attempt (inbound SYN/ACK does not occur on a
	// listening port, so this is always a client opening a connection).
	EventSYN
	// EventFIN is an orderly close.
	EventFIN
	// EventData is a segment carrying payload: the flow got past the handshake
	// and the censor let real bytes through.
	EventData
	// EventACKOnly is a bare acknowledgement.
	EventACKOnly
	// EventFragment is a non-initial IPv4 fragment: legitimate traffic that
	// carries no TCP header of its own, so it cannot be classified further.
	// Inbound fragmentation is worth counting in its own right — it is a censor
	// evasion and a middlebox behaviour, not something a normal proxy flow
	// produces.
	EventFragment
	// EventUndecodable is a packet whose IPv4/TCP headers could not be read. A
	// nonzero count means the steering rules are delivering something other
	// than what this observer assumes, not that a censor did anything.
	EventUndecodable

	eventCount
)

// KernelEvents are the events the nftables classification chain can sort
// packets into, in classification precedence order. It is the single list the
// kernel-side counter names and rules derive from (see internal/nftables), so
// adding or renaming an event cannot leave the two sides silently disagreeing.
// EventFragment and EventUndecodable have no kernel equivalent: a fragment
// carries no TCP header to match, and nothing the kernel counts is decoded.
var KernelEvents = []Event{EventRST, EventSYN, EventFIN, EventData, EventACKOnly}

func (e Event) String() string {
	switch e {
	case EventRST:
		return "rst"
	case EventSYN:
		return "syn"
	case EventFIN:
		return "fin"
	case EventData:
		return "data"
	case EventACKOnly:
		return "ack_only"
	case EventFragment:
		return "fragment"
	case EventUndecodable:
		return "undecodable"
	default:
		return "unknown"
	}
}

// Observer counts inbound TCP packets by event. It satisfies the nfqueue
// Observer interface and is safe for concurrent use.
type Observer struct {
	counts [eventCount]atomic.Uint64
}

// New returns an Observer with zeroed counters.
func New() *Observer { return &Observer{} }

// Observe classifies raw, which must begin at the IPv4 header exactly as
// NFQUEUE delivers it. Outbound packets are ignored: the censor's effect on
// this box is visible in what arrives, not in what the box sends.
func (o *Observer) Observe(raw []byte, dir strategy.Direction) {
	if dir != strategy.DirectionInbound {
		return
	}
	// Every inbound packet lands in exactly one bucket, fragments and
	// unreadable headers included, so the counts sum to everything observed and
	// a ratio between two of them means what it appears to mean.
	o.counts[classify(raw)].Add(1)
}

// Snapshot is a value copy of the counters.
type Snapshot struct {
	// Events maps each event's name to its count. Every event is present, so a
	// zero is reported as zero rather than as a missing series.
	Events map[string]uint64 `json:"events"`
}

// Snapshot returns the current counts.
func (o *Observer) Snapshot() Snapshot {
	s := Snapshot{Events: make(map[string]uint64, eventCount)}
	for e := Event(0); e < eventCount; e++ {
		s.Events[e.String()] = o.counts[e].Load()
	}
	return s
}

// Count returns the count for a single event.
func (o *Observer) Count(e Event) uint64 {
	if e < 0 || e >= eventCount {
		return 0
	}
	return o.counts[e].Load()
}

// TCP flag bits in the octet at TCP header offset 13.
const (
	flagFIN = 1 << 0
	flagSYN = 1 << 1
	flagRST = 1 << 2
)

// classify reads the flags and payload length straight out of the header
// octets. gopacket would be the obvious tool, but this runs on every inbound
// packet in prod mode as well as eval, where the engine may not otherwise
// decode anything; a hand-rolled read of four fields allocates nothing and
// keeps the observer off the proxy's latency budget.
func classify(raw []byte) Event {
	// IPv4 header: version/IHL, then total length at 2:4, protocol at 9.
	if len(raw) < 20 || raw[0]>>4 != 4 {
		return EventUndecodable
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || len(raw) < ihl {
		return EventUndecodable
	}
	const protoTCP = 6
	if raw[9] != protoTCP {
		return EventUndecodable
	}
	// Only the first fragment of a fragmented datagram carries the TCP header;
	// the protocol field still reads TCP on the rest, so without this check the
	// bytes at ihl would be payload read as flags and a data offset.
	fragOffset := int(raw[6]&0x1f)<<8 | int(raw[7])
	if fragOffset != 0 {
		return EventFragment
	}
	totalLen := int(raw[2])<<8 | int(raw[3])
	// Trust the shorter of the header's claim and the bytes actually delivered:
	// NFQUEUE can hand over a truncated copy, and a header claiming more than
	// arrived must not yield a negative payload length.
	if totalLen == 0 || totalLen > len(raw) {
		totalLen = len(raw)
	}

	tcp := raw[ihl:]
	if len(tcp) < 20 {
		return EventUndecodable
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || ihl+dataOff > totalLen {
		return EventUndecodable
	}
	flags := tcp[13]

	switch {
	case flags&flagRST != 0:
		return EventRST
	case flags&flagSYN != 0:
		return EventSYN
	case flags&flagFIN != 0:
		return EventFIN
	case totalLen-ihl-dataOff > 0:
		return EventData
	default:
		return EventACKOnly
	}
}
