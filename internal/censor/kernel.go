package censor

import (
	"context"
	"sync"
	"time"
)

// Source is where the inbound TCP counts come from. Two implementations exist
// and only one is active on a box:
//
//   - Observer, which classifies packets that NFQUEUE delivered to userspace.
//     It only ever sees what the strategy already asked to be steered.
//   - KernelSource, which reads nftables counters that classified the packets in
//     the kernel. It sees every inbound packet on the proxy's port whether or
//     not the strategy touches inbound, and costs no userspace round trip.
type Source interface {
	Count(e Event) uint64
	Snapshot() Snapshot
}

// KernelSource exposes nftables classification counters as censor events.
//
// This is what lets the burn signal survive steering being scoped to what a
// strategy can act on. An outbound-only strategy steers no inbound packets, so
// the userspace classifier sees nothing and the signal goes dark — while the
// kernel can count what arrives for free, and does.
type KernelSource struct {
	read func(context.Context) (map[string]uint64, error)
	ttl  time.Duration

	mu sync.Mutex
	// total is the monotonic count exported for each event. The kernel's
	// counters are objects inside the sidecar's table, so they reset whenever
	// the table is rebuilt — which a strategy change does. Accumulating deltas
	// here keeps the exported series monotonic across those rebuilds, so a
	// rollout does not look like a counter going backwards.
	total [eventCount]uint64
	// lastRaw is the previous reading, to difference against.
	lastRaw  [eventCount]uint64
	lastRead time.Time
	// reads and readErrors are for diagnosis: a source that cannot read is
	// reporting stale numbers, and that has to be visible somewhere.
	reads, readErrors uint64
}

// NewKernelSource returns a source that reads counts through read, no more often
// than once per ttl. read is called with a short-lived context by whichever
// goroutine asks for a count.
//
// A ttl of zero or less reads on every call. That is not what a box wants — one
// nft invocation per event per metric export — but it is what a test wants, and
// silently substituting a default would make the caching untestable.
func NewKernelSource(read func(context.Context) (map[string]uint64, error), ttl time.Duration) *KernelSource {
	return &KernelSource{read: read, ttl: ttl}
}

// eventNames maps the kernel counter names to events. The kernel counters are
// named for the events, so this is the identity for those it can classify;
// fragment and undecodable have no kernel equivalent and stay at zero.
func eventFor(name string) (Event, bool) {
	for e := Event(0); e < eventCount; e++ {
		if e.String() == name {
			return e, true
		}
	}
	return 0, false
}

// refresh reads the counters if the cached values are older than the TTL.
// Failures leave the previous totals in place: stale counts are a better answer
// than zeroes, which would read as "the censor stopped".
func (k *KernelSource) refresh() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.ttl > 0 && !k.lastRead.IsZero() && time.Since(k.lastRead) < k.ttl {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	raw, err := k.read(ctx)
	k.lastRead = time.Now()
	k.reads++
	if err != nil {
		k.readErrors++
		return
	}
	for name, v := range raw {
		e, ok := eventFor(name)
		if !ok {
			continue
		}
		switch {
		case v >= k.lastRaw[e]:
			k.total[e] += v - k.lastRaw[e]
		default:
			// The counter went backwards, so the table was rebuilt and the
			// counter started over: everything it holds now is new.
			k.total[e] += v
		}
		k.lastRaw[e] = v
	}
}

// Count returns the accumulated count for one event.
func (k *KernelSource) Count(e Event) uint64 {
	k.refresh()
	k.mu.Lock()
	defer k.mu.Unlock()
	if e < 0 || e >= eventCount {
		return 0
	}
	return k.total[e]
}

// Snapshot returns all accumulated counts.
func (k *KernelSource) Snapshot() Snapshot {
	k.refresh()
	k.mu.Lock()
	defer k.mu.Unlock()
	s := Snapshot{Events: make(map[string]uint64, eventCount)}
	for e := Event(0); e < eventCount; e++ {
		s.Events[e.String()] = k.total[e]
	}
	return s
}

// Reads reports how many times the counters have been read and how many of those
// failed, for the health surface.
func (k *KernelSource) Reads() (total, failed uint64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.reads, k.readErrors
}
