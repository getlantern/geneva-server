package engine

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/getlantern/geneva/strategy"
)

// ErrGenerationNotFound marks a packet or lifecycle request naming an engine
// generation which has not been prepared (or has already been collected).
var ErrGenerationNotFound = errors.New("engine generation not found")

// Registry owns immutable engines. Preparing a generation creates a new Engine;
// no lifecycle operation ever calls SetStrategy on an engine already in the
// registry. Packet readers use a copy-on-write map, so dispatch adds no lock to
// the NFQUEUE hot path.
type Registry struct {
	mu     sync.Mutex
	byID   atomic.Pointer[map[uint32]*Engine]
	active atomic.Uint32
	swaps  atomic.Uint64
}

// NewRegistry returns an empty immutable-engine registry.
func NewRegistry() *Registry {
	r := &Registry{}
	empty := make(map[uint32]*Engine)
	r.byID.Store(&empty)
	return r
}

// Prepare parses and validates dna, then publishes it as generation id. The
// operation is idempotent only when the existing generation has identical DNA.
func (r *Registry) Prepare(id uint32, dna string) error {
	eng, err := New(dna)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := *r.byID.Load()
	if existing := cur[id]; existing != nil {
		if existing.DNA() == dna {
			return nil
		}
		return fmt.Errorf("generation %d is immutable and already contains different DNA", id)
	}
	next := make(map[uint32]*Engine, len(cur)+1)
	for k, v := range cur {
		next[k] = v
	}
	next[id] = eng
	r.byID.Store(&next)
	return nil
}

// Activate changes the generation used by compatibility reads and direct
// Process calls. NFQUEUE dispatch itself always names a generation explicitly.
func (r *Registry) Activate(id uint32) error {
	if (*r.byID.Load())[id] == nil {
		return fmt.Errorf("%w: %d", ErrGenerationNotFound, id)
	}
	old := r.active.Swap(id)
	if old != 0 && old != id {
		r.swaps.Add(1)
	}
	return nil
}

// Deactivate clears the compatibility active generation.
func (r *Registry) Deactivate() { r.active.Store(0) }

// Remove forgets an inactive engine generation after its conntrack entries have
// drained. The caller is responsible for removing its kernel rules first.
func (r *Registry) Remove(id uint32) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active.Load() == id {
		return fmt.Errorf("generation %d is active", id)
	}
	cur := *r.byID.Load()
	if cur[id] == nil {
		return fmt.Errorf("%w: %d", ErrGenerationNotFound, id)
	}
	next := make(map[uint32]*Engine, len(cur)-1)
	for k, v := range cur {
		if k != id {
			next[k] = v
		}
	}
	r.byID.Store(&next)
	return nil
}

// DNA returns the compatibility active generation's DNA.
func (r *Registry) DNA() string {
	if eng := (*r.byID.Load())[r.active.Load()]; eng != nil {
		return eng.DNA()
	}
	return ""
}

// Process applies the compatibility active generation.
func (r *Registry) Process(raw []byte, dir strategy.Direction, scratch *Scratch) (Result, error) {
	id := r.active.Load()
	if id == 0 {
		return Result{}, fmt.Errorf("%w: no active generation", ErrGenerationNotFound)
	}
	return r.ProcessGeneration(id, raw, dir, scratch)
}

// ProcessGeneration applies exactly the immutable engine named by id.
func (r *Registry) ProcessGeneration(id uint32, raw []byte, dir strategy.Direction, scratch *Scratch) (Result, error) {
	eng := (*r.byID.Load())[id]
	if eng == nil {
		return Result{}, fmt.Errorf("%w: %d", ErrGenerationNotFound, id)
	}
	return eng.Process(raw, dir, scratch)
}

// Snapshot returns aggregate counters across all live generations.
func (r *Registry) Snapshot() Snapshot {
	var out Snapshot
	for _, eng := range *r.byID.Load() {
		s := eng.Snapshot()
		out.PacketsIn += s.PacketsIn
		out.PacketsOut += s.PacketsOut
		out.BytesIn += s.BytesIn
		out.BytesOut += s.BytesOut
		out.Unchanged += s.Unchanged
		out.Dropped += s.Dropped
		out.Tampered += s.Tampered
		out.Expanded += s.Expanded
		out.Errors += s.Errors
	}
	out.Swaps = r.swaps.Load()
	if out.PacketsIn > 0 {
		out.PacketOverhead = float64(out.PacketsOut)/float64(out.PacketsIn) - 1
	}
	if out.BytesIn > 0 {
		out.ByteOverhead = float64(out.BytesOut)/float64(out.BytesIn) - 1
	}
	return out
}
