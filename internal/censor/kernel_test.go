package censor

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestKernelSourceCounts(t *testing.T) {
	raw := map[string]uint64{"syn": 5, "data": 100, "rst": 1}
	k := NewKernelSource(func(context.Context) (map[string]uint64, error) { return raw, nil }, -1)

	if got := k.Count(EventSYN); got != 5 {
		t.Errorf("syn = %d, want 5", got)
	}
	snap := k.Snapshot()
	if snap.Events["data"] != 100 || snap.Events["rst"] != 1 {
		t.Errorf("snapshot = %v", snap.Events)
	}
	// Every event is present, so a zero reads as zero rather than as a missing
	// series — the same contract the userspace observer has.
	for _, want := range []string{"syn", "rst", "fin", "data", "ack_only", "fragment", "undecodable"} {
		if _, ok := snap.Events[want]; !ok {
			t.Errorf("event %q missing from snapshot", want)
		}
	}
}

// TestKernelSourceAccumulatesAcrossResets is the property that makes these
// counters usable as a metric: the kernel's counters are objects inside the
// sidecar's table, so a strategy change rebuilds the table and restarts them
// from zero. The exported series must not go backwards when that happens.
func TestKernelSourceAccumulatesAcrossResets(t *testing.T) {
	var raw map[string]uint64
	k := NewKernelSource(func(context.Context) (map[string]uint64, error) { return raw, nil }, -1)

	raw = map[string]uint64{"syn": 10}
	if got := k.Count(EventSYN); got != 10 {
		t.Fatalf("first read = %d, want 10", got)
	}
	raw = map[string]uint64{"syn": 25}
	if got := k.Count(EventSYN); got != 25 {
		t.Fatalf("after growth = %d, want 25", got)
	}
	// Table rebuilt: the counter starts over at 3, and everything it holds is
	// new traffic.
	raw = map[string]uint64{"syn": 3}
	if got := k.Count(EventSYN); got != 28 {
		t.Errorf("after a reset = %d, want 28", got)
	}
	raw = map[string]uint64{"syn": 4}
	if got := k.Count(EventSYN); got != 29 {
		t.Errorf("after the reset, growth = %d, want 29", got)
	}
}

// TestKernelSourceKeepsCountsOnReadFailure pins that a failed read reports the
// last known counts rather than zeroes: zeroes would read as "the censor
// stopped", which is the opposite of "we cannot see".
func TestKernelSourceKeepsCountsOnReadFailure(t *testing.T) {
	fail := false
	k := NewKernelSource(func(context.Context) (map[string]uint64, error) {
		if fail {
			return nil, errors.New("nft went away")
		}
		return map[string]uint64{"syn": 7}, nil
	}, -1)

	if got := k.Count(EventSYN); got != 7 {
		t.Fatalf("first read = %d, want 7", got)
	}
	fail = true
	if got := k.Count(EventSYN); got != 7 {
		t.Errorf("after a failed read = %d, want the last known 7", got)
	}
	if _, failed := k.Reads(); failed == 0 {
		t.Error("failed read not counted")
	}
}

// TestKernelSourceCachesReads keeps the read off the per-call path: Count is
// called once per event per metric export, and each read is an nft invocation.
func TestKernelSourceCachesReads(t *testing.T) {
	var reads int
	k := NewKernelSource(func(context.Context) (map[string]uint64, error) {
		reads++
		return map[string]uint64{"syn": 1}, nil
	}, time.Hour)

	for range 10 {
		k.Count(EventSYN)
		k.Snapshot()
	}
	if reads != 1 {
		t.Errorf("read %d times, want 1 within the TTL", reads)
	}
}
