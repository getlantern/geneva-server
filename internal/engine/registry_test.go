package engine

import (
	"errors"
	"testing"

	"github.com/getlantern/geneva/strategy"

	"github.com/getlantern/geneva-server/internal/testutil"
)

func TestRegistryGenerationsAreImmutable(t *testing.T) {
	r := NewRegistry()
	if err := r.Prepare(7, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(7, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatalf("idempotent prepare: %v", err)
	}
	if err := r.Prepare(7, `[TCP:flags:S]-drop-| \/`); err == nil {
		t.Fatal("replaced immutable generation")
	}
	if err := r.VerifyGeneration(7, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatalf("verify immutable generation: %v", err)
	}
	if err := r.VerifyGeneration(7, `[TCP:flags:S]-drop-| \/`); err == nil {
		t.Fatal("verified generation against different durable DNA")
	}
	if err := r.VerifyGeneration(8, ""); !errors.Is(err, ErrGenerationNotFound) {
		t.Fatalf("verify missing generation error = %v", err)
	}
}

func TestRegistryDispatchesExplicitGeneration(t *testing.T) {
	r := NewRegistry()
	if err := r.Prepare(1, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(2, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatal(err)
	}
	raw := testutil.BuildTCP(t, 1000, testutil.TCPFlags{RST: true}, nil)
	res, err := r.ProcessGeneration(1, raw, strategy.DirectionOutbound, nil)
	if err != nil || res.Outcome != OutcomeUnchanged {
		t.Fatalf("generation 1 = %+v, %v", res, err)
	}
	res, err = r.ProcessGeneration(2, raw, strategy.DirectionOutbound, nil)
	if err != nil || res.Outcome != OutcomeDropped {
		t.Fatalf("generation 2 = %+v, %v", res, err)
	}
	if _, err := r.ProcessGeneration(3, raw, strategy.DirectionOutbound, nil); !errors.Is(err, ErrGenerationNotFound) {
		t.Fatalf("missing generation error = %v", err)
	}
}

func TestRegistryGenerationSnapshotsAreSeparateLineages(t *testing.T) {
	r := NewRegistry()
	if err := r.Prepare(1, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(2, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatal(err)
	}
	raw := testutil.BuildTCP(t, 1000, testutil.TCPFlags{RST: true}, nil)
	for range 3 {
		if _, err := r.ProcessGeneration(2, raw, strategy.DirectionOutbound, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.ProcessGeneration(1, raw, strategy.DirectionOutbound, nil); err != nil {
		t.Fatal(err)
	}
	one, ok := r.GenerationSnapshot(1)
	if !ok || one.PacketsIn != 1 || one.Unchanged != 1 || one.Dropped != 0 {
		t.Fatalf("generation 1 snapshot = %+v, %v", one, ok)
	}
	two, ok := r.GenerationSnapshot(2)
	if !ok || two.PacketsIn != 3 || two.Dropped != 3 {
		t.Fatalf("generation 2 snapshot = %+v, %v", two, ok)
	}
	if one.Lineage == "" || one.Lineage == two.Lineage {
		t.Fatalf("lineages must be distinct and non-empty: %q %q", one.Lineage, two.Lineage)
	}
	if _, ok := r.GenerationSnapshot(3); ok {
		t.Fatal("snapshot of a missing generation")
	}

	// Preparing the same generation again after removal restarts its counters
	// under a new lineage, so a consumer never reads the reset as a decrease.
	if err := r.Remove(2); err != nil {
		t.Fatal(err)
	}
	if err := r.Prepare(2, `[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatal(err)
	}
	again, ok := r.GenerationSnapshot(2)
	if !ok || again.PacketsIn != 0 || again.Lineage == two.Lineage {
		t.Fatalf("re-prepared generation snapshot = %+v (previous lineage %q)", again, two.Lineage)
	}
	if other := NewRegistry(); other.epoch == r.epoch {
		t.Fatal("two registries share a counter epoch")
	}
}
