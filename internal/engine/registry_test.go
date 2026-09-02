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
