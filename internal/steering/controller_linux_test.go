//go:build linux

package steering

import "testing"

// TestObservationFloorIsEvalOnly is the controller-side half of the mode gate.
// main.go refuses the flag in prod mode; this is the second lock, for a
// Controller built by something other than the CLI. Widening inbound to
// everything on a prod box is exactly the cost scoping exists to avoid.
func TestObservationFloorIsEvalOnly(t *testing.T) {
	// An outbound-only strategy: nothing asks for inbound, so inbound is
	// steered only if the observation floor widens it.
	handshake := mustScope(t, `[TCP:flags:S]-duplicate-| \/`)

	cases := []struct {
		mode        string
		observe     bool
		wantInbound bool
	}{
		{mode: "eval", observe: true, wantInbound: true},
		{mode: "eval", observe: false, wantInbound: false},
		{mode: "prod", observe: true, wantInbound: false},
		{mode: "prod", observe: false, wantInbound: false},
	}
	for _, c := range cases {
		ctrl := New(nil, Config{Mode: c.mode, ObserveInbound: c.observe}, nil)
		got := ctrl.widen(handshake)
		if got.Inbound.Any != c.wantInbound {
			t.Errorf("mode=%s observe=%v: inbound steered = %v, want %v",
				c.mode, c.observe, got.Inbound.Any, c.wantInbound)
		}
		// Widening must never touch the outbound side.
		if len(got.Outbound.Flags) != 1 || got.Outbound.Any {
			t.Errorf("mode=%s observe=%v: outbound selector altered: %+v", c.mode, c.observe, got.Outbound)
		}
	}
}

// TestObservationFloorLeavesIdleIdle pins the other half: a box with no strategy
// stays off the data path even in eval mode with observation asked for.
func TestObservationFloorLeavesIdleIdle(t *testing.T) {
	ctrl := New(nil, Config{Mode: "eval", ObserveInbound: true}, nil)
	if got := ctrl.widen(mustScope(t, "")); !got.Idle() {
		t.Errorf("idle strategy widened to %+v", got)
	}
}
