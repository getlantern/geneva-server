//go:build linux

package steering

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/nftables"
	"github.com/getlantern/geneva-server/internal/testutil"
)

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

// TestStartClearsStaleTableWhenIdle covers the unclean-restart case: a table
// left behind by a SIGKILL or a crash, followed by a start with no strategy.
//
// A leftover table with no reader is harmless (the rules carry `bypass`), but
// this process is about to open its queues — so the stale rules would put a box
// with no strategy straight back on the data path, which is the one thing the
// scoping is supposed to guarantee cannot happen.
//
// Requires root and nft, and self-skips otherwise, like the nftables lifecycle
// test.
func TestStartClearsStaleTableWhenIdle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	ctx := context.Background()
	const table = "geneva_stale_test"

	// Leave a table behind, exactly as a killed sidecar would.
	stale := nftables.New(nftables.Config{
		Table: table, Port: 18081, OutQueue: 300, InQueue: 301,
		Outbound: nftables.Selector{Any: true}, Inbound: nftables.Selector{Any: true},
	})
	if err := stale.Install(ctx); err != nil {
		t.Fatalf("install stale table: %v", err)
	}
	t.Cleanup(func() { _ = stale.Remove(ctx) })
	if !testutil.TableExists(t, table) {
		t.Fatal("stale table absent after install")
	}

	// Start with no strategy. Iface is empty so the NIC is left alone.
	eng := engine.NewRegistry()
	ctrl := New(eng, Config{Mode: "eval", NFT: nftables.Config{Table: table, Port: 18081, OutQueue: 300, InQueue: 301}}, nil)
	if err := ctrl.Start(ctx, ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if testutil.TableExists(t, table) {
		t.Error("stale table survived a start with no strategy: the box is steering with nothing to apply")
	}
	if st := ctrl.State(); st.Steering {
		t.Errorf("State reports steering with no strategy: %+v", st)
	}
}
