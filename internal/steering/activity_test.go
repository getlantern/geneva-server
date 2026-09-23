package steering

import (
	"context"
	"testing"

	"github.com/getlantern/geneva/strategy"

	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/nftables"
	"github.com/getlantern/geneva-server/internal/testutil"
)

// Status reports each serving generation's own counters and the port the
// runtime steers, so a control plane can tell a strategy that acted on
// traffic from one that saw traffic and changed nothing, and can compare the
// steered port against the proxy's real listener.
func TestStatusReportsGenerationActivityAndSteering(t *testing.T) {
	ctx := context.Background()
	eng := engine.NewRegistry()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(eng, Config{NoNFT: true, NFT: nftables.Config{Port: 46551}, Connections: flows}, nil)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	one := lifecycleArtifact(t, "r1", genOneDNA)
	two := lifecycleArtifact(t, "r2", genTwoDNA)
	if err := c.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.Prepare(ctx, two); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, two); err != nil {
		t.Fatal(err)
	}
	flows.counts[1] = 2

	raw := testutil.BuildTCP(t, 46551, testutil.TCPFlags{ACK: true}, []byte("payload"))
	for id, packets := range map[uint32]int{1: 2, 2: 5} {
		for range packets {
			if _, err := eng.ProcessGeneration(id, raw, strategy.DirectionOutbound, nil); err != nil {
				t.Fatal(err)
			}
		}
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Steering == nil || st.Steering.Port != 46551 {
		t.Fatalf("steering status = %+v", st.Steering)
	}
	if len(st.Activity) != 2 {
		t.Fatalf("activity = %+v, want the active and the draining generation", st.Activity)
	}
	byRevision := map[string]uint64{}
	for _, activity := range st.Activity {
		if activity.Lineage == "" {
			t.Fatalf("activity without lineage: %+v", activity)
		}
		acted := activity.Dropped + activity.Tampered + activity.Expanded
		if activity.Unchanged+acted+activity.Errors != activity.PacketsIn {
			t.Fatalf("outcomes do not account for every packet: %+v", activity)
		}
		byRevision[activity.Identity.Revision] = activity.PacketsIn
	}
	if byRevision[one.Identity().Revision] != 2 || byRevision[two.Identity().Revision] != 5 {
		t.Fatalf("per-generation packets = %v", byRevision)
	}

	// A drained, collected generation stops reporting activity.
	flows.counts[1] = 0
	if _, err := c.Drain(ctx, one.Identity()); err != nil {
		t.Fatal(err)
	}
	if err := c.GarbageCollect(ctx, nil); err != nil {
		t.Fatal(err)
	}
	st, err = c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Activity) != 1 || st.Activity[0].Identity != two.Identity() {
		t.Fatalf("activity after collection = %+v", st.Activity)
	}
}

// Counters are only reported against the generation view they were read
// under: a view that moved since it was taken is refused rather than paired
// with another generation's counters.
func TestActivityRefusesAStaleGenerationView(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, NFT: nftables.Config{Port: 46551}, Connections: flows}, nil)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	one := lifecycleArtifact(t, "r1", genOneDNA)
	two := lifecycleArtifact(t, "r2", genTwoDNA)
	if err := c.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, one); err != nil {
		t.Fatal(err)
	}
	view := c.State()
	if activity, err := c.activityFor(view); err != nil || len(activity) != 1 {
		t.Fatalf("current view activity = %+v, %v", activity, err)
	}
	if err := c.Prepare(ctx, two); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, two); err != nil {
		t.Fatal(err)
	}
	if _, err := c.activityFor(view); err == nil {
		t.Fatal("stale generation view produced activity")
	}
}
