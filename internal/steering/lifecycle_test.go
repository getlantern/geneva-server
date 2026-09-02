//go:build linux

package steering

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getlantern/geneva/strategy"

	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/generation"
	"github.com/getlantern/geneva-server/internal/netdev"
	"github.com/getlantern/geneva-server/internal/nftables"
	"github.com/getlantern/geneva-server/internal/testutil"
)

const (
	genOneDNA      = `[TCP:flags:S]-drop-| \/`
	genTwoDNA      = `[TCP:flags:S]-duplicate-| \/`
	everyPacketDNA = `[TCP:load:GET]-duplicate-| \/`
)

func lifecycleArtifact(t *testing.T, revision, dna string) adapter.Artifact {
	return lifecycleArtifactForRuntime(t, revision, dna, "dev")
}

func lifecycleArtifactForRuntime(t *testing.T, revision, dna, runtimeVersion string) adapter.Artifact {
	t.Helper()
	payload := []byte(dna)
	a, err := adapter.NewArtifact(adapter.ArtifactMetadata{
		Technique: adapter.TechniqueGeneva, Revision: revision, Digest: adapter.Digest(payload), Size: len(payload),
		AdapterProtocol: adapter.Version1, RequiredRuntimeName: adapter.RuntimeNameGeneva,
		RequiredRuntimeVersion: runtimeVersion, SchemaVersion: adapter.SchemaVersionV1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type fakeConnections struct {
	counts      map[uint32]int
	countsErr   error
	countCalls  int
	namespace   int
	gotID       uint32
	gotPort     uint16
	neutralized int
	countsHook  func()
}

func (f *fakeConnections) Count(_ context.Context, id uint32, port uint16) (int, error) {
	f.gotID, f.gotPort = id, port
	return f.counts[id], nil
}
func (f *fakeConnections) Counts(context.Context, uint16) (map[uint32]int, error) {
	f.countCalls++
	if f.countsHook != nil {
		f.countsHook()
	}
	if f.countsErr != nil {
		return nil, f.countsErr
	}
	counts := make(map[uint32]int, len(f.counts)+1)
	for id, count := range f.counts {
		counts[id] = count
	}
	if f.namespace != 0 {
		counts[99] = f.namespace
	}
	return counts, nil
}
func (f *fakeConnections) Neutralize(context.Context, uint16) (int, error) {
	f.neutralized++
	return f.neutralized, nil
}

type blockingConnections struct{}

func (blockingConnections) Count(context.Context, uint32, uint16) (int, error) { return 0, nil }
func (blockingConnections) Counts(ctx context.Context, _ uint16) (map[uint32]int, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (blockingConnections) Neutralize(ctx context.Context, _ uint16) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

type wedgedConnections struct{}

func (wedgedConnections) Count(context.Context, uint32, uint16) (int, error) { select {} }
func (wedgedConnections) Counts(context.Context, uint16) (map[uint32]int, error) {
	select {}
}
func (wedgedConnections) Neutralize(context.Context, uint16) (int, error) { select {} }

type orderingConnections struct{ events chan<- string }

func (orderingConnections) Count(context.Context, uint32, uint16) (int, error) { return 0, nil }
func (c orderingConnections) Counts(context.Context, uint16) (map[uint32]int, error) {
	c.events <- "conntrack audit"
	return map[uint32]int{}, nil
}
func (orderingConnections) Neutralize(context.Context, uint16) (int, error) { return 0, nil }

func TestResourceClassOnlyTreatsEstablishmentAsScoped(t *testing.T) {
	exact := func(value uint8) nftables.Selector {
		return nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0xff, Value: value}}}
	}
	cases := []struct {
		name  string
		scope Scope
		want  string
	}{
		{"SYN only", Scope{Outbound: exact(0x02)}, resourceHandshake},
		{"SYN ACK", Scope{Inbound: exact(0x12)}, resourceHandshake},
		{"ACK", Scope{Outbound: exact(0x10)}, resourceEvery},
		{"PSH ACK", Scope{Outbound: exact(0x18)}, resourceEvery},
		{"mixed", Scope{Outbound: nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0xff, Value: 0x02}, {Mask: 0xff, Value: 0x10}}}}, resourceEvery},
		{"absent flags constraint", Scope{Outbound: nftables.Selector{Any: true}}, resourceEvery},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceClass(tc.scope); got != tc.want {
				t.Fatalf("resource class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestActivationStagesUnionBeforeFlippingNewSYNs(t *testing.T) {
	ctx := context.Background()
	reg := engine.NewRegistry()
	var calls []nftables.Config
	var verifies []bool
	c := New(reg, Config{Mode: "prod", NFT: nftables.Config{Port: 443}, Program: func(_ context.Context, cfg nftables.Config, verify bool) error {
		calls, verifies = append(calls, cfg), append(verifies, verify)
		return nil
	}}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 2, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	calls, verifies = nil, nil
	if err := c.ActivateNew(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("program calls = %d, want 2", len(calls))
	}
	if !verifies[0] || verifies[1] {
		t.Fatalf("verify sequence = %v, want [true false]", verifies)
	}
	for i, cfg := range calls {
		if len(cfg.Generations) != 2 {
			t.Fatalf("call %d live generations = %d", i, len(cfg.Generations))
		}
	}
	if calls[0].ActiveGeneration != 1 {
		t.Fatalf("staging assigned %d, want old 1", calls[0].ActiveGeneration)
	}
	if calls[1].ActiveGeneration != 2 {
		t.Fatalf("flip assigned %d, want new 2", calls[1].ActiveGeneration)
	}
	// The candidate engine was live before either transaction could reference it.
	raw := testutil.BuildTCP(t, 443, testutil.TCPFlags{SYN: true}, nil)
	if _, err := reg.ProcessGeneration(2, raw, strategy.DirectionOutbound, nil); err != nil {
		t.Fatalf("candidate engine absent: %v", err)
	}
}

func TestFirstActivationNeutralizesExactBoundaryBeforeAssignment(t *testing.T) {
	flows := &fakeConnections{counts: map[uint32]int{}}
	var calls []nftables.Config
	c := New(engine.NewRegistry(), Config{NFT: nftables.Config{Port: 443}, Connections: flows, Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
		calls = append(calls, cfg)
		return nil
	}}, nil)
	if err := c.Start(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(context.Background(), 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err := c.ActivateNew(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !calls[0].NeutralizeNew || calls[0].ActiveGeneration != 0 || calls[1].NeutralizeNew || calls[1].ActiveGeneration != 1 {
		t.Fatalf("activation boundary calls = %+v", calls)
	}
	if flows.neutralized != 1 {
		t.Fatalf("neutralization sweeps = %d", flows.neutralized)
	}
}

func TestDrainScopesCountAndGuardsReuse(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	reg := engine.NewRegistry()
	c := New(reg, Config{Mode: "prod", NFT: nftables.Config{Port: 8443}, NoNFT: true, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 7, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := c.DeactivateNew(ctx); err != nil {
		t.Fatal(err)
	}
	flows.counts[7] = 2
	n, err := c.DrainGeneration(ctx, 7)
	if err != nil || n != 2 {
		t.Fatalf("Drain = %d, %v", n, err)
	}
	if flows.gotID != 7 || flows.gotPort != 8443 {
		t.Fatalf("count scope = generation %d port %d", flows.gotID, flows.gotPort)
	}
	if err := c.GarbageCollectGeneration(ctx, 7); err == nil {
		t.Fatal("collected generation with live flows")
	}
	flows.counts[7] = 0
	if err := c.GarbageCollectGeneration(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 7, genTwoDNA); err != nil {
		t.Fatalf("safe ID reuse after zero-flow GC: %v", err)
	}
}

func TestGenerationIDBoundsPreventWraparound(t *testing.T) {
	c := New(engine.NewRegistry(), Config{}, nil)
	if err := c.PrepareGeneration(context.Background(), generation.MaxID, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(context.Background(), generation.MaxID+1, genOneDNA); !errors.Is(err, engine.ErrInvalidStrategy) {
		t.Fatalf("overflow error = %v", err)
	}
}

func TestPrepareEnforcesDefaultLiveGenerationBudget(t *testing.T) {
	c := New(engine.NewRegistry(), Config{}, nil)
	for id := uint32(1); id <= 3; id++ {
		if err := c.PrepareGeneration(context.Background(), id, genOneDNA); err != nil {
			t.Fatalf("prepare %d: %v", id, err)
		}
	}
	if err := c.PrepareGeneration(context.Background(), 4, genOneDNA); err == nil || !strings.Contains(err.Error(), "budget is full") {
		t.Fatalf("fourth prepare error = %v", err)
	}
}

func TestPrepareEnforcesSeparateResourceBudgets(t *testing.T) {
	c := New(engine.NewRegistry(), Config{
		MaxGenerations:            3,
		MaxScopedGenerations:      1,
		MaxEveryPacketGenerations: 1,
	}, nil)
	if err := c.PrepareGeneration(context.Background(), 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(context.Background(), 2, genTwoDNA); err == nil || !strings.Contains(err.Error(), "handshake-scoped") {
		t.Fatalf("second scoped prepare error = %v", err)
	}
	if err := c.PrepareGeneration(context.Background(), 2, everyPacketDNA); err != nil {
		t.Fatalf("first every-packet prepare: %v", err)
	}
	if err := c.PrepareGeneration(context.Background(), 3, everyPacketDNA); err == nil || !strings.Contains(err.Error(), "every-packet") {
		t.Fatalf("second every-packet prepare error = %v", err)
	}
	st := c.State()
	if len(st.Generations) != 2 || st.Generations[0].ResourceClass != resourceHandshake || st.Generations[1].ResourceClass != resourceEvery {
		t.Fatalf("resource classes = %+v", st.Generations)
	}
}

func TestDefaultEveryPacketBudgetAllowsPBGAndChallenger(t *testing.T) {
	c := New(engine.NewRegistry(), Config{}, nil)
	if err := c.PrepareGeneration(context.Background(), 1, everyPacketDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(context.Background(), 2, everyPacketDNA); err != nil {
		t.Fatalf("default every-packet budget did not permit PBG plus challenger: %v", err)
	}
	if err := c.PrepareGeneration(context.Background(), 3, everyPacketDNA); err == nil || !strings.Contains(err.Error(), "every-packet") {
		t.Fatalf("third every-packet generation error = %v", err)
	}
}

func TestIdentityMappingIsDurableIdempotentAndReusableOnlyAfterGC(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	one := lifecycleArtifact(t, "r1", genOneDNA)
	c1 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c1.Prepare(ctx, one); err != nil {
		t.Fatalf("idempotent prepare: %v", err)
	}
	first := c1.State()
	if len(first.Generations) != 1 || first.Generations[0].ID != 1 {
		t.Fatalf("first identity mapping = %+v", first.Generations)
	}
	duplicate := adapter.Deployment{Generation: 2, Identity: one.Identity()}
	if err := c1.PrepareDeployment(ctx, duplicate, genOneDNA); err == nil || !strings.Contains(err.Error(), "already mapped") {
		t.Fatalf("duplicate identity mapping error = %v", err)
	}

	c2 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c2.Prepare(ctx, one); err != nil {
		t.Fatalf("restart idempotent prepare: %v", err)
	}
	if got := c2.State().Generations; len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("restart identity mapping = %+v", got)
	}
	if err := c2.GarbageCollect(ctx, nil); err != nil {
		t.Fatal(err)
	}
	two := lifecycleArtifact(t, "r2", genTwoDNA)
	if err := c2.Prepare(ctx, two); err != nil {
		t.Fatal(err)
	}
	if got := c2.State().Generations; len(got) != 1 || got[0].ID != 1 || got[0].Identity != two.Identity() {
		t.Fatalf("post-GC private ID reuse = %+v", got)
	}
}

func TestGenericV1LifecycleIsIdentityFencedAndRetryStable(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	one := lifecycleArtifact(t, "r1", genOneDNA)
	two := lifecycleArtifact(t, "r2", genTwoDNA)
	if err := c.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, one); err != nil {
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
	if err := c.DeactivateForNewConnections(ctx, one.Identity()); err != nil {
		t.Fatalf("stale deactivation was not an idempotent no-op: %v", err)
	}
	if st, err := c.Status(ctx); err != nil || st.Active == nil || *st.Active != two.Identity() {
		t.Fatalf("status after stale deactivation = %+v, %v", st, err)
	}
	flows.counts[1] = 4
	if st, err := c.Status(ctx); err != nil || len(st.Draining) != 1 || st.Draining[0].Identity != one.Identity() || st.Draining[0].RemainingConnections != 4 {
		t.Fatalf("authoritative generic drain status = %+v, %v", st, err)
	}
	if err := c.Rollback(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.Rollback(ctx, one); err != nil {
		t.Fatalf("rollback retry: %v", err)
	}
	if err := c.DeactivateForNewConnections(ctx, two.Identity()); err != nil {
		t.Fatalf("delayed deactivate of challenger: %v", err)
	}
	flows.counts[2] = 0
	result, err := c.Drain(ctx, two.Identity())
	if err != nil || !result.Complete {
		t.Fatalf("drain result = %+v, %v", result, err)
	}
	if err := c.GarbageCollect(ctx, []adapter.ArtifactIdentity{one.Identity()}); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Prepared) != 1 || st.Prepared[0] != one.Identity() || st.Active == nil || *st.Active != one.Identity() {
		t.Fatalf("post-GC generic status = %+v", st)
	}
}

func TestGenericRollbackCanRestageGCdArtifactUnderIntegrityLatch(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	one := lifecycleArtifact(t, "known-good", genOneDNA)
	if err := c.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.DeactivateForNewConnections(ctx, one.Identity()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Drain(ctx, one.Identity()); err != nil {
		t.Fatal(err)
	}
	if err := c.GarbageCollect(ctx, nil); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.unsafe, c.failure = true, "injected integrity fault"
	c.faultLatched.Store(true)
	c.mu.Unlock()
	if err := c.Rollback(ctx, one); err != nil {
		t.Fatalf("restage GC'd known-good rollback: %v", err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Active == nil || *st.Active != one.Identity() || c.State().Unsafe {
		t.Fatalf("rollback recovery state = %+v internal=%+v, %v", st, c.State(), err)
	}
}

func TestStatusReportsAuthoritativeCountsAndHonorsContext(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, NFT: nftables.Config{Port: 443}, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	flows.counts[1] = 7
	st, err := c.DetailedStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Generations) != 1 || st.Generations[0].Connections != 7 {
		t.Fatalf("status = %+v", st)
	}

	c.cfg.Connections = blockingConnections{}
	deadline, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if _, err := c.DetailedStatus(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded status error = %v", err)
	}
}

func TestPersistenceSyncsDirectoryAndRejectsTrailingState(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	syncs := 0
	c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: &fakeConnections{counts: map[uint32]int{}}, SyncDirectory: func(path string) error {
		syncs++
		if path != filepath.Dir(state) {
			t.Errorf("sync path = %s", path)
		}
		return nil
	}}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if syncs < 2 {
		t.Fatalf("directory sync calls = %d", syncs)
	}
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, append(b, []byte(`{"extra":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: &fakeConnections{counts: map[uint32]int{}}}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st := c2.State(); !st.Unsafe || st.ActiveNew != 0 || !strings.Contains(st.IntegrityFailure, "trailing") {
		t.Fatalf("trailing state was not quarantined unsafe: %+v", st)
	}
}

func TestCanonicalDigestIsBareLowerHex(t *testing.T) {
	c := New(engine.NewRegistry(), Config{}, nil)
	if err := c.PrepareGeneration(context.Background(), 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	d := c.State().Generations[0].Digest
	if len(d) != 64 || strings.ToLower(d) != d || strings.Contains(d, ":") {
		t.Fatalf("non-canonical digest %q", d)
	}
}

func TestRestartReconstructsEveryLiveEngineBeforeSteering(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	c1 := New(engine.NewRegistry(), Config{Mode: "prod", NFT: nftables.Config{Port: 443}, NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 2, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 2); err != nil {
		t.Fatal(err)
	}

	reg2 := engine.NewRegistry()
	c2 := New(reg2, Config{Mode: "prod", NFT: nftables.Config{Port: 443}, NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if got := c2.State().ActiveNew; got != 2 {
		t.Fatalf("active after restart = %d", got)
	}
	raw := testutil.BuildTCP(t, 443, testutil.TCPFlags{RST: true}, nil)
	for _, id := range []uint32{1, 2} {
		if _, err := reg2.ProcessGeneration(id, raw, strategy.DirectionOutbound, nil); err != nil {
			t.Fatalf("generation %d not reconstructed: %v", id, err)
		}
	}
}

func TestOrphanedMarksDisableNewSteering(t *testing.T) {
	flows := &fakeConnections{counts: map[uint32]int{}, namespace: 3}
	c := New(engine.NewRegistry(), Config{Mode: "prod", NFT: nftables.Config{Port: 443}, NoNFT: true, Connections: flows}, nil)
	if err := c.Start(context.Background(), genOneDNA); err != nil {
		t.Fatal(err)
	}
	st := c.State()
	if !st.Unsafe || st.ActiveNew != 0 {
		t.Fatalf("orphan audit state = %+v", st)
	}
	if err := c.ActivateNew(context.Background(), 1); err == nil {
		t.Fatal("activated while orphan audit unsafe")
	}
}

func deployment(id uint32, dna, revision string) adapter.Deployment {
	identity := legacyIdentity(id, dna)
	identity.Revision = revision
	return adapter.Deployment{Generation: id, Identity: identity}
}

func TestIdentityCheckedMutationsAreRetryStable(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	one, two := deployment(1, genOneDNA, "r1"), deployment(2, genTwoDNA, "r2")
	if err := c.PrepareDeployment(ctx, one, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateDeployment(ctx, one, adapter.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareDeployment(ctx, two, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateDeployment(ctx, two, one); err != nil {
		t.Fatal(err)
	}
	if err := c.DeactivateDeployment(ctx, one); err == nil {
		t.Fatal("stale deactivation changed a later active generation")
	}
	if got := c.State().ActiveNew; got != 2 {
		t.Fatalf("active after stale deactivate = %d", got)
	}
	if err := c.RollbackDeployment(ctx, one, two); err != nil {
		t.Fatal(err)
	}
	if err := c.RollbackDeployment(ctx, one, two); err != nil {
		t.Fatalf("rollback retry was not stable: %v", err)
	}
	if err := c.DeactivateDeployment(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.DeactivateDeployment(ctx, one); err != nil {
		t.Fatalf("deactivate retry was not stable: %v", err)
	}
}

func TestRetainedDrainedPreviousKnownGoodCanReactivate(t *testing.T) {
	ctx := context.Background()
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, Connections: flows}, nil)
	_ = c.Start(ctx, "")
	one, two := deployment(1, genOneDNA, "r1"), deployment(2, genTwoDNA, "r2")
	if err := c.PrepareDeployment(ctx, one, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateDeployment(ctx, one, adapter.Deployment{}); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareDeployment(ctx, two, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateDeployment(ctx, two, one); err != nil {
		t.Fatal(err)
	}
	if remaining, err := c.DrainDeployment(ctx, one); err != nil || remaining != 0 {
		t.Fatalf("drain remaining = %d, %v", remaining, err)
	}
	if err := c.RollbackDeployment(ctx, one, two); err != nil {
		t.Fatalf("reactivate retained drained PBG: %v", err)
	}
}

func TestDirectorySyncFailureIsFatalAndDoesNotProgramKernel(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	syncErr := errors.New("injected directory sync failure")
	failSync := false
	programCalls := 0
	fatal := make(chan error, 1)
	c := New(engine.NewRegistry(), Config{
		StateFile: state, Connections: &fakeConnections{counts: map[uint32]int{}},
		SyncDirectory: func(string) error {
			if failSync {
				return syncErr
			}
			return nil
		},
		Program: func(context.Context, nftables.Config, bool) error { programCalls++; return nil },
		Fatal:   func(err error) { fatal <- err },
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	before := programCalls
	failSync = true
	if err := c.ActivateNew(ctx, 1); err == nil || !strings.Contains(err.Error(), syncErr.Error()) {
		t.Fatalf("activation durability error = %v", err)
	}
	if programCalls != before {
		t.Fatalf("kernel programmed after uncertain directory durability: before=%d after=%d", before, programCalls)
	}
	select {
	case err := <-fatal:
		if !strings.Contains(err.Error(), "durability") {
			t.Fatalf("fatal error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("directory-sync failure did not request process restart")
	}
	if st := c.State(); !st.Unsafe {
		t.Fatalf("directory-sync failure did not latch unsafe: %+v", st)
	}
}

func TestFileSyncFailureDoesNotRenameOrProgramKernel(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	failSync := false
	programCalls := 0
	fatal := make(chan error, 1)
	c := New(engine.NewRegistry(), Config{
		StateFile: state, Connections: &fakeConnections{counts: map[uint32]int{}},
		SyncFile: func(file *os.File) error {
			if failSync {
				return errors.New("injected file sync failure")
			}
			return file.Sync()
		},
		Program: func(context.Context, nftables.Config, bool) error { programCalls++; return nil },
		Fatal:   func(err error) { fatal <- err },
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	beforeState, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	beforePrograms := programCalls
	failSync = true
	if err := c.ActivateNew(ctx, 1); err == nil || !strings.Contains(err.Error(), "file sync") {
		t.Fatalf("activation file-sync error = %v", err)
	}
	afterState, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterState) != string(beforeState) {
		t.Fatal("file-sync failure replaced durable state")
	}
	if programCalls != beforePrograms {
		t.Fatal("file-sync failure allowed kernel mutation")
	}
	select {
	case <-fatal:
	case <-time.After(time.Second):
		t.Fatal("file-sync failure did not request process restart")
	}
}

func TestRestartRestagesDurableActiveThroughNeutralBoundary(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows1 := &fakeConnections{counts: map[uint32]int{}}
	c1 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows1}, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}

	// A durable active record is indistinguishable from a crash immediately
	// after intent persistence, including one with a preactivation half-open SYN.
	// Restart must never install active assignment directly from that record.
	flows2 := &fakeConnections{counts: map[uint32]int{1: 2}}
	var calls []nftables.Config
	c2 := New(engine.NewRegistry(), Config{
		StateFile: state, Connections: flows2,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			calls = append(calls, cfg)
			return nil
		},
	}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("restart program calls = %d, want stale removal + neutral union + active flip: %+v", len(calls), calls)
	}
	if calls[0].ActiveGeneration != 0 || len(calls[0].Generations) != 0 {
		t.Fatalf("restart did not first remove stale assignment: %+v", calls[0])
	}
	if !calls[1].NeutralizeNew || calls[1].ActiveGeneration != 0 || len(calls[1].Generations) != 1 {
		t.Fatalf("restart neutral boundary = %+v", calls[1])
	}
	if calls[2].NeutralizeNew || calls[2].ActiveGeneration != 1 || len(calls[2].Generations) != 1 {
		t.Fatalf("restart assignment flip = %+v", calls[2])
	}
	if flows2.neutralized != 1 {
		t.Fatalf("pre-existing/half-open conntrack neutralization calls = %d", flows2.neutralized)
	}
	if got := c2.State().ActiveNew; got != 1 {
		t.Fatalf("restored active generation = %d", got)
	}
}

func writeActiveLifecycleState(t *testing.T, runtimeVersion string) (string, *fakeConnections) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, RuntimeVersion: runtimeVersion, Connections: flows}, nil)
	ctx := context.Background()
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	return state, flows
}

func mutatePersistedGenerationMetadata(t *testing.T, state string, mutate func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	generations := raw["generations"].([]any)
	metadata := generations[0].(map[string]any)["artifact_metadata"].(map[string]any)
	mutate(metadata)
	b, err = json.MarshalIndent(raw, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(state, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRestartRequiresExactPersistedArtifactCompatibility(t *testing.T) {
	t.Run("compatible", func(t *testing.T) {
		state, flows := writeActiveLifecycleState(t, "runtime-a")
		c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, RuntimeVersion: "runtime-a", Connections: flows}, nil)
		if err := c.Start(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		if st := c.State(); st.Unsafe || st.ActiveNew != 1 {
			t.Fatalf("compatible restart state = %+v", st)
		}
	})

	for _, tc := range []struct {
		name    string
		runtime string
		mutate  func(map[string]any)
		want    string
	}{
		{name: "runtime", runtime: "runtime-b", mutate: func(map[string]any) {}, want: "runtime version"},
		{name: "protocol", runtime: "runtime-a", mutate: func(m map[string]any) { m["adapter_protocol"] = float64(2) }, want: "adapter protocol"},
		{name: "schema", runtime: "runtime-a", mutate: func(m map[string]any) { m["schema_version"] = float64(2) }, want: "schema"},
		{name: "missing metadata", runtime: "runtime-a", mutate: func(m map[string]any) { clear(m) }, want: "metadata"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, flows := writeActiveLifecycleState(t, "runtime-a")
			mutatePersistedGenerationMetadata(t, state, tc.mutate)
			c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, RuntimeVersion: tc.runtime, Connections: flows}, nil)
			if err := c.Start(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
			st := c.State()
			if !st.Unsafe || st.ActiveNew != 0 || !strings.Contains(st.IntegrityFailure, tc.want) {
				t.Fatalf("incompatible restart state = %+v, want failure containing %q", st, tc.want)
			}
			quarantined, err := filepath.Glob(state + ".quarantine-*")
			if err != nil || len(quarantined) != 1 {
				t.Fatalf("quarantined state = %v, %v", quarantined, err)
			}
		})
	}

	t.Run("metadata-less v1", func(t *testing.T) {
		state, flows := writeActiveLifecycleState(t, "runtime-a")
		b, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		raw["version"] = float64(1)
		for _, encoded := range raw["generations"].([]any) {
			delete(encoded.(map[string]any), "artifact_metadata")
		}
		b, err = json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(state, b, 0o600); err != nil {
			t.Fatal(err)
		}
		c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, RuntimeVersion: "runtime-a", Connections: flows}, nil)
		if err := c.Start(context.Background(), ""); err != nil {
			t.Fatal(err)
		}
		if st := c.State(); !st.Unsafe || st.ActiveNew != 0 || !strings.Contains(st.IntegrityFailure, "state version 1") {
			t.Fatalf("metadata-less v1 restart state = %+v", st)
		}
	})
}

func TestIncompatibleStateStillRestoresDurableOffloadOwnership(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	original := &netdev.Original{Interface: "eth-test", Features: []string{"tso"}}
	c1 := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, RuntimeVersion: "runtime-a", Connections: flows, Iface: "eth-test",
		CaptureOffloads: func(context.Context, string, string) (*netdev.Original, error) { return original, nil },
		DisableOffloads: func(context.Context, string, *netdev.Original) error { return nil },
		RestoreOffloads: func(context.Context, string, *netdev.Original) error { return nil },
	}, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	restores := 0
	c2 := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, RuntimeVersion: "runtime-b", Connections: flows, Iface: "eth-test",
		RestoreOffloads: func(_ context.Context, _ string, got *netdev.Original) error {
			restores++
			if got.Interface != original.Interface || len(got.Features) != 1 || got.Features[0] != "tso" {
				t.Fatalf("restored offload ownership = %+v", got)
			}
			return nil
		},
	}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if restores != 1 || c2.State().OffloadsDisabled {
		t.Fatalf("incompatible restart restores=%d state=%+v", restores, c2.State())
	}
}

func TestRollbackAllocatesOnlyGenerationProvenFreeOfOrphanFlows(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	var calls []nftables.Config
	reg := engine.NewRegistry()
	c := New(reg, Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			calls = append(calls, cfg)
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st := c.State(); !st.Unsafe || st.ActiveNew != 0 {
		t.Fatalf("orphan startup state = %+v", st)
	}
	calls = nil
	artifact := lifecycleArtifact(t, "orphan-recovery", genOneDNA)
	if err := c.Rollback(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	st := c.State()
	if st.Unsafe || st.ActiveNew != 2 || len(st.Generations) != 1 || st.Generations[0].ID != 2 {
		t.Fatalf("rollback reused orphan generation: %+v", st)
	}
	for _, call := range calls {
		for _, gen := range call.Generations {
			if gen.ID == 1 {
				t.Fatalf("orphan generation entered steering union: %+v", call)
			}
		}
	}
	raw := testutil.BuildTCP(t, 443, testutil.TCPFlags{SYN: true}, nil)
	if _, err := reg.ProcessGeneration(1, raw, strategy.DirectionOutbound, nil); !errors.Is(err, engine.ErrGenerationNotFound) {
		t.Fatalf("orphan generation was dispatchable: %v", err)
	}
}

func TestRollbackGenerationProofFailureHasNoMutationAndCanRetry(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	programs := 0
	c := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(context.Context, nftables.Config, bool) error { programs++; return nil },
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	programs = 0
	flows.countsErr = errors.New("injected conntrack dump failure")
	artifact := lifecycleArtifact(t, "retry-after-count", genOneDNA)
	if err := c.Rollback(ctx, artifact); err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("rollback count error = %v", err)
	}
	after, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) || programs != 0 || len(c.State().Generations) != 0 {
		t.Fatalf("failed proof mutated state: programs=%d state=%+v", programs, c.State())
	}
	flows.countsErr = nil
	if err := c.Rollback(ctx, artifact); err != nil {
		t.Fatalf("retry after authoritative snapshot: %v", err)
	}
	if got := c.State().ActiveNew; got != 2 {
		t.Fatalf("retry generation = %d, want 2", got)
	}
}

func TestRollbackGenerationProofHandlesExhaustionAndLaterZero(t *testing.T) {
	ctx := context.Background()
	counts := make(map[uint32]int, generation.MaxID)
	for id := uint32(1); id <= generation.MaxID; id++ {
		counts[id] = 1
	}
	flows := &fakeConnections{counts: counts}
	c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: filepath.Join(t.TempDir(), "adapter.json"), Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	artifact := lifecycleArtifact(t, "exhausted", genOneDNA)
	if err := c.Rollback(ctx, artifact); err == nil || !strings.Contains(err.Error(), "no proven-zero") {
		t.Fatalf("exhausted rollback error = %v", err)
	}
	flows.counts = map[uint32]int{1: 1}
	if err := c.Rollback(ctx, artifact); err != nil {
		t.Fatalf("rollback after authoritative zero snapshot: %v", err)
	}
	if got := c.State().ActiveNew; got != 2 {
		t.Fatalf("post-zero generation = %d, want 2", got)
	}
}

func TestCorruptStateIsQuarantinedAndOrphanIDsRemainReserved(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	if err := os.WriteFile(state, []byte("{not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	c := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st := c.State(); !st.Unsafe || st.ActiveNew != 0 || !strings.Contains(st.IntegrityFailure, "quarantined") {
		t.Fatalf("corrupt startup state = %+v", st)
	}
	quarantined, err := filepath.Glob(state + ".quarantine-*")
	if err != nil || len(quarantined) != 1 {
		t.Fatalf("quarantined files = %v, %v", quarantined, err)
	}
	if err := c.Rollback(ctx, lifecycleArtifact(t, "corrupt-recovery", genOneDNA)); err != nil {
		t.Fatal(err)
	}
	if got := c.State().ActiveNew; got != 2 {
		t.Fatalf("corrupt-state recovery reused orphan: generation=%d", got)
	}
}

func TestQuarantineRemediatesThroughGenericT8ChampionSequence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(*testing.T) (string, *fakeConnections)
		runtime string
	}{
		{
			name: "corrupt state",
			setup: func(t *testing.T) (string, *fakeConnections) {
				state := filepath.Join(t.TempDir(), "adapter.json")
				if err := os.WriteFile(state, []byte("{not-json\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return state, &fakeConnections{counts: map[uint32]int{1: 1}}
			},
			runtime: "dev",
		},
		{
			name: "incompatible state",
			setup: func(t *testing.T) (string, *fakeConnections) {
				state, flows := writeActiveLifecycleState(t, "runtime-a")
				flows.counts[1] = 1
				return state, flows
			},
			runtime: "runtime-b",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			state, flows := tc.setup(t)
			var calls []nftables.Config
			var installed nftables.Config
			newController := func() *Controller {
				return New(engine.NewRegistry(), Config{
					NoNFT: true, StateFile: state, RuntimeVersion: tc.runtime, Connections: flows,
					Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
						calls = append(calls, cfg)
						installed = cfg
						return nil
					},
					VerifyProgram: func(_ context.Context, want nftables.Config) error {
						if !sameProgram(installed, want) {
							return errors.New("installed steering is not exactly neutral")
						}
						return nil
					},
				}, nil)
			}
			artifact := lifecycleArtifactForRuntime(t, "newer-champion", genOneDNA, tc.runtime)
			c := newController()
			if err := c.Start(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 {
				t.Fatalf("quarantine state = %+v", st)
			}
			calls = nil
			// This is the exact t8 deployLocked/activateTargetLocked sequence for a
			// newer champion at lantern-cloud 5cf7ac68f.
			if err := c.Prepare(ctx, artifact); err != nil {
				t.Fatalf("prepare newer champion: %v", err)
			}
			if len(calls) != 0 {
				t.Fatalf("prepare programmed steering while quarantined: %+v", calls)
			}
			if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 {
				t.Fatalf("prepare cleared quarantine health: %+v", st)
			}
			persisted, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(persisted), "generic_remediation_allowed") {
				t.Fatal("process-local verified-neutral proof leaked into durable state")
			}
			if err := c.Verify(ctx, artifact); err != nil {
				t.Fatalf("verify newer champion: %v", err)
			}
			if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 {
				t.Fatalf("verify cleared quarantine health: %+v", st)
			}

			// Crash after the fsynced recovery Prepare. The process-local proof is
			// gone; Start and the replayed Prepare must re-read both kernel and
			// conntrack state before activation is allowed.
			calls = nil
			preparedRestart := newController()
			if err := preparedRestart.Start(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if st := preparedRestart.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 1 || st.Generations[0].ID != 2 {
				t.Fatalf("post-prepare restart state = %+v", st)
			}
			calls = nil
			if err := preparedRestart.Prepare(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			if err := preparedRestart.Verify(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			c = preparedRestart
			if err := c.ActivateForNewConnections(ctx, artifact); err != nil {
				t.Fatalf("activate newer champion: %v", err)
			}
			st := c.State()
			if st.Unsafe || st.Remediation || st.ActiveNew != 2 {
				t.Fatalf("remediated state = %+v", st)
			}
			if len(calls) != 2 || !calls[0].NeutralizeNew || calls[0].ActiveGeneration != 0 || calls[1].NeutralizeNew || calls[1].ActiveGeneration != 2 {
				t.Fatalf("remediation transactions = %+v", calls)
			}
			for _, call := range calls {
				for _, gen := range call.Generations {
					if gen.ID == 1 {
						t.Fatalf("orphan generation entered remediation union: %+v", call)
					}
				}
			}

			// A crash after durable preparation or activation preserves the
			// remediable latch. t8 can replay the same generic sequence without a
			// Geneva-specific Rollback call.
			calls = nil
			restarted := newController()
			if err := restarted.Start(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if st := restarted.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 {
				t.Fatalf("restart remediation state = %+v", st)
			}
			calls = nil
			if err := restarted.Prepare(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			if err := restarted.Verify(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			if err := restarted.ActivateForNewConnections(ctx, artifact); err != nil {
				t.Fatal(err)
			}
			if st := restarted.State(); st.Unsafe || st.Remediation || st.ActiveNew != 2 {
				t.Fatalf("replayed remediation state = %+v", st)
			}
		})
	}
}

func TestRecoveryPrepareRearmsAfterTransientStartupFailures(t *testing.T) {
	t.Run("conntrack snapshot", func(t *testing.T) {
		ctx := context.Background()
		state := filepath.Join(t.TempDir(), "adapter.json")
		if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		flows := &fakeConnections{counts: map[uint32]int{1: 1}, countsErr: errors.New("transient startup count failure")}
		var installed nftables.Config
		programs := 0
		c := New(engine.NewRegistry(), Config{
			NoNFT: true, StateFile: state, Connections: flows,
			Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
				programs++
				installed = cfg
				return nil
			},
			VerifyProgram: func(_ context.Context, want nftables.Config) error {
				if !sameProgram(installed, want) {
					return errors.New("unexpected installed steering")
				}
				return nil
			},
		}, nil)
		if err := c.Start(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if st := c.State(); !st.Unsafe || st.Remediation || st.ActiveNew != 0 {
			t.Fatalf("startup count failure state = %+v", st)
		}
		artifact := lifecycleArtifact(t, "startup-count-retry", genOneDNA)
		before, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		programs = 0
		if err := c.Prepare(ctx, artifact); err == nil {
			t.Fatal("recovery Prepare succeeded while the conntrack snapshot still failed")
		}
		after, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		if programs != 0 || string(after) != string(before) || len(c.State().Generations) != 0 {
			t.Fatalf("failed startup-count retry mutated state: programs=%d state=%+v", programs, c.State())
		}

		flows.countsErr = nil
		if err := c.Prepare(ctx, artifact); err != nil {
			t.Fatalf("same-process recovery Prepare retry: %v", err)
		}
		if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 1 || st.Generations[0].ID != 2 {
			t.Fatalf("rearmed startup-count recovery state = %+v", st)
		}
	})

	t.Run("final exact readback", func(t *testing.T) {
		ctx := context.Background()
		state := filepath.Join(t.TempDir(), "adapter.json")
		if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		flows := &fakeConnections{counts: map[uint32]int{1: 1}}
		var installed nftables.Config
		programs, verifies := 0, 0
		c := New(engine.NewRegistry(), Config{
			NoNFT: true, StateFile: state, Connections: flows,
			Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
				programs++
				installed = cfg
				return nil
			},
			VerifyProgram: func(_ context.Context, want nftables.Config) error {
				verifies++
				// Call 1 verifies the startup program. Call 2 is Start's final
				// recovery readback; call 3 is the first Prepare retry.
				if verifies == 2 || verifies == 3 {
					return errors.New("transient final exact-readback failure")
				}
				if !sameProgram(installed, want) {
					return errors.New("unexpected installed steering")
				}
				return nil
			},
		}, nil)
		if err := c.Start(ctx, ""); err != nil {
			t.Fatal(err)
		}
		if st := c.State(); !st.Unsafe || st.Remediation || st.ActiveNew != 0 {
			t.Fatalf("startup readback failure state = %+v", st)
		}
		artifact := lifecycleArtifact(t, "startup-readback-retry", genOneDNA)
		before, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		programs = 0
		if err := c.Prepare(ctx, artifact); err == nil {
			t.Fatal("first recovery Prepare unexpectedly passed transient readback failure")
		}
		after, err := os.ReadFile(state)
		if err != nil {
			t.Fatal(err)
		}
		if programs != 0 || string(after) != string(before) || len(c.State().Generations) != 0 {
			t.Fatalf("failed startup-readback retry mutated state: programs=%d state=%+v", programs, c.State())
		}
		if err := c.Prepare(ctx, artifact); err != nil {
			t.Fatalf("same-process recovery Prepare retry: %v", err)
		}
		if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 1 || st.Generations[0].ID != 2 {
			t.Fatalf("rearmed startup-readback recovery state = %+v", st)
		}
	})
}

func TestGenericRecoveryRearmsAfterAsyncIntegrityReconciliation(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	var installed nftables.Config
	c := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			installed = cfg
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("unexpected installed steering")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	one := lifecycleArtifact(t, "integrity-pbg", genOneDNA)
	two := lifecycleArtifact(t, "integrity-newer", genTwoDNA)
	if err := c.Prepare(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, one); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, one); err != nil {
		t.Fatal(err)
	}
	flows.counts[1] = 1
	c.IntegrityFailure(errors.New("injected post-activation integrity failure"))
	deadline := time.Now().Add(time.Second)
	for {
		st := c.State()
		if st.Unsafe && !st.Remediation && st.ActiveNew == 0 && !c.integrityReconciling.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("async integrity reconciliation did not become inactive: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}

	if err := c.Prepare(ctx, two); err != nil {
		t.Fatalf("generic Prepare did not re-arm after async reconciliation: %v", err)
	}
	if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 2 {
		t.Fatalf("post-integrity recovery Prepare state = %+v", st)
	}
	if err := c.Verify(ctx, two); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, two); err != nil {
		t.Fatal(err)
	}
	if st := c.State(); st.Unsafe || st.Remediation || st.ActiveNew != 2 || len(st.Generations) != 2 {
		t.Fatalf("post-integrity generic recovery state = %+v", st)
	}
}

func TestIntegritySignalInterruptsRecoveryPrepareRearm(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	var installed nftables.Config
	var c *Controller
	c = New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			installed = cfg
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("unexpected installed steering")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	c.IntegrityFailure(errors.New("clear initial recovery gate"))
	deadline := time.Now().Add(time.Second)
	for c.integrityReconciling.Load() {
		if time.Now().After(deadline) {
			t.Fatal("initial integrity reconciliation did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	flows.countsHook = func() {
		c.IntegrityFailure(errors.New("interrupt recovery conntrack proof"))
	}
	artifact := lifecycleArtifact(t, "interrupted-rearm", genOneDNA)
	if err := c.Prepare(ctx, artifact); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("interrupted recovery Prepare error = %v", err)
	}
	if len(c.State().Generations) != 0 {
		t.Fatalf("interrupted recovery Prepare created an engine: %+v", c.State())
	}
	flows.countsHook = nil
	deadline = time.Now().Add(time.Second)
	for c.integrityReconciling.Load() {
		if time.Now().After(deadline) {
			t.Fatal("interrupting integrity reconciliation did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if err := c.Prepare(ctx, artifact); err != nil {
		t.Fatalf("recovery Prepare did not re-arm after interruption: %v", err)
	}
}

func TestRecoveryPrepareProofFailuresAreMutationFreeAndRetryable(t *testing.T) {
	for _, proof := range []string{"nft readback", "conntrack snapshot"} {
		t.Run(proof, func(t *testing.T) {
			ctx := context.Background()
			state := filepath.Join(t.TempDir(), "adapter.json")
			if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			flows := &fakeConnections{counts: map[uint32]int{1: 1}}
			var installed nftables.Config
			programs := 0
			readbackErr := error(nil)
			c := New(engine.NewRegistry(), Config{
				NoNFT: true, StateFile: state, Connections: flows,
				Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
					programs++
					installed = cfg
					return nil
				},
				VerifyProgram: func(_ context.Context, want nftables.Config) error {
					if readbackErr != nil {
						return readbackErr
					}
					if !sameProgram(installed, want) {
						return errors.New("unexpected installed steering")
					}
					return nil
				},
			}, nil)
			if err := c.Start(ctx, ""); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			programs = 0
			if proof == "nft readback" {
				readbackErr = errors.New("injected exact-readback failure")
			} else {
				flows.countsErr = errors.New("injected conntrack snapshot failure")
			}
			artifact := lifecycleArtifact(t, "retryable-newer", genOneDNA)
			if err := c.Prepare(ctx, artifact); err == nil {
				t.Fatal("recovery Prepare succeeded without its proof")
			}
			after, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			if programs != 0 || string(after) != string(before) || len(c.State().Generations) != 0 {
				t.Fatalf("failed recovery proof mutated state: programs=%d state=%+v", programs, c.State())
			}
			readbackErr = nil
			flows.countsErr = nil
			if err := c.Prepare(ctx, artifact); err != nil {
				t.Fatalf("recovery Prepare retry: %v", err)
			}
			if st := c.State(); !st.Unsafe || !st.Remediation || len(st.Generations) != 1 || st.Generations[0].ID != 2 {
				t.Fatalf("recovery Prepare retry state = %+v", st)
			}
		})
	}
}

func TestRecoveryActivateReprovesNeutralSteeringBeforeMutation(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	var installed nftables.Config
	programs := 0
	var readbackErr error
	c := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			programs++
			installed = cfg
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if readbackErr != nil {
				return readbackErr
			}
			if !sameProgram(installed, want) {
				return errors.New("unexpected installed steering")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	artifact := lifecycleArtifact(t, "activate-reproof", genOneDNA)
	if err := c.Prepare(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	programs = 0
	readbackErr = errors.New("injected pre-activation readback failure")
	if err := c.ActivateForNewConnections(ctx, artifact); err == nil {
		t.Fatal("recovery activation succeeded after its neutral proof was lost")
	}
	after, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if programs != 0 || string(after) != string(before) {
		t.Fatalf("failed recovery activation mutated state: programs=%d", programs)
	}
	if st := c.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 {
		t.Fatalf("failed recovery activation state = %+v", st)
	}

	readbackErr = nil
	if err := c.ActivateForNewConnections(ctx, artifact); err != nil {
		t.Fatalf("recovery activation retry: %v", err)
	}
	if st := c.State(); st.Unsafe || st.Remediation || st.ActiveNew != 2 {
		t.Fatalf("recovery activation retry state = %+v", st)
	}
	if programs != 2 {
		t.Fatalf("recovery activation programmed %d transactions, want neutral stage and direct flip", programs)
	}
}

func TestIntegritySignalInterruptsGenericRecoveryActivation(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	var installed nftables.Config
	var c *Controller
	interrupt := false
	c = New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			installed = cfg
			if interrupt {
				interrupt = false
				c.IntegrityFailure(errors.New("integrity fault during generic recovery activation"))
			}
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("unexpected installed steering")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	artifact := lifecycleArtifact(t, "interrupted-recovery", genOneDNA)
	if err := c.Prepare(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	interrupt = true
	if err := c.ActivateForNewConnections(ctx, artifact); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("interrupted recovery activation error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		st := c.State()
		if st.Unsafe && !st.Remediation && st.ActiveNew == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("integrity reconciliation did not restore inactive quarantine: %+v", st)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRecoveryPrepareDirectorySyncAmbiguityIsFatalWithoutSteering(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	if err := os.WriteFile(state, []byte("{corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	var installed nftables.Config
	programs := 0
	failSync := false
	fatal := make(chan error, 1)
	c := New(engine.NewRegistry(), Config{
		NoNFT: true, StateFile: state, Connections: flows,
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			programs++
			installed = cfg
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("unexpected installed steering")
			}
			return nil
		},
		SyncDirectory: func(string) error {
			if failSync {
				return errors.New("injected directory sync ambiguity")
			}
			return nil
		},
		Fatal: func(err error) { fatal <- err },
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	programs = 0
	failSync = true
	artifact := lifecycleArtifact(t, "fatal-newer", genOneDNA)
	if err := c.Prepare(ctx, artifact); err == nil || !strings.Contains(err.Error(), "durability") {
		t.Fatalf("directory-sync recovery Prepare error = %v", err)
	}
	if programs != 0 {
		t.Fatalf("ambiguous recovery Prepare programmed steering %d times", programs)
	}
	if st := c.State(); !st.Unsafe || st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 0 {
		t.Fatalf("ambiguous recovery Prepare state = %+v", st)
	}
	select {
	case <-fatal:
	case <-time.After(time.Second):
		t.Fatal("directory sync ambiguity did not request fatal restart")
	}
	if err := c.Prepare(ctx, artifact); err == nil {
		t.Fatal("durability-fatal controller accepted recovery retry")
	}
}

func TestGenericRecoveryPreservesPreviousKnownGoodGenerations(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{}}
	var installed nftables.Config
	var calls []nftables.Config
	config := func() Config {
		return Config{
			NoNFT: true, StateFile: state, Connections: flows, MaxScopedGenerations: 3,
			Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
				installed = cfg
				calls = append(calls, cfg)
				return nil
			},
			VerifyProgram: func(_ context.Context, want nftables.Config) error {
				if !sameProgram(installed, want) {
					return errors.New("unexpected installed steering")
				}
				return nil
			},
		}
	}
	one := lifecycleArtifact(t, "champion-one", genOneDNA)
	two := lifecycleArtifact(t, "challenger-two", genTwoDNA)
	three := lifecycleArtifact(t, "newer-champion-three", genOneDNA)
	c1 := New(engine.NewRegistry(), config(), nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	for _, artifact := range []adapter.Artifact{one, two} {
		if err := c1.Prepare(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		if err := c1.ActivateForNewConnections(ctx, artifact); err != nil {
			t.Fatal(err)
		}
	}
	flows.counts = map[uint32]int{1: 1, 2: 1}
	c1.mu.Lock()
	c1.integrityFailureLocked(ctx, errors.New("injected integrity latch"))
	c1.mu.Unlock()

	calls = nil
	c2 := New(engine.NewRegistry(), config(), nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st := c2.State(); !st.Unsafe || !st.Remediation || st.ActiveNew != 0 || len(st.Generations) != 2 {
		t.Fatalf("recovery start did not retain PBG generations: %+v", st)
	}
	calls = nil
	if err := c2.Prepare(ctx, three); err != nil {
		t.Fatal(err)
	}
	if err := c2.Verify(ctx, three); err != nil {
		t.Fatal(err)
	}
	if err := c2.ActivateForNewConnections(ctx, three); err != nil {
		t.Fatal(err)
	}
	st := c2.State()
	if st.Unsafe || st.Remediation || st.ActiveNew != 3 || len(st.Generations) != 3 {
		t.Fatalf("PBG recovery result = %+v", st)
	}
	want := map[adapter.ArtifactIdentity]bool{one.Identity(): true, two.Identity(): true, three.Identity(): true}
	for _, gen := range st.Generations {
		delete(want, gen.Identity)
	}
	if len(want) != 0 {
		t.Fatalf("recovery discarded retained identities: %v", want)
	}
	if len(calls) != 2 {
		t.Fatalf("recovery activation calls = %+v", calls)
	}
	for _, call := range calls {
		if len(call.Generations) != 3 {
			t.Fatalf("recovery union omitted retained generation: %+v", call)
		}
	}
}

func TestRestartReenumeratesOrphanReservations(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	flows := &fakeConnections{counts: map[uint32]int{1: 1}}
	first := lifecycleArtifact(t, "first-recovery", genOneDNA)
	c1 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.Rollback(ctx, first); err != nil {
		t.Fatal(err)
	}
	c2 := New(engine.NewRegistry(), Config{NoNFT: true, StateFile: state, Connections: flows}, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c2.Rollback(ctx, first); err != nil {
		t.Fatalf("repair retained generation after orphan re-enumeration: %v", err)
	}
	next := lifecycleArtifact(t, "after-restart", genTwoDNA)
	if err := c2.Prepare(ctx, next); err != nil {
		t.Fatal(err)
	}
	c2.mu.Lock()
	_, gen, err := c2.generationForIdentityLocked(next.Identity())
	c2.mu.Unlock()
	if err != nil || gen == nil || gen.ID != 3 {
		t.Fatalf("post-restart generation = %+v, %v; want 3", gen, err)
	}
}

func TestOffloadOwnershipSurvivesCrashAndNeverClaimsPreDisabled(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	captures, disables, restores := 0, 0, 0
	cfg := Config{NoNFT: true, StateFile: state, Iface: "eth-test", Connections: &fakeConnections{counts: map[uint32]int{}},
		CaptureOffloads: func(context.Context, string, string) (*netdev.Original, error) {
			captures++
			return &netdev.Original{Interface: "eth-test", Features: []string{"gso", "tso"}}, nil
		},
		DisableOffloads: func(_ context.Context, _ string, original *netdev.Original) error { disables++; return nil },
		RestoreOffloads: func(_ context.Context, _ string, original *netdev.Original) error {
			restores++
			original.Features = nil
			return nil
		},
	}
	c1 := New(engine.NewRegistry(), cfg, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if captures != 1 || disables != 1 {
		t.Fatalf("capture/disable = %d/%d", captures, disables)
	}

	c2 := New(engine.NewRegistry(), cfg, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if captures != 1 || disables != 2 {
		t.Fatalf("restart recaptured ownership: capture/disable = %d/%d", captures, disables)
	}
	if err := c2.DeactivateNew(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.DrainGeneration(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c2.GarbageCollectGeneration(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if restores != 1 {
		t.Fatalf("restore calls = %d", restores)
	}

	preDisabled := cfg
	preDisabled.StateFile = filepath.Join(t.TempDir(), "adapter.json")
	preDisabled.CaptureOffloads = func(context.Context, string, string) (*netdev.Original, error) {
		return &netdev.Original{Interface: "eth-test"}, nil
	}
	preDisabled.DisableOffloads = func(context.Context, string, *netdev.Original) error { return fmt.Errorf("must not disable") }
	c3 := New(engine.NewRegistry(), preDisabled, nil)
	if err := c3.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c3.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c3.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if c3.State().OffloadsDisabled {
		t.Fatal("claimed ownership of pre-disabled features")
	}
}

func TestPartialOffloadRestoreRetainsRetryableOwnership(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	firstRestore := true
	cfg := Config{
		NoNFT: true, StateFile: state, Iface: "eth-test", Connections: &fakeConnections{counts: map[uint32]int{}},
		CaptureOffloads: func(context.Context, string, string) (*netdev.Original, error) {
			return &netdev.Original{Interface: "eth-test", Features: []string{"gso", "tso"}}, nil
		},
		DisableOffloads: func(context.Context, string, *netdev.Original) error { return nil },
		RestoreOffloads: func(_ context.Context, _ string, original *netdev.Original) error {
			if firstRestore {
				firstRestore = false
				original.Features = []string{"tso"} // gso was restored; tso remains owned
				return errors.New("tso restore failed")
			}
			original.Features = nil
			return nil
		},
	}
	c1 := New(engine.NewRegistry(), cfg, nil)
	if err := c1.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c1.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c1.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c1.DeactivateNew(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.DrainGeneration(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c1.GarbageCollectGeneration(ctx, 1); err == nil {
		t.Fatal("partial offload restoration reported success")
	}
	if !c1.State().OffloadsDisabled {
		t.Fatal("partial restoration dropped controller ownership")
	}

	c2 := New(engine.NewRegistry(), cfg, nil)
	if err := c2.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if c2.State().OffloadsDisabled {
		t.Fatal("restart did not finish restoring the retained feature")
	}
}

func TestStartConntrackAuditHasControllerDeadline(t *testing.T) {
	c := New(engine.NewRegistry(), Config{NoNFT: true, Connections: wedgedConnections{}, ConntrackTimeout: 10 * time.Millisecond}, nil)
	start := time.Now()
	if err := c.Start(context.Background(), genOneDNA); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Start blocked for %s", elapsed)
	}
	if st := c.State(); !st.Unsafe || st.Remediation || st.ActiveNew != 0 {
		t.Fatalf("bounded startup state = %+v", st)
	}
}

func TestStartRemovesStaleAssignmentBeforeConntrackAudit(t *testing.T) {
	events := make(chan string, 4)
	c := New(engine.NewRegistry(), Config{
		Connections: orderingConnections{events: events},
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			if cfg.ActiveGeneration == 0 && len(cfg.Generations) == 0 {
				events <- "inactive rules"
				return nil
			}
			return fmt.Errorf("unexpected startup steering: active=%d generations=%d", cfg.ActiveGeneration, len(cfg.Generations))
		},
	}, nil)
	if err := c.Start(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if first := <-events; first != "inactive rules" {
		t.Fatalf("first startup kernel operation = %q, want stale assignment removal", first)
	}
	if second := <-events; second != "conntrack audit" {
		t.Fatalf("second startup operation = %q, want conntrack audit", second)
	}
}

func TestIntegritySignalDoesNotWaitForStatusConntrackDump(t *testing.T) {
	flows := blockingConnections{}
	programmed := make(chan uint32, 4)
	c := New(engine.NewRegistry(), Config{NFT: nftables.Config{Port: 443}, Connections: flows, ConntrackTimeout: 100 * time.Millisecond, Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
		programmed <- cfg.ActiveGeneration
		return nil
	}}, nil)
	c.mu.Lock()
	c.generations[1] = &generationState{ID: 1, DNA: genOneDNA, Digest: legacyIdentity(1, genOneDNA).Digest, Identity: legacyIdentity(1, genOneDNA), Phase: PhaseActive, Scope: mustScope(t, genOneDNA)}
	c.activeNew = 1
	_ = c.eng.Prepare(1, genOneDNA)
	_ = c.eng.Activate(1)
	c.mu.Unlock()

	statusDone := make(chan struct{})
	go func() { _, _ = c.Status(context.Background()); close(statusDone) }()
	time.Sleep(5 * time.Millisecond)
	start := time.Now()
	c.IntegrityFailure(errors.New("missing generation"))
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("hot-path signal blocked for %s", elapsed)
	}
	if err := c.ActivateNew(context.Background(), 1); err == nil {
		t.Fatal("mutator did not observe atomic fault latch")
	}
	if err := c.Prepare(context.Background(), lifecycleArtifact(t, "ordinary-integrity-newer", genTwoDNA)); err == nil {
		t.Fatal("ordinary in-process integrity latch bypassed verified-neutral recovery gate")
	}
	select {
	case active := <-programmed:
		if active != 0 {
			t.Fatalf("integrity reconciliation active = %d", active)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("new-SYN assignment was not asynchronously disabled")
	}
	<-statusDone
}

func sameProgram(a, b nftables.Config) bool {
	return nftables.New(a).Ruleset() == nftables.New(b).Ruleset()
}

func TestAmbiguousKernelCommitIsResolvedByExactReadback(t *testing.T) {
	ctx := context.Background()
	var installed nftables.Config
	ambiguous := false
	c := New(engine.NewRegistry(), Config{
		NoNFT: true,
		NFT:   nftables.Config{Port: 443},
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			installed = cfg
			if ambiguous && cfg.ActiveGeneration == 2 {
				return context.DeadlineExceeded // kernel committed before client timeout
			}
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("kernel does not contain desired transaction")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 2, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	ambiguous = true
	if err := c.ActivateNew(ctx, 2); err != nil {
		t.Fatalf("verified committed timeout was not reconciled: %v", err)
	}
	if got := c.State().ActiveNew; got != 2 {
		t.Fatalf("active generation = %d, want 2", got)
	}
}

func TestUnconfirmedKernelCompensationLatchesUnsafe(t *testing.T) {
	ctx := context.Background()
	var installed nftables.Config
	fail := false
	c := New(engine.NewRegistry(), Config{
		NoNFT: true,
		NFT:   nftables.Config{Port: 443},
		Program: func(_ context.Context, cfg nftables.Config, _ bool) error {
			if fail {
				installed = nftables.Config{Port: 443}
				return context.DeadlineExceeded
			}
			installed = cfg
			return nil
		},
		VerifyProgram: func(_ context.Context, want nftables.Config) error {
			if !sameProgram(installed, want) {
				return errors.New("unconfirmed kernel state")
			}
			return nil
		},
	}, nil)
	if err := c.Start(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 1, genOneDNA); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateNew(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := c.PrepareGeneration(ctx, 2, genTwoDNA); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := c.ActivateNew(ctx, 2); err == nil {
		t.Fatal("unconfirmed install and compensation succeeded")
	}
	st := c.State()
	if !st.Unsafe || st.ActiveNew != 0 {
		t.Fatalf("unconfirmed compensation state = %+v", st)
	}
	if err := c.PrepareGeneration(ctx, 3, genOneDNA); err == nil {
		t.Fatal("unsafe latch allowed a new mutation")
	}
}
