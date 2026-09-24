//go:build linux

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/steering"
)

const testDNA = `[TCP:flags:S]-drop-| \/`

type idleConnections struct{}

func (idleConnections) Count(context.Context, uint32, uint16) (int, error) { return 0, nil }
func (idleConnections) Counts(context.Context, uint16) (map[uint32]int, error) {
	return map[uint32]int{}, nil
}
func (idleConnections) Neutralize(context.Context, uint16) (int, error) { return 0, nil }

// withBuildVersion runs the process as if it had been built as build.
func withBuildVersion(t *testing.T, build string) {
	t.Helper()
	prev := version
	version = build
	t.Cleanup(func() { version = prev })
}

func newTestController(t *testing.T, stateFile string) *steering.Controller {
	t.Helper()
	cfg := steeringConfig(&runCmd{}, func(err error) { t.Errorf("fatal: %v", err) })
	cfg.NoNFT = true
	cfg.StateFile = stateFile
	cfg.Connections = idleConnections{}
	c := steering.New(engine.NewRegistry(), cfg, nil)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func engineArtifact(t *testing.T) adapter.Artifact {
	t.Helper()
	payload := []byte(testDNA)
	a, err := adapter.NewArtifact(adapter.ArtifactMetadata{
		Technique: adapter.TechniqueGeneva, Revision: "r1", Digest: adapter.Digest(payload), Size: len(payload),
		AdapterProtocol: adapter.Version1, RequiredRuntimeName: adapter.RuntimeNameGeneva,
		RequiredRuntimeVersion: adapter.RuntimeVersionGeneva, SchemaVersion: adapter.SchemaVersionV1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDescriptorRuntimeVersionIsEngineVersionRegardlessOfBuild(t *testing.T) {
	for _, build := range []string{"dev", "0.0.4", "0.0.5", "9.9.9-rc1"} {
		t.Run(build, func(t *testing.T) {
			withBuildVersion(t, build)
			c := newTestController(t, filepath.Join(t.TempDir(), "adapter.json"))
			if got := c.Descriptor().RuntimeVersion; got != adapter.RuntimeVersionGeneva {
				t.Fatalf("descriptor runtime_version = %q under build %q, want %q", got, build, adapter.RuntimeVersionGeneva)
			}
		})
	}
}

func TestEngineVersionArtifactPreparesUnderDifferentBuild(t *testing.T) {
	withBuildVersion(t, "0.0.5-different-build")
	ctx := context.Background()
	c := newTestController(t, filepath.Join(t.TempDir(), "adapter.json"))
	artifact := engineArtifact(t)
	if err := c.Prepare(ctx, artifact); err != nil {
		t.Fatalf("prepare artifact requiring %q: %v", adapter.RuntimeVersionGeneva, err)
	}
	if err := c.Verify(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := c.ActivateForNewConnections(ctx, artifact); err != nil {
		t.Fatal(err)
	}
}

func TestPersistedStateSurvivesBuildUpgradeWithSameEngineVersion(t *testing.T) {
	ctx := context.Background()
	state := filepath.Join(t.TempDir(), "adapter.json")
	artifact := engineArtifact(t)

	withBuildVersion(t, "0.0.4")
	before := newTestController(t, state)
	if err := before.Prepare(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := before.Verify(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if err := before.ActivateForNewConnections(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	active := before.State().ActiveNew

	version = "0.0.5"
	after := newTestController(t, state)
	st := after.State()
	if st.Unsafe || st.IntegrityFailure != "" || st.ActiveNew != active {
		t.Fatalf("restored state after build upgrade = %+v, want active generation %d", st, active)
	}
	quarantined, err := filepath.Glob(state + ".quarantine-*")
	if err != nil || len(quarantined) != 0 {
		t.Fatalf("quarantined state = %v, %v", quarantined, err)
	}
}
