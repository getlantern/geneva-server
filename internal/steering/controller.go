//go:build linux

package steering

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/geneva"

	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/generation"
	"github.com/getlantern/geneva-server/internal/netdev"
	"github.com/getlantern/geneva-server/internal/nftables"
)

type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// ConnectionCounter supplies authoritative conntrack drain counts.
type ConnectionCounter interface {
	Count(context.Context, uint32, uint16) (int, error)
	Counts(context.Context, uint16) (map[uint32]int, error)
	Neutralize(context.Context, uint16) (int, error)
}

type Config struct {
	Mode                      string
	NFT                       nftables.Config
	EthtoolPath               string
	Iface                     string
	NoNFT                     bool
	ObserveInbound            bool
	StateFile                 string
	Connections               ConnectionCounter
	MaxGenerations            int
	MaxScopedGenerations      int
	MaxEveryPacketGenerations int
	SyncDirectory             func(string) error
	SyncFile                  func(*os.File) error
	CaptureOffloads           func(context.Context, string, string) (*netdev.Original, error)
	DisableOffloads           func(context.Context, string, *netdev.Original) error
	RestoreOffloads           func(context.Context, string, *netdev.Original) error
	Fatal                     func(error)
	ConntrackTimeout          time.Duration
	RuntimeVersion            string
	// Program is a test seam for asserting lifecycle transaction ordering. A
	// production controller leaves it nil and invokes nft directly.
	Program       func(context.Context, nftables.Config, bool) error
	VerifyProgram func(context.Context, nftables.Config) error
}

const (
	defaultMaxGenerations            = 3
	defaultMaxScopedGenerations      = 3
	defaultMaxEveryPacketGenerations = 2
	maxGenerationArtifact            = 256 << 10
	persistedStateVersion            = 2
)

type stateCompatibilityError struct{ cause error }

func (e *stateCompatibilityError) Error() string {
	return fmt.Sprintf("persisted artifact compatibility check failed: %v", e.cause)
}

func (e *stateCompatibilityError) Unwrap() error { return e.cause }

type Phase string

const (
	PhasePrepared Phase = "prepared"
	PhaseActive   Phase = "active"
	PhaseDraining Phase = "draining"
	PhaseDrained  Phase = "drained"
)

type generationState struct {
	ID       uint32                   `json:"id"`
	DNA      string                   `json:"dna"`
	Digest   string                   `json:"digest"`
	Phase    Phase                    `json:"phase"`
	Scope    Scope                    `json:"-"`
	Identity adapter.Identity         `json:"identity"`
	Metadata adapter.ArtifactMetadata `json:"artifact_metadata"`
}

type GenerationStatus struct {
	ID            uint32           `json:"generation"`
	Digest        string           `json:"digest"`
	Phase         Phase            `json:"phase"`
	Connections   int              `json:"connections"`
	Outbound      string           `json:"outbound"`
	Inbound       string           `json:"inbound"`
	ResourceClass string           `json:"resource_class"`
	Identity      adapter.Identity `json:"identity"`
}

type State struct {
	Version          int                `json:"version"`
	Steering         bool               `json:"steering"`
	ActiveNew        uint32             `json:"active_new_generation,omitempty"`
	Previous         uint32             `json:"previous_generation,omitempty"`
	OffloadsDisabled bool               `json:"offloads_disabled"`
	Unsafe           bool               `json:"unsafe"`
	Remediation      bool               `json:"generic_remediation_allowed"`
	IntegrityFailure string             `json:"integrity_failure,omitempty"`
	Generations      []GenerationStatus `json:"generations"`
}

type persistedState struct {
	Version     int               `json:"version"`
	ActiveNew   uint32            `json:"active_new_generation,omitempty"`
	Previous    uint32            `json:"previous_generation,omitempty"`
	Unsafe      bool              `json:"unsafe"`
	Failure     string            `json:"integrity_failure,omitempty"`
	Offloads    *netdev.Original  `json:"offload_original,omitempty"`
	Generations []generationState `json:"generations"`
}

// Controller owns immutable engines, conntrack steering, durable state and NIC offloads.
type Controller struct {
	cfg          Config
	eng          *engine.Registry
	log          Logger
	mu           sync.Mutex
	generations  map[uint32]*generationState
	activeNew    uint32
	previous     uint32
	unsafe       bool
	failure      string
	nft          *nftables.Manager
	offloads     *netdev.Original
	faultLatched atomic.Bool
	persistFatal atomic.Bool
	// repairGuard lets a new hot-path integrity signal interrupt remediation
	// even though the original quarantine fault remains latched.
	repairGuard atomic.Bool
	remediation bool
	// reservedGenerations contains namespace IDs observed on orphaned live
	// conntracks. They cannot be reused until a later authoritative full dump
	// proves the ID has no flows.
	reservedGenerations map[uint32]struct{}
}

var _ adapter.Adapter = (*Controller)(nil)

func New(eng *engine.Registry, cfg Config, log Logger) *Controller {
	if log == nil {
		log = nopLogger{}
	}
	if cfg.MaxGenerations == 0 {
		cfg.MaxGenerations = defaultMaxGenerations
	}
	if cfg.MaxGenerations > int(adapter.MaxLiveGenerationBudget) {
		cfg.MaxGenerations = int(adapter.MaxLiveGenerationBudget)
	}
	if cfg.MaxScopedGenerations == 0 {
		cfg.MaxScopedGenerations = min(defaultMaxScopedGenerations, cfg.MaxGenerations)
	}
	if cfg.MaxEveryPacketGenerations == 0 {
		cfg.MaxEveryPacketGenerations = min(defaultMaxEveryPacketGenerations, cfg.MaxGenerations)
	}
	if cfg.ConntrackTimeout <= 0 {
		cfg.ConntrackTimeout = 5 * time.Second
	}
	if cfg.RuntimeVersion == "" {
		cfg.RuntimeVersion = "dev"
	}
	if cfg.CaptureOffloads == nil {
		cfg.CaptureOffloads = netdev.Capture
	}
	if cfg.DisableOffloads == nil {
		cfg.DisableOffloads = func(ctx context.Context, path string, original *netdev.Original) error {
			return original.Disable(ctx, path)
		}
	}
	if cfg.RestoreOffloads == nil {
		cfg.RestoreOffloads = func(ctx context.Context, path string, original *netdev.Original) error {
			return original.Restore(ctx, path)
		}
	}
	return &Controller{
		cfg: cfg, eng: eng, log: log,
		generations: make(map[uint32]*generationState), reservedGenerations: make(map[uint32]struct{}),
	}
}

// Start reconstructs durable engines before enabling any steering.
func (c *Controller) Start(ctx context.Context, initialDNA string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; only identity-checked rollback may repair it")
	}
	// Queue ownership is established by the caller before Start. Remove any
	// table left by a crashed predecessor before reading durable state or doing
	// a conntrack dump: reconstruction runs fail-open and no stale assignment
	// can create a generation whose safety has not yet been audited.
	if !c.cfg.NoNFT {
		removeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.removeRulesLocked(removeCtx)
		cancel()
		if err != nil {
			return fmt.Errorf("remove stale steering before reconstruction: %w", err)
		}
	}
	loaded, err := c.loadLocked()
	compatibilityUnsafe := false
	if err != nil {
		quarantined, quarantineErr := c.quarantineStateLocked()
		if quarantineErr != nil {
			return errors.Join(fmt.Errorf("load adapter state: %w", err), fmt.Errorf("quarantine adapter state: %w", quarantineErr))
		}
		// No engine or assignment from corrupt/incompatible durable intent is
		// loaded. The original bytes remain in a durably renamed quarantine file,
		// and the new state records the unsafe remediation requirement.
		compatibilityUnsafe = true
		loaded = false
		c.unsafe, c.activeNew = true, 0
		c.faultLatched.Store(true)
		c.failure = fmt.Sprintf("adapter state quarantined at %s: %v", quarantined, err)
	}
	legacyInitial := uint32(0)
	if !loaded && !compatibilityUnsafe && initialDNA != "" {
		if err := c.prepareLocked(1, legacyIdentity(1, initialDNA), initialDNA); err != nil {
			return err
		}
		legacyInitial = 1
	}
	conntrackAuthoritative := false
	if c.cfg.Connections != nil {
		counts, countErr := c.connectionCounts(ctx)
		if countErr != nil {
			c.unsafe, c.activeNew = true, 0
			c.faultLatched.Store(true)
			c.appendFailureLocked(fmt.Sprintf("bounded startup conntrack audit failed: %v", countErr))
			for _, gen := range c.generations {
				if gen.Phase == PhaseActive {
					gen.Phase = PhaseDraining
				}
			}
			counts = nil
		} else {
			conntrackAuthoritative = true
		}
		c.reconcileReservedGenerationsLocked(counts)
		if !loaded {
			n := 0
			for _, count := range counts {
				n += count
			}
			if n != 0 {
				c.unsafe, c.activeNew = true, 0
				c.appendFailureLocked(fmt.Sprintf("%d orphaned Geneva-marked flows without durable engine state", n))
				for _, gen := range c.generations {
					gen.Phase = PhasePrepared
				}
			}
		} else {
			orphaned := 0
			for id, count := range counts {
				if c.generations[id] == nil {
					orphaned += count
				}
			}
			if orphaned != 0 {
				c.unsafe, c.activeNew = true, 0
				c.appendFailureLocked(fmt.Sprintf("%d orphaned Geneva-marked flows have no reconstructed engine", orphaned))
			}
		}
	}
	if c.unsafe {
		c.remediation = false
		c.faultLatched.Store(true)
		if c.activeNew != 0 && c.generations[c.activeNew] != nil {
			c.generations[c.activeNew].Phase = PhaseDraining
		}
		c.activeNew = 0
	}
	c.repairGuard.Store(false)
	// Persist reconstructable intent before any rule can assign or queue a
	// generation. This also records an orphan audit's unsafe state before the
	// table is replaced.
	if err := c.persistLocked(); err != nil {
		return err
	}
	steering := c.hasSteeringLocked()
	if steering {
		if err := c.ensureOffloadsDown(ctx); err != nil {
			return err
		}
	}
	// A durable active identity is desired state, not proof that the previous
	// process completed its neutral boundary. Every restart therefore rebuilds
	// active assignment through that boundary. Already marked generations keep
	// their union rules throughout; only unowned/pre-existing flows are neutral.
	if loaded && c.activeNew != 0 && !c.unsafe {
		if err := c.restoreActiveAfterRestartLocked(ctx); err != nil {
			return err
		}
		return nil
	}
	if err := c.programLocked(ctx, c.liveLocked(), c.activeNew, true); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		removeErr := c.removeRulesLocked(recoveryCtx)
		var restoreErr error
		if removeErr == nil {
			restoreErr = c.restoreOffloads(recoveryCtx)
		}
		return errors.Join(err, removeErr, restoreErr)
	}
	// This proof is deliberately process-local. A restart must repeat the exact
	// kernel readback and bounded conntrack snapshot before generic remediation.
	if c.unsafe && conntrackAuthoritative && c.cfg.StateFile != "" && !c.persistFatal.Load() {
		if err := c.verifyCurrentProgramLocked(ctx); err == nil {
			c.remediation = true
			c.repairGuard.Store(true)
		} else {
			c.appendFailureLocked(fmt.Sprintf("verified-neutral recovery gate failed: %v", err))
		}
	}
	if !steering && c.offloads != nil {
		if err := c.restoreOffloads(ctx); err != nil {
			return err
		}
	}
	if legacyInitial != 0 && !c.unsafe {
		// The explicitly requested compatibility seed uses the same exact first-
		// activation boundary as the versioned API. It may not capture a SYN
		// conntrack which existed before process startup.
		return c.activateLocked(ctx, legacyInitial, false)
	}
	if c.activeNew != 0 {
		if err := c.eng.Activate(c.activeNew); err != nil {
			removeErr := c.removeRulesLocked(ctx)
			var restoreErr error
			if removeErr == nil {
				restoreErr = c.restoreOffloads(ctx)
			}
			return errors.Join(err, removeErr, restoreErr)
		}
	} else {
		c.eng.Deactivate()
	}
	return nil
}

func (c *Controller) restoreActiveAfterRestartLocked(ctx context.Context) error {
	if c.cfg.Connections == nil {
		return errors.New("cannot restore active generation without conntrack neutralization")
	}
	active := c.activeNew
	live := c.liveLocked()
	if err := c.programModeLocked(ctx, live, 0, true, true); err != nil {
		return fmt.Errorf("install restart neutral boundary: %w", err)
	}
	if _, err := c.neutralizeConnections(ctx); err != nil {
		return fmt.Errorf("neutralize conntracks during active restart: %w", err)
	}
	if err := c.programLocked(ctx, live, active, false); err != nil {
		return fmt.Errorf("restore restart active assignment: %w", err)
	}
	if err := c.eng.Activate(active); err != nil {
		return err
	}
	c.log.Infof("restored active generation %d through neutral restart boundary", active)
	return nil
}

// Prepare is the legacy compatibility path. Versioned callers use
// PrepareDeployment with a complete immutable identity.
func (c *Controller) PrepareGeneration(ctx context.Context, id uint32, dna string) error {
	return c.prepare(ctx, id, legacyIdentity(id, dna), dna)
}

func (c *Controller) prepare(ctx context.Context, id uint32, identity adapter.Identity, dna string) error {
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; only identity-checked rollback may repair it")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := generation.Mark(id); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	if existingID, existing, err := c.generationForIdentityLocked(identity); err != nil {
		return err
	} else if existing != nil && existingID != id {
		return fmt.Errorf("artifact identity is already mapped to generation %d", existingID)
	}
	if old := c.generations[id]; old != nil {
		if old.DNA == dna && old.Identity == identity {
			return nil
		}
		return fmt.Errorf("generation %d is immutable", id)
	}
	if len(c.generations) >= c.cfg.MaxGenerations {
		return fmt.Errorf("live generation budget is full (%d); drain and garbage-collect one before prepare", c.cfg.MaxGenerations)
	}
	if err := c.prepareLocked(id, identity, dna); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	if err := c.validateResourceBudgetsLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	if err := c.persistLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	return nil
}

// Apply preserves the legacy PUT /strategy behavior using the generation
// lifecycle. It never mutates an engine or resets a connection.
func (c *Controller) Apply(ctx context.Context, dna string) error {
	if dna == "" {
		return c.DeactivateNew(ctx)
	}
	c.mu.Lock()
	id := c.nextGenerationLocked()
	c.mu.Unlock()
	if id == 0 {
		return errors.New("all generation IDs are in use; drain and garbage-collect an old generation")
	}
	if err := c.PrepareGeneration(ctx, id, dna); err != nil {
		return err
	}
	return c.ActivateNew(ctx, id)
}

func (c *Controller) prepareLocked(id uint32, identity adapter.Identity, dna string) error {
	descriptor := c.Descriptor()
	return c.prepareArtifactLocked(id, adapter.ArtifactMetadata{
		Technique: identity.Technique, Revision: identity.Revision, Digest: identity.Digest, Size: len([]byte(dna)),
		AdapterProtocol: descriptor.AdapterProtocol, RequiredRuntimeName: descriptor.RuntimeName,
		RequiredRuntimeVersion: descriptor.RuntimeVersion, SchemaVersion: adapter.SchemaVersionV1,
	}, dna)
}

func (c *Controller) prepareArtifactLocked(id uint32, metadata adapter.ArtifactMetadata, dna string) error {
	if len([]byte(dna)) > maxGenerationArtifact {
		return fmt.Errorf("%w: artifact exceeds 256 KiB", engine.ErrInvalidStrategy)
	}
	artifact, err := adapter.NewArtifact(metadata, []byte(dna))
	if err != nil {
		return fmt.Errorf("%w: artifact metadata: %v", engine.ErrInvalidStrategy, err)
	}
	if err := artifact.ValidateFor(c.Descriptor()); err != nil {
		return fmt.Errorf("%w: artifact compatibility: %v", engine.ErrInvalidStrategy, err)
	}
	parsed, err := geneva.NewStrategy(dna)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", engine.ErrInvalidStrategy, err)
	}
	if err := geneva.Validate(parsed); err != nil {
		return fmt.Errorf("%w: validate: %w", engine.ErrInvalidStrategy, err)
	}
	if err := c.eng.Prepare(id, dna); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(dna))
	digest := hex.EncodeToString(sum[:])
	identity := artifact.Identity()
	if err := validateIdentity(identity, digest); err != nil {
		_ = c.eng.Remove(id)
		return err
	}
	c.generations[id] = &generationState{
		ID: id, DNA: dna, Digest: digest, Identity: identity, Metadata: metadata,
		Phase: PhasePrepared, Scope: c.widen(Of(parsed)),
	}
	return nil
}

func legacyIdentity(id uint32, dna string) adapter.Identity {
	sum := sha256.Sum256([]byte(dna))
	return adapter.Identity{Technique: adapter.TechniqueGeneva, Revision: fmt.Sprintf("legacy-%d", id), Digest: hex.EncodeToString(sum[:])}
}

func validateIdentity(identity adapter.Identity, artifactDigest string) error {
	if identity.Technique != adapter.TechniqueGeneva {
		return fmt.Errorf("technique %q is not supported", identity.Technique)
	}
	if identity.Revision == "" {
		return errors.New("revision is required")
	}
	decoded, err := hex.DecodeString(identity.Digest)
	if err != nil || len(decoded) != sha256.Size || identity.Digest != strings.ToLower(identity.Digest) {
		return errors.New("digest must be bare lowercase 64-character SHA-256 hex")
	}
	if identity.Digest != artifactDigest {
		return errors.New("artifact digest does not match immutable identity")
	}
	return nil
}

func (c *Controller) Descriptor() adapter.Descriptor {
	return adapter.Descriptor{
		AdapterProtocol: adapter.Version1, Technique: adapter.TechniqueGeneva,
		RuntimeName: adapter.RuntimeNameGeneva, RuntimeVersion: c.cfg.RuntimeVersion,
		SchemaVersions: []uint32{adapter.SchemaVersionV1}, MaxLiveGenerations: uint32(c.cfg.MaxGenerations),
	}
}

func (c *Controller) verifyArtifact(ctx context.Context, identity adapter.Identity, dna string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(dna) > adapter.MaxArtifactSize {
		return fmt.Errorf("%w: artifact exceeds 256 KiB", engine.ErrInvalidStrategy)
	}
	sum := sha256.Sum256([]byte(dna))
	if err := validateIdentity(identity, hex.EncodeToString(sum[:])); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	parsed, err := geneva.NewStrategy(dna)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", engine.ErrInvalidStrategy, err)
	}
	if err := geneva.Validate(parsed); err != nil {
		return fmt.Errorf("%w: validate: %w", engine.ErrInvalidStrategy, err)
	}
	return nil
}

func (c *Controller) PrepareDeployment(ctx context.Context, deployment adapter.Deployment, dna string) error {
	return c.prepare(ctx, deployment.Generation, deployment.Identity, dna)
}

// Prepare implements the generic identity-based adapter contract. The
// numeric conntrack generation is a private durable mapping owned here.
func (c *Controller) Prepare(ctx context.Context, artifact adapter.Artifact) error {
	if err := artifact.ValidateFor(c.Descriptor()); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	dna := string(artifact.Payload())
	if err := c.verifyArtifact(ctx, artifact.Identity(), dna); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	recovery := c.faultLatched.Load()
	if recovery {
		if !c.remediation || !c.repairGuard.Load() || c.activeNew != 0 || c.persistFatal.Load() {
			return errors.New("adapter integrity fault is latched")
		}
		// Re-prove the process-local neutral gate on every recovery Prepare.
		// Both operations are read-only; failure leaves engine, nft, and durable
		// state untouched so t8 can retry the same newer snapshot.
		if err := c.verifyCurrentProgramLocked(ctx); err != nil {
			return fmt.Errorf("verify neutral steering before recovery prepare: %w", err)
		}
		counts, err := c.connectionCounts(ctx)
		if err != nil {
			return fmt.Errorf("snapshot conntracks before recovery prepare: %w", err)
		}
		c.reconcileReservedGenerationsLocked(counts)
	}
	if id, gen, err := c.generationForIdentityLocked(artifact.Identity()); err != nil {
		return err
	} else if gen != nil {
		if gen.DNA != dna || gen.Metadata != artifact.Metadata() {
			return fmt.Errorf("artifact identity is already mapped to generation %d with different immutable artifact metadata or content", id)
		}
		return nil
	}
	if len(c.generations) >= c.cfg.MaxGenerations {
		return fmt.Errorf("live generation budget is full (%d); drain and garbage-collect one before prepare", c.cfg.MaxGenerations)
	}
	id := c.nextGenerationLocked()
	if id == 0 {
		return errors.New("no private generation ID is available")
	}
	if err := c.prepareArtifactLocked(id, artifact.Metadata(), dna); err != nil {
		return err
	}
	if err := c.validateResourceBudgetsLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	if err := c.persistLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	return nil
}

func (c *Controller) Verify(ctx context.Context, artifact adapter.Artifact) error {
	if err := artifact.ValidateFor(c.Descriptor()); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	if err := c.verifyArtifact(ctx, artifact.Identity(), string(artifact.Payload())); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, gen, err := c.generationForIdentityLocked(artifact.Identity())
	if err != nil {
		return err
	}
	if gen == nil || gen.DNA != string(artifact.Payload()) || gen.Metadata != artifact.Metadata() {
		return errors.New("artifact has not been prepared")
	}
	return nil
}

func (c *Controller) ActivateForNewConnections(ctx context.Context, artifact adapter.Artifact) error {
	if err := artifact.ValidateFor(c.Descriptor()); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	remediation := c.faultLatched.Load() && c.remediation && c.repairGuard.Load() && c.activeNew == 0 && !c.persistFatal.Load()
	if c.faultLatched.Load() && !remediation {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	id, gen, err := c.generationForIdentityLocked(artifact.Identity())
	if err != nil {
		return err
	}
	if gen == nil || gen.DNA != string(artifact.Payload()) || gen.Metadata != artifact.Metadata() {
		return errors.New("artifact has not been prepared")
	}
	if c.activeNew == id {
		return nil
	}
	if remediation {
		if err := c.verifyCurrentProgramLocked(ctx); err != nil {
			return fmt.Errorf("verify neutral steering before recovery activation: %w", err)
		}
	}
	return c.activateLocked(ctx, id, remediation)
}

func (c *Controller) DeactivateForNewConnections(ctx context.Context, identity adapter.ArtifactIdentity) error {
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeNew == 0 {
		return nil
	}
	active := c.generations[c.activeNew]
	if active == nil || active.Identity != identity {
		return nil // identity-fenced stale retry
	}
	return c.deactivateLocked(ctx)
}

func (c *Controller) Rollback(ctx context.Context, artifact adapter.Artifact) error {
	if c.persistFatal.Load() {
		return errors.New("adapter durability failure requires process restart")
	}
	if err := artifact.ValidateFor(c.Descriptor()); err != nil {
		return fmt.Errorf("%w: %v", engine.ErrInvalidStrategy, err)
	}
	c.mu.Lock()
	id, gen, err := c.generationForIdentityLocked(artifact.Identity())
	if err != nil {
		c.mu.Unlock()
		return err
	}
	dna := string(artifact.Payload())
	if gen != nil {
		defer c.mu.Unlock()
		if gen.DNA != dna || gen.Metadata != artifact.Metadata() {
			return errors.New("rollback artifact identity is retained with different content")
		}
		return c.activateLocked(ctx, id, true)
	}
	if len(c.generations) >= c.cfg.MaxGenerations {
		c.mu.Unlock()
		return fmt.Errorf("live generation budget is full (%d); cannot restore rollback artifact", c.cfg.MaxGenerations)
	}
	c.mu.Unlock()

	// An absent rollback artifact needs a new private numeric mapping. A full,
	// bounded namespace snapshot is the authority that the chosen ID has zero
	// flows; in-memory state alone cannot see orphan marks left by lost state.
	counts, err := c.connectionCounts(ctx)
	if err != nil {
		cause := fmt.Errorf("cannot prove a zero-flow generation for rollback: %w", err)
		c.mu.Lock()
		c.faultLatched.Store(true)
		c.repairGuard.Store(false)
		c.unsafe, c.remediation = true, false
		c.appendFailureLocked(cause.Error())
		active := c.activeNew
		if active != 0 {
			failureCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			c.integrityFailureLocked(failureCtx, cause)
			cancel()
		}
		c.mu.Unlock()
		return cause
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Another idempotent caller may have completed the preparation while the
	// conntrack dump was in flight.
	id, gen, err = c.generationForIdentityLocked(artifact.Identity())
	if err != nil {
		return err
	}
	if gen != nil {
		if gen.DNA != dna || gen.Metadata != artifact.Metadata() {
			return errors.New("rollback artifact identity is retained with different content")
		}
		return c.activateLocked(ctx, id, true)
	}
	if len(c.generations) >= c.cfg.MaxGenerations {
		return fmt.Errorf("live generation budget is full (%d); cannot restore rollback artifact", c.cfg.MaxGenerations)
	}
	c.reconcileReservedGenerationsLocked(counts)
	id = c.nextGenerationLocked()
	if id == 0 {
		return errors.New("no proven-zero private generation ID is available for rollback")
	}
	if err := c.prepareArtifactLocked(id, artifact.Metadata(), dna); err != nil {
		return err
	}
	if err := c.validateResourceBudgetsLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	if err := c.persistLocked(); err != nil {
		delete(c.generations, id)
		_ = c.eng.Remove(id)
		return err
	}
	return c.activateLocked(ctx, id, true)
}

func (c *Controller) generationForIdentityLocked(identity adapter.ArtifactIdentity) (uint32, *generationState, error) {
	var foundID uint32
	var found *generationState
	for id, gen := range c.generations {
		if gen.Identity != identity {
			continue
		}
		if found != nil {
			return 0, nil, fmt.Errorf("artifact identity is ambiguously mapped to generations %d and %d", foundID, id)
		}
		foundID, found = id, gen
	}
	return foundID, found, nil
}

func (c *Controller) ActivateDeployment(ctx context.Context, target adapter.Deployment, expected adapter.Deployment) error {
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	if c.matchesLocked(target) && c.activeNew == target.Generation {
		return nil
	}
	if !c.activeMatchesLocked(expected) {
		return fmt.Errorf("active deployment precondition does not match")
	}
	if !c.matchesLocked(target) {
		return fmt.Errorf("target deployment identity does not match prepared generation")
	}
	return c.activateLocked(ctx, target.Generation, false)
}

func (c *Controller) matchesLocked(deployment adapter.Deployment) bool {
	gen := c.generations[deployment.Generation]
	return gen != nil && gen.Identity == deployment.Identity
}

func (c *Controller) activeMatchesLocked(expected adapter.Deployment) bool {
	if expected.Generation == 0 {
		return c.activeNew == 0
	}
	return c.activeNew == expected.Generation && c.matchesLocked(expected)
}

// ActivateNew stages and verifies union rules before atomically flipping SYN assignment.
func (c *Controller) ActivateNew(ctx context.Context, id uint32) error {
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	if c.unsafe {
		return fmt.Errorf("adapter is unsafe after integrity failure; rollback required: %s", c.failure)
	}
	return c.activateLocked(ctx, id, false)
}

func (c *Controller) activateLocked(ctx context.Context, id uint32, repair bool) error {
	target := c.generations[id]
	if target == nil {
		return fmt.Errorf("generation %d is not prepared", id)
	}
	if target.Scope.Idle() {
		return fmt.Errorf("generation %d has an empty steering scope; use deactivate-new", id)
	}
	hadSteering := c.hasSteeringLocked()
	oldActive, oldPrevious := c.activeNew, c.previous
	oldUnsafe, oldFailure := c.unsafe, c.failure
	oldRemediation := c.remediation
	oldRepairGuard := c.repairGuard.Load()
	oldPhases := c.phasesLocked()
	restoreState := func() {
		fatalFailure := c.failure
		c.restoreLocked(oldActive, oldPrevious, oldUnsafe, oldFailure, oldRemediation, oldPhases)
		if !oldRepairGuard {
			c.repairGuard.Store(false)
		}
		if c.persistFatal.Load() {
			c.unsafe, c.remediation, c.failure = true, false, fatalFailure
			c.faultLatched.Store(true)
			c.repairGuard.Store(false)
		}
	}
	if oldActive != 0 && oldActive != id {
		c.generations[oldActive].Phase, c.previous = PhaseDraining, oldActive
	}
	target.Phase, c.activeNew = PhaseActive, id
	if repair {
		// A distinct integrity signal during repair consumes this guard and
		// prevents the old quarantine latch from being cleared on success.
		if !oldRemediation {
			c.repairGuard.Store(true)
		}
		c.unsafe, c.failure = false, ""
		c.remediation = false
	}
	// Durable intent comes first: after a crash every mark either transaction can
	// assign still has a reconstructable engine.
	if err := c.persistLocked(); err != nil {
		restoreState()
		return err
	}
	if !target.Scope.Idle() {
		if err := c.ensureOffloadsDown(ctx); err != nil {
			restoreState()
			if persistErr := c.persistLocked(); persistErr != nil {
				failure := errors.Join(err, fmt.Errorf("persist offload compensation: %w", persistErr))
				c.integrityFailureLocked(ctx, failure)
				return failure
			}
			return err
		}
	}
	live := c.liveLocked()
	// Transaction one adds the candidate's rules while assignment remains old.
	// On the first activation it instead assigns neutral generation zero so no
	// SYN arriving during the conntrack sweep can cross the boundary.
	neutralBoundary := oldActive == 0
	if err := c.programModeLocked(ctx, live, oldActive, neutralBoundary, true); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		restoreState()
		recoveryErr := errors.Join(
			c.programLocked(recoveryCtx, c.liveLocked(), oldActive, false),
			c.persistLocked(),
		)
		if !hadSteering {
			recoveryErr = errors.Join(recoveryErr, c.restoreOffloads(recoveryCtx))
		}
		if recoveryErr != nil {
			failure := errors.Join(err, fmt.Errorf("activation compensation failed: %w", recoveryErr))
			c.integrityFailureLocked(recoveryCtx, failure)
			return failure
		}
		return err
	}
	if neutralBoundary && c.cfg.Connections != nil {
		if _, err := c.neutralizeConnections(ctx); err != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			restoreState()
			recoveryErr := errors.Join(
				c.programLocked(recoveryCtx, c.liveLocked(), oldActive, false),
				c.persistLocked(),
			)
			if recoveryErr != nil {
				failure := errors.Join(err, fmt.Errorf("neutral-boundary compensation failed: %w", recoveryErr))
				c.integrityFailureLocked(recoveryCtx, failure)
				return failure
			}
			return fmt.Errorf("neutralize pre-activation conntracks: %w", err)
		}
	}
	// Transaction two changes only which mark new SYNs receive.
	if err := c.programLocked(ctx, live, id, false); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		restoreState()
		recoveryErr := errors.Join(
			c.programLocked(recoveryCtx, c.liveLocked(), oldActive, false),
			c.persistLocked(),
		)
		if !hadSteering {
			recoveryErr = errors.Join(recoveryErr, c.restoreOffloads(recoveryCtx))
		}
		if recoveryErr != nil {
			failure := errors.Join(err, fmt.Errorf("activation compensation failed: %w", recoveryErr))
			c.integrityFailureLocked(recoveryCtx, failure)
			return failure
		}
		return err
	}
	if err := c.eng.Activate(id); err != nil {
		c.integrityFailureLocked(ctx, err)
		return err
	}
	if repair {
		c.faultLatched.Store(false)
		if !c.repairGuard.CompareAndSwap(true, false) {
			// IntegrityFailure consumed the repair guard and queued fail-closed
			// reconciliation while this lifecycle operation held the mutex.
			c.faultLatched.Store(true)
			return errors.New("integrity failure interrupted lifecycle remediation")
		}
	}
	c.log.Infof("new connections activated on generation %d", id)
	return nil
}

func (c *Controller) DeactivateNew(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deactivateLocked(ctx)
}

func (c *Controller) DeactivateDeployment(ctx context.Context, expected adapter.Deployment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeNew == 0 {
		return nil
	}
	if !c.activeMatchesLocked(expected) {
		return errors.New("active deployment precondition does not match; no change made")
	}
	return c.deactivateLocked(ctx)
}

func (c *Controller) deactivateLocked(ctx context.Context) error {
	old := c.activeNew
	oldPrevious := c.previous
	if old == 0 {
		return nil
	}
	c.generations[old].Phase, c.previous, c.activeNew = PhaseDraining, old, 0
	if err := c.persistLocked(); err != nil {
		c.generations[old].Phase, c.previous, c.activeNew = PhaseActive, oldPrevious, old
		return err
	}
	if err := c.programLocked(ctx, c.liveLocked(), 0, true); err != nil {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.generations[old].Phase, c.previous, c.activeNew = PhaseActive, oldPrevious, old
		recoveryErr := errors.Join(
			c.programLocked(recoveryCtx, c.liveLocked(), old, false),
			c.persistLocked(),
		)
		if recoveryErr != nil {
			failure := errors.Join(err, fmt.Errorf("deactivation compensation failed: %w", recoveryErr))
			c.integrityFailureLocked(recoveryCtx, failure)
			return failure
		}
		return err
	}
	c.eng.Deactivate()
	return nil
}

// Rollback changes only new SYN assignment; existing conntrack marks are untouched.
func (c *Controller) RollbackGeneration(ctx context.Context, id uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id == 0 {
		id = c.previous
	}
	if id == 0 {
		return errors.New("no previous generation available for rollback")
	}
	return c.activateLocked(ctx, id, true)
}

func (c *Controller) RollbackDeployment(ctx context.Context, target, expected adapter.Deployment) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.activeNew == target.Generation && c.matchesLocked(target) {
		return nil
	}
	if !c.activeMatchesLocked(expected) {
		return errors.New("active deployment precondition does not match; no change made")
	}
	if !c.matchesLocked(target) {
		return errors.New("rollback target identity does not match retained generation")
	}
	return c.activateLocked(ctx, target.Generation, true)
}

func (c *Controller) DrainGeneration(ctx context.Context, id uint32) (int, error) {
	c.mu.Lock()
	gen := c.generations[id]
	if gen == nil {
		c.mu.Unlock()
		return 0, fmt.Errorf("generation %d is not prepared", id)
	}
	if c.activeNew == id {
		c.mu.Unlock()
		return 0, fmt.Errorf("generation %d still accepts new connections", id)
	}
	identity := gen.Identity
	c.mu.Unlock()
	n, err := c.connectionCount(ctx, id)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	gen = c.generations[id]
	if gen == nil || gen.Identity != identity || c.activeNew == id {
		return 0, errors.New("generation changed while drain count was in progress")
	}
	if n == 0 {
		gen.Phase = PhaseDrained
		if err := c.persistLocked(); err != nil {
			return 0, err
		}
	} else {
		gen.Phase = PhaseDraining
	}
	return n, nil
}

func (c *Controller) DrainDeployment(ctx context.Context, deployment adapter.Deployment) (int, error) {
	c.mu.Lock()
	if !c.matchesLocked(deployment) {
		c.mu.Unlock()
		return 0, errors.New("drain deployment identity does not match")
	}
	c.mu.Unlock()
	return c.DrainGeneration(ctx, deployment.Generation)
}

func (c *Controller) Drain(ctx context.Context, identity adapter.ArtifactIdentity) (adapter.DrainResult, error) {
	c.mu.Lock()
	id, gen, err := c.generationForIdentityLocked(identity)
	if err != nil {
		c.mu.Unlock()
		return adapter.DrainResult{}, err
	}
	if gen == nil {
		c.mu.Unlock()
		return adapter.DrainResult{Complete: true}, nil
	}
	c.mu.Unlock()
	n, err := c.DrainGeneration(ctx, id)
	if err != nil {
		return adapter.DrainResult{}, err
	}
	return adapter.DrainResult{Complete: n == 0, RemainingConnections: uint64(n)}, nil
}

// GarbageCollect removes kernel rules before the engine and only at zero flows.
func (c *Controller) GarbageCollectGeneration(ctx context.Context, id uint32) error {
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	c.mu.Lock()
	gen := c.generations[id]
	if gen == nil {
		c.mu.Unlock()
		return fmt.Errorf("generation %d is not prepared", id)
	}
	if c.activeNew == id {
		c.mu.Unlock()
		return fmt.Errorf("generation %d still accepts new connections", id)
	}
	identity := gen.Identity
	c.mu.Unlock()
	n, err := c.connectionCount(ctx, id)
	if err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("generation %d still has %d connections", id, n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.faultLatched.Load() {
		return errors.New("adapter integrity fault is latched; rollback is required")
	}
	gen = c.generations[id]
	if gen == nil || gen.Identity != identity || c.activeNew == id {
		return errors.New("generation changed while garbage-collection count was in progress")
	}
	delete(c.generations, id)
	oldPrevious := c.previous
	if c.previous == id {
		c.previous = 0
	}
	if err := c.programLocked(ctx, c.liveLocked(), c.activeNew, true); err != nil {
		c.generations[id] = gen
		c.previous = oldPrevious
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		recoveryErr := c.programLocked(recoveryCtx, c.liveLocked(), c.activeNew, false)
		if recoveryErr != nil {
			failure := errors.Join(err, fmt.Errorf("GC compensation failed: %w", recoveryErr))
			c.integrityFailureLocked(recoveryCtx, failure)
			return failure
		}
		return err
	}
	if err := c.eng.Remove(id); err != nil {
		c.generations[id] = gen
		c.previous = oldPrevious
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		recoveryErr := c.programLocked(recoveryCtx, c.liveLocked(), c.activeNew, false)
		if recoveryErr != nil {
			failure := errors.Join(err, fmt.Errorf("engine-removal compensation failed: %w", recoveryErr))
			c.integrityFailureLocked(recoveryCtx, failure)
			return failure
		}
		return err
	}
	if !c.hasSteeringLocked() {
		if err := c.restoreOffloads(ctx); err != nil {
			return err
		}
	}
	return c.persistLocked()
}

func (c *Controller) GarbageCollect(ctx context.Context, keep []adapter.ArtifactIdentity) error {
	keepSet := make(map[adapter.ArtifactIdentity]bool, len(keep))
	for _, identity := range keep {
		keepSet[identity] = true
	}
	c.mu.Lock()
	candidates := make([]adapter.Deployment, 0, len(c.generations))
	for id, gen := range c.generations {
		if keepSet[gen.Identity] || id == c.activeNew || gen.Phase == PhaseDraining {
			continue
		}
		candidates = append(candidates, adapter.Deployment{Generation: id, Identity: gen.Identity})
	}
	c.mu.Unlock()
	for _, deployment := range candidates {
		c.mu.Lock()
		matches := c.matchesLocked(deployment)
		c.mu.Unlock()
		if !matches {
			return fmt.Errorf("generation %d identity changed during GC", deployment.Generation)
		}
		if err := c.GarbageCollectGeneration(ctx, deployment.Generation); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) connectionCount(ctx context.Context, id uint32) (int, error) {
	if c.cfg.Connections == nil {
		return 0, errors.New("conntrack drain counter is not configured")
	}
	type result struct {
		count int
		err   error
	}
	bounded, cancel := context.WithTimeout(ctx, c.cfg.ConntrackTimeout)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		n, err := c.cfg.Connections.Count(bounded, id, c.cfg.NFT.Port)
		done <- result{count: n, err: err}
	}()
	select {
	case r := <-done:
		return r.count, r.err
	case <-bounded.Done():
		return 0, bounded.Err()
	}
}

// IntegrityFailure makes the hot-path callback non-blocking while disabling new assignment.
func (c *Controller) IntegrityFailure(err error) {
	newFault := c.faultLatched.CompareAndSwap(false, true)
	interruptedRepair := c.repairGuard.CompareAndSwap(true, false)
	if !newFault && !interruptedRepair {
		return
	}
	go func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c.integrityFailureLocked(ctx, err)
	}()
}

func (c *Controller) integrityFailureLocked(ctx context.Context, cause error) {
	c.faultLatched.Store(true)
	c.repairGuard.Store(false)
	c.unsafe, c.remediation, c.failure = true, false, cause.Error()
	if c.activeNew != 0 && c.generations[c.activeNew] != nil {
		c.generations[c.activeNew].Phase = PhaseDraining
	}
	c.activeNew = 0
	c.eng.Deactivate()
	if err := c.programLocked(ctx, c.liveLocked(), 0, false); err != nil {
		cause = errors.Join(cause, fmt.Errorf("disable new assignment: %w", err))
		if removeErr := c.removeRulesLocked(ctx); removeErr != nil {
			cause = errors.Join(cause, fmt.Errorf("remove unsafe steering: %w", removeErr))
			if c.cfg.Fatal != nil {
				go c.cfg.Fatal(cause)
			}
		}
	}
	c.failure = cause.Error()
	if err := c.persistLocked(); err != nil {
		c.failure = errors.Join(cause, fmt.Errorf("persist integrity failure: %w", err)).Error()
		if c.cfg.Fatal != nil {
			go c.cfg.Fatal(errors.New(c.failure))
		}
	}
	c.log.Errorf("unsafe new steering disabled: %v", cause)
}

func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stateLocked()
}

func (c *Controller) stateLocked() State {
	out := State{Version: persistedStateVersion, ActiveNew: c.activeNew, Previous: c.previous, OffloadsDisabled: c.offloads != nil, Unsafe: c.unsafe || c.faultLatched.Load(), Remediation: c.remediation, IntegrityFailure: c.failure, Generations: make([]GenerationStatus, 0, len(c.generations))}
	for _, g := range c.generations {
		out.Generations = append(out.Generations, GenerationStatus{ID: g.ID, Digest: g.Digest, Identity: g.Identity, Phase: g.Phase, Outbound: describe(g.Scope.Outbound), Inbound: describe(g.Scope.Inbound), ResourceClass: resourceClass(g.Scope)})
		if (g.Phase == PhaseActive || g.Phase == PhaseDraining) && !g.Scope.Idle() {
			out.Steering = true
		}
	}
	sort.Slice(out.Generations, func(i, j int) bool { return out.Generations[i].ID < out.Generations[j].ID })
	return out
}

// Status adds one bounded, authoritative conntrack snapshot to lifecycle state.
// Health uses State instead so routine probes never dump conntrack.
func (c *Controller) DetailedStatus(ctx context.Context) (State, error) {
	c.mu.Lock()
	before := c.stateLocked()
	c.mu.Unlock()
	if c.cfg.Connections == nil {
		return State{}, errors.New("conntrack status counter is not configured")
	}
	counts, err := c.connectionCounts(ctx)
	if err != nil {
		return State{}, err
	}
	c.mu.Lock()
	out := c.stateLocked()
	c.mu.Unlock()
	if !sameStatusGenerationView(before, out) {
		return State{}, errors.New("adapter generations changed while conntrack status was in progress; retry status")
	}
	for i := range out.Generations {
		phase := out.Generations[i].Phase
		if phase == PhaseActive || phase == PhaseDraining {
			out.Generations[i].Connections = counts[out.Generations[i].ID]
		}
	}
	return out, nil
}

func (c *Controller) Status(ctx context.Context) (adapter.Status, error) {
	detailed, err := c.DetailedStatus(ctx)
	if err != nil {
		return adapter.Status{}, err
	}
	out := adapter.Status{Prepared: make([]adapter.ArtifactIdentity, 0, len(detailed.Generations))}
	for _, gen := range detailed.Generations {
		out.Prepared = append(out.Prepared, gen.Identity)
		if gen.ID == detailed.ActiveNew {
			identity := gen.Identity
			out.Active = &identity
		}
		if gen.Phase == PhaseDraining {
			out.Draining = append(out.Draining, adapter.DrainGeneration{
				Identity: gen.Identity, RemainingConnections: uint64(gen.Connections),
			})
		}
	}
	sort.Slice(out.Prepared, func(i, j int) bool {
		if out.Prepared[i].Technique != out.Prepared[j].Technique {
			return out.Prepared[i].Technique < out.Prepared[j].Technique
		}
		if out.Prepared[i].Revision != out.Prepared[j].Revision {
			return out.Prepared[i].Revision < out.Prepared[j].Revision
		}
		return out.Prepared[i].Digest < out.Prepared[j].Digest
	})
	sort.Slice(out.Draining, func(i, j int) bool {
		return out.Draining[i].Identity.Revision < out.Draining[j].Identity.Revision
	})
	return out, nil
}

func sameStatusGenerationView(a, b State) bool {
	if a.ActiveNew != b.ActiveNew || len(a.Generations) != len(b.Generations) {
		return false
	}
	for i := range a.Generations {
		if a.Generations[i].ID != b.Generations[i].ID ||
			a.Generations[i].Identity != b.Generations[i].Identity ||
			a.Generations[i].Phase != b.Generations[i].Phase {
			return false
		}
	}
	return true
}

func (c *Controller) connectionCounts(ctx context.Context) (map[uint32]int, error) {
	type result struct {
		counts map[uint32]int
		err    error
	}
	bounded, cancel := context.WithTimeout(ctx, c.cfg.ConntrackTimeout)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		counts, err := c.cfg.Connections.Counts(bounded, c.cfg.NFT.Port)
		done <- result{counts: counts, err: err}
	}()
	select {
	case r := <-done:
		return r.counts, r.err
	case <-bounded.Done():
		return nil, bounded.Err()
	}
}

func (c *Controller) neutralizeConnections(ctx context.Context) (int, error) {
	type result struct {
		count int
		err   error
	}
	bounded, cancel := context.WithTimeout(ctx, c.cfg.ConntrackTimeout)
	defer cancel()
	done := make(chan result, 1)
	go func() {
		n, err := c.cfg.Connections.Neutralize(bounded, c.cfg.NFT.Port)
		done <- result{count: n, err: err}
	}()
	select {
	case r := <-done:
		return r.count, r.err
	case <-bounded.Done():
		return 0, bounded.Err()
	}
}

func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.removeRulesLocked(ctx); err != nil {
		// Keep controller-owned offloads disabled while live steering may still
		// exist. The caller retries teardown before releasing NFQUEUE ownership.
		return err
	}
	return c.restoreOffloads(ctx)
}

func (c *Controller) widen(sc Scope) Scope {
	if !c.cfg.ObserveInbound || c.cfg.Mode != modeEval || sc.Idle() {
		return sc
	}
	sc.Inbound = nftables.Selector{Any: true}
	return sc
}

const modeEval = "eval"

func (c *Controller) liveLocked() []*generationState {
	live := make([]*generationState, 0, len(c.generations))
	for _, g := range c.generations {
		if g.Phase == PhaseActive || g.Phase == PhaseDraining {
			live = append(live, g)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].ID < live[j].ID })
	return live
}
func (c *Controller) hasSteeringLocked() bool {
	for _, g := range c.liveLocked() {
		if !g.Scope.Idle() {
			return true
		}
	}
	return false
}
func (c *Controller) managerLocked(live []*generationState, active uint32) *nftables.Manager {
	cfg := c.cfg.NFT
	cfg.Outbound, cfg.Inbound = nftables.Selector{}, nftables.Selector{}
	cfg.Generations = nil
	cfg.ActiveGeneration = active
	for _, g := range live {
		cfg.Generations = append(cfg.Generations, nftables.Generation{ID: g.ID, Outbound: g.Scope.Outbound, Inbound: g.Scope.Inbound})
	}
	return nftables.New(cfg)
}
func (c *Controller) programLocked(ctx context.Context, live []*generationState, active uint32, verify bool) error {
	return c.programModeLocked(ctx, live, active, false, verify)
}

func (c *Controller) verifyCurrentProgramLocked(ctx context.Context) error {
	m := c.managerLocked(c.liveLocked(), c.activeNew)
	verifyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c.cfg.Program != nil {
		if c.cfg.VerifyProgram == nil {
			return errors.New("exact steering readback is not configured")
		}
		return c.cfg.VerifyProgram(verifyCtx, m.Config())
	}
	if c.cfg.NoNFT {
		return errors.New("exact steering readback is unavailable with no-nft mode")
	}
	return m.VerifyInstalled(verifyCtx)
}

func (c *Controller) programModeLocked(ctx context.Context, live []*generationState, active uint32, neutral bool, verify bool) error {
	m := c.managerLocked(live, active)
	cfg := m.Config()
	cfg.NeutralizeNew = neutral
	m = nftables.New(cfg)
	if c.cfg.Program != nil {
		err := c.cfg.Program(ctx, m.Config(), verify)
		if c.cfg.VerifyProgram != nil {
			verifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			verifyErr := c.cfg.VerifyProgram(verifyCtx, m.Config())
			cancel()
			if verifyErr != nil {
				return errors.Join(err, fmt.Errorf("verify programmed steering: %w", verifyErr))
			}
			// A verified exact desired state resolves a command timeout which may
			// have happened after the kernel accepted the transaction.
			err = nil
		}
		if err != nil {
			return err
		}
		c.nft = m
		return nil
	}
	if c.cfg.NoNFT {
		c.nft = m
		return nil
	}
	if verify {
		if err := m.Verify(ctx); err != nil {
			return err
		}
	}
	if err := m.InstallVerified(ctx); err != nil {
		return err
	}
	c.nft = m
	return nil
}
func (c *Controller) removeRulesLocked(ctx context.Context) error {
	return c.programLocked(ctx, nil, 0, true)
}
func (c *Controller) ensureOffloadsDown(ctx context.Context) error {
	if c.cfg.Iface == "" || c.offloads != nil {
		if c.offloads == nil {
			return nil
		}
		if c.offloads.Interface != c.cfg.Iface {
			return fmt.Errorf("persisted offload owner names %q, configured interface is %q", c.offloads.Interface, c.cfg.Iface)
		}
		return c.cfg.DisableOffloads(ctx, c.cfg.EthtoolPath, c.offloads)
	}
	d, err := c.cfg.CaptureOffloads(ctx, c.cfg.EthtoolPath, c.cfg.Iface)
	if err != nil {
		return err
	}
	if len(d.Features) == 0 {
		c.log.Infof("NIC offloads already disabled on %s; controller claims no ownership", c.cfg.Iface)
		return nil
	}
	c.offloads = d
	// Ownership must be durable before the first feature is mutated.
	if err := c.persistLocked(); err != nil {
		c.offloads = nil
		return err
	}
	if err := c.cfg.DisableOffloads(ctx, c.cfg.EthtoolPath, d); err != nil {
		restoreErr := c.cfg.RestoreOffloads(ctx, c.cfg.EthtoolPath, d)
		if restoreErr == nil {
			c.offloads = nil
		}
		persistErr := c.persistLocked()
		return errors.Join(err, restoreErr, persistErr)
	}
	c.log.Infof("NIC offloads adjusted: iface=%s %s", c.cfg.Iface, d.Summary())
	return nil
}
func (c *Controller) restoreOffloads(ctx context.Context) error {
	if c.offloads == nil {
		return nil
	}
	if err := c.cfg.RestoreOffloads(ctx, c.cfg.EthtoolPath, c.offloads); err != nil {
		c.log.Errorf("restore NIC offloads: %v", err)
		return errors.Join(err, c.persistLocked())
	}
	c.log.Infof("NIC offloads restored on %s", c.cfg.Iface)
	c.offloads = nil
	return c.persistLocked()
}
func (c *Controller) CensorCounts(ctx context.Context) (map[string]uint64, error) {
	c.mu.Lock()
	n := c.nft
	c.mu.Unlock()
	if n == nil {
		return map[string]uint64{}, nil
	}
	return n.ReadCounters(ctx)
}

func (c *Controller) persistLocked() (retErr error) {
	if c.cfg.StateFile == "" {
		return nil
	}
	defer func() {
		if retErr != nil {
			retErr = c.persistenceFailureLocked(retErr)
		}
	}()
	s := persistedState{Version: persistedStateVersion, ActiveNew: c.activeNew, Previous: c.previous, Unsafe: c.unsafe, Failure: c.failure, Offloads: c.offloads, Generations: make([]generationState, 0, len(c.generations))}
	for _, g := range c.generations {
		x := *g
		x.Scope = Scope{}
		s.Generations = append(s.Generations, x)
	}
	sort.Slice(s.Generations, func(i, j int) bool { return s.Generations[i].ID < s.Generations[j].ID })
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(c.cfg.StateFile)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create adapter state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".adapter-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	syncFile := c.cfg.SyncFile
	if syncFile == nil {
		syncFile = func(file *os.File) error { return file.Sync() }
	}
	if err := syncFile(tmp); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, c.cfg.StateFile); err != nil {
		return err
	}
	syncDirectory := c.cfg.SyncDirectory
	if syncDirectory == nil {
		syncDirectory = fsyncDirectory
	}
	if err := syncDirectory(dir); err != nil {
		// A successful rename is only visible-state evidence, not crash
		// durability. Never authorize a kernel transition without the directory
		// sync acknowledgement.
		ok = true
		return fmt.Errorf("sync adapter state directory after rename: %w", err)
	}
	ok = true
	return nil
}

func (c *Controller) persistenceFailureLocked(err error) error {
	cause := fmt.Errorf("adapter durability failure: %w", err)
	if c.persistFatal.CompareAndSwap(false, true) {
		c.faultLatched.Store(true)
		c.repairGuard.Store(false)
		c.unsafe, c.remediation = true, false
		c.failure = cause.Error()
		c.log.Errorf("%v", cause)
		if c.cfg.Fatal != nil {
			go c.cfg.Fatal(cause)
		}
	}
	return cause
}

func (c *Controller) loadLocked() (bool, error) {
	if c.cfg.StateFile == "" {
		return false, nil
	}
	f, err := os.Open(c.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	limit := int64(c.cfg.MaxGenerations)*(maxGenerationArtifact+4096) + 4096
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return false, fmt.Errorf("read adapter state: %w", err)
	}
	if int64(len(b)) > limit {
		return false, fmt.Errorf("adapter state exceeds %d-byte limit", limit)
	}
	var s persistedState
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return false, fmt.Errorf("decode adapter state: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("trailing JSON value")
		}
		return false, fmt.Errorf("decode adapter state: %w", err)
	}
	if s.Offloads != nil && s.Offloads.Interface != c.cfg.Iface {
		return false, fmt.Errorf("persisted offload owner names %q, configured interface is %q", s.Offloads.Interface, c.cfg.Iface)
	}
	// Even when artifact compatibility later fails, retain valid controller-
	// owned offload restoration metadata. Startup remains inactive and restores
	// these features before persisting that ownership as complete.
	c.offloads = s.Offloads
	if s.Version == 1 {
		return false, &stateCompatibilityError{cause: errors.New("state version 1 has no durable artifact protocol/schema/runtime metadata")}
	}
	if s.Version != persistedStateVersion {
		return false, fmt.Errorf("unsupported adapter state version %d", s.Version)
	}
	if len(s.Generations) > c.cfg.MaxGenerations {
		return false, fmt.Errorf("adapter state has %d generations, exceeding configured maximum %d", len(s.Generations), c.cfg.MaxGenerations)
	}
	// Validate the complete immutable artifact contract before reconstructing a
	// single engine. A changed binary must never partially load old intent and
	// then discover an incompatible active generation.
	savedByID := make(map[uint32]generationState, len(s.Generations))
	savedIdentity := make(map[adapter.Identity]uint32, len(s.Generations))
	for _, saved := range s.Generations {
		if _, err := generation.Mark(saved.ID); err != nil {
			return false, err
		}
		if _, exists := savedByID[saved.ID]; exists {
			return false, fmt.Errorf("adapter state contains duplicate generation %d", saved.ID)
		}
		if existingID, exists := savedIdentity[saved.Identity]; exists {
			return false, fmt.Errorf("adapter state maps artifact identity to both generations %d and %d", existingID, saved.ID)
		}
		if saved.Phase != PhasePrepared && saved.Phase != PhaseActive && saved.Phase != PhaseDraining && saved.Phase != PhaseDrained {
			return false, fmt.Errorf("generation %d has invalid phase %q", saved.ID, saved.Phase)
		}
		artifact, artifactErr := adapter.NewArtifact(saved.Metadata, []byte(saved.DNA))
		if artifactErr != nil {
			return false, &stateCompatibilityError{cause: fmt.Errorf("generation %d metadata: %w", saved.ID, artifactErr)}
		}
		if artifact.Identity() != saved.Identity {
			return false, &stateCompatibilityError{cause: fmt.Errorf("generation %d metadata identity does not match retained identity", saved.ID)}
		}
		if artifactErr := artifact.ValidateFor(c.Descriptor()); artifactErr != nil {
			return false, &stateCompatibilityError{cause: fmt.Errorf("generation %d: %w", saved.ID, artifactErr)}
		}
		if saved.Digest != saved.Metadata.Digest {
			return false, fmt.Errorf("generation %d digest does not match persisted artifact metadata", saved.ID)
		}
		if artifactErr := c.verifyArtifact(context.Background(), saved.Identity, saved.DNA); artifactErr != nil {
			return false, fmt.Errorf("validate persisted generation %d: %w", saved.ID, artifactErr)
		}
		savedByID[saved.ID] = saved
		savedIdentity[saved.Identity] = saved.ID
	}
	if s.ActiveNew != 0 {
		active, exists := savedByID[s.ActiveNew]
		if !exists {
			return false, fmt.Errorf("active generation %d absent from adapter state", s.ActiveNew)
		}
		if active.Phase != PhaseActive {
			return false, fmt.Errorf("active generation %d has phase %q", s.ActiveNew, active.Phase)
		}
	}
	prepared := make([]uint32, 0, len(s.Generations))
	cleanupPrepared := func() {
		for _, id := range prepared {
			delete(c.generations, id)
			_ = c.eng.Remove(id)
		}
	}
	for _, saved := range s.Generations {
		if err := c.prepareArtifactLocked(saved.ID, saved.Metadata, saved.DNA); err != nil {
			cleanupPrepared()
			return false, fmt.Errorf("reconstruct generation %d: %w", saved.ID, err)
		}
		prepared = append(prepared, saved.ID)
		c.generations[saved.ID].Phase = saved.Phase
	}
	if err := c.validateResourceBudgetsLocked(); err != nil {
		cleanupPrepared()
		return false, fmt.Errorf("adapter state resource budget: %w", err)
	}
	c.activeNew, c.previous, c.unsafe, c.failure, c.offloads = s.ActiveNew, s.Previous, s.Unsafe, s.Failure, s.Offloads
	c.remediation = false
	return true, nil
}

const (
	resourceHandshake = "handshake_scoped"
	resourceEvery     = "every_packet"
)

func resourceClass(scope Scope) string {
	if !establishmentOnly(scope.Outbound) || !establishmentOnly(scope.Inbound) {
		return resourceEvery
	}
	return resourceHandshake
}

func establishmentOnly(selector nftables.Selector) bool {
	if selector.Any {
		return false
	}
	for _, match := range selector.Flags {
		if match.Mask != 0xff || (match.Value != 0x02 && match.Value != 0x12) {
			return false
		}
	}
	return true
}

func (c *Controller) validateResourceBudgetsLocked() error {
	scoped, every := 0, 0
	for _, gen := range c.generations {
		if resourceClass(gen.Scope) == resourceEvery {
			every++
		} else {
			scoped++
		}
	}
	if scoped > c.cfg.MaxScopedGenerations {
		return fmt.Errorf("handshake-scoped generation budget is full (%d); drain and garbage-collect one before prepare", c.cfg.MaxScopedGenerations)
	}
	if every > c.cfg.MaxEveryPacketGenerations {
		return fmt.Errorf("every-packet generation budget is full (%d); drain and garbage-collect one before prepare", c.cfg.MaxEveryPacketGenerations)
	}
	return nil
}

func (c *Controller) nextGenerationLocked() uint32 {
	ids := make([]uint32, 0, len(c.generations)+len(c.reservedGenerations))
	for id := range c.generations {
		ids = append(ids, id)
	}
	for id := range c.reservedGenerations {
		if c.generations[id] == nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	candidate := uint32(1)
	for _, id := range ids {
		if id == candidate {
			candidate++
		} else if id > candidate {
			break
		}
	}
	if candidate == 0 || candidate > generation.MaxID {
		return 0
	}
	return candidate
}

func (c *Controller) reconcileReservedGenerationsLocked(counts map[uint32]int) {
	for id := range c.reservedGenerations {
		if counts[id] == 0 {
			delete(c.reservedGenerations, id)
		}
	}
	for id, count := range counts {
		if count > 0 && c.generations[id] == nil {
			c.reservedGenerations[id] = struct{}{}
		}
	}
}

func (c *Controller) appendFailureLocked(failure string) {
	if c.failure == "" {
		c.failure = failure
		return
	}
	c.failure += "; " + failure
}

func fsyncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

func (c *Controller) quarantineStateLocked() (string, error) {
	if c.cfg.StateFile == "" {
		return "", errors.New("adapter state path is empty")
	}
	dir := filepath.Dir(c.cfg.StateFile)
	var quarantine string
	for attempt := 0; attempt < 100; attempt++ {
		quarantine = fmt.Sprintf("%s.quarantine-%d-%d", c.cfg.StateFile, time.Now().UnixNano(), attempt)
		if _, err := os.Lstat(quarantine); errors.Is(err, os.ErrNotExist) {
			break
		} else if err != nil {
			return "", err
		}
		quarantine = ""
	}
	if quarantine == "" {
		return "", errors.New("could not allocate a unique quarantine path")
	}
	if err := os.Rename(c.cfg.StateFile, quarantine); err != nil {
		return "", err
	}
	syncDirectory := c.cfg.SyncDirectory
	if syncDirectory == nil {
		syncDirectory = fsyncDirectory
	}
	if err := syncDirectory(dir); err != nil {
		return "", fmt.Errorf("sync quarantine rename: %w", err)
	}
	return quarantine, nil
}
func (c *Controller) phasesLocked() map[uint32]Phase {
	m := make(map[uint32]Phase, len(c.generations))
	for id, g := range c.generations {
		m[id] = g.Phase
	}
	return m
}
func (c *Controller) restoreLocked(active, previous uint32, unsafe bool, failure string, remediation bool, phases map[uint32]Phase) {
	c.activeNew, c.previous, c.unsafe, c.failure, c.remediation = active, previous, unsafe, failure, remediation
	for id, p := range phases {
		if c.generations[id] != nil {
			c.generations[id].Phase = p
		}
	}
}
func describe(sel nftables.Selector) string {
	switch {
	case sel.Any:
		return "all"
	case sel.Empty():
		return "none"
	default:
		out := ""
		for i, f := range sel.Flags {
			if i > 0 {
				out += ","
			}
			out += fmt.Sprintf("flags&%#02x==%#02x", f.Mask, f.Value)
		}
		return out
	}
}
