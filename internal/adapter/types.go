// Package adapter mirrors the generic overlay adapter v1 contract. Technique-
// specific runtimes keep their numeric kernel generation IDs private.
package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrPayloadTooLarge   = errors.New("artifact payload too large")
	ErrLifecycleConflict = errors.New("adapter lifecycle conflict")
)

type Version = uint32

const (
	Version1                    Version = 1
	SchemaVersionV1             uint32  = 1
	TechniqueGeneva                     = "geneva"
	RuntimeNameGeneva                   = "geneva-engine"
	MaxArtifactSize                     = 256 * 1024
	DefaultLiveGenerationBudget uint32  = 3
	MaxLiveGenerationBudget     uint32  = 32
)

// RuntimeVersionGeneva is the strategy-compatibility version of the Geneva
// engine. The descriptor advertises it as runtime_version and artifacts must
// require it exactly, so it is deliberately independent of the package build
// version: a release that leaves strategy interpretation unchanged keeps it,
// and every published artifact stays valid across the upgrade. Bump it only
// when the same DNA could behave differently: a grammar change, different
// engine semantics, or different action behavior.
const RuntimeVersionGeneva = "0.0.4"

type Descriptor struct {
	AdapterProtocol    Version  `json:"adapter_protocol"`
	Technique          string   `json:"technique"`
	RuntimeName        string   `json:"runtime_name"`
	RuntimeVersion     string   `json:"runtime_version"`
	SchemaVersions     []uint32 `json:"schema_versions"`
	MaxLiveGenerations uint32   `json:"max_live_generations,omitempty"`
}

type ArtifactIdentity struct {
	Technique string `json:"technique"`
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
}

type Identity = ArtifactIdentity

type ArtifactMetadata struct {
	Technique              string  `json:"technique"`
	Revision               string  `json:"revision"`
	Digest                 string  `json:"content_sha256"`
	Size                   int     `json:"size"`
	AdapterProtocol        Version `json:"adapter_protocol"`
	RequiredRuntimeName    string  `json:"required_runtime_name"`
	RequiredRuntimeVersion string  `json:"required_runtime_version"`
	SchemaVersion          uint32  `json:"schema_version"`
}

// Artifact is immutable after construction or JSON decoding. Accessors return
// values or copies, matching overlay-agent's generic v1 boundary.
type Artifact struct {
	metadata ArtifactMetadata
	payload  []byte
}

func NewArtifact(metadata ArtifactMetadata, payload []byte) (Artifact, error) {
	a := Artifact{metadata: metadata, payload: slices.Clone(payload)}
	if err := a.Validate(); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (a Artifact) Metadata() ArtifactMetadata { return a.metadata }
func (a Artifact) Payload() []byte            { return slices.Clone(a.payload) }

func (a Artifact) Identity() ArtifactIdentity {
	return ArtifactIdentity{Technique: a.metadata.Technique, Revision: a.metadata.Revision, Digest: a.metadata.Digest}
}

func (a Artifact) Equal(other Artifact) bool {
	return a.metadata == other.metadata && slices.Equal(a.payload, other.payload)
}

func (a Artifact) Validate() error {
	identity := a.Identity()
	switch {
	case strings.TrimSpace(identity.Technique) == "":
		return errors.New("technique is required")
	case strings.TrimSpace(identity.Revision) == "":
		return errors.New("revision is required")
	case a.metadata.Size < 0 || a.metadata.Size != len(a.payload):
		return fmt.Errorf("metadata size %d does not match payload size %d", a.metadata.Size, len(a.payload))
	case len(a.payload) > MaxArtifactSize:
		return fmt.Errorf("%w: artifact is %d bytes; limit is %d", ErrPayloadTooLarge, len(a.payload), MaxArtifactSize)
	case identity.Digest != Digest(a.payload):
		return errors.New("artifact digest does not match payload")
	case a.metadata.AdapterProtocol == 0:
		return errors.New("adapter protocol is required")
	case strings.TrimSpace(a.metadata.RequiredRuntimeName) == "":
		return errors.New("required runtime name is required")
	case strings.TrimSpace(a.metadata.RequiredRuntimeVersion) == "":
		return errors.New("required runtime version is required")
	case a.metadata.SchemaVersion == 0:
		return errors.New("schema version is required")
	default:
		return nil
	}
}

func (a Artifact) ValidateFor(descriptor Descriptor) error {
	if err := a.Validate(); err != nil {
		return err
	}
	identity := a.Identity()
	switch {
	case descriptor.AdapterProtocol != a.metadata.AdapterProtocol:
		return fmt.Errorf("artifact requires adapter protocol %d, runtime implements %d", a.metadata.AdapterProtocol, descriptor.AdapterProtocol)
	case descriptor.Technique != identity.Technique:
		return fmt.Errorf("artifact technique %q does not match adapter technique %q", identity.Technique, descriptor.Technique)
	case descriptor.RuntimeName != a.metadata.RequiredRuntimeName:
		return fmt.Errorf("artifact requires runtime %q, adapter provides %q", a.metadata.RequiredRuntimeName, descriptor.RuntimeName)
	case descriptor.RuntimeVersion != a.metadata.RequiredRuntimeVersion:
		return fmt.Errorf("artifact requires runtime version %q, adapter provides exact version %q", a.metadata.RequiredRuntimeVersion, descriptor.RuntimeVersion)
	case !slices.Contains(descriptor.SchemaVersions, a.metadata.SchemaVersion):
		return fmt.Errorf("adapter does not support schema %d", a.metadata.SchemaVersion)
	default:
		return nil
	}
}

type artifactJSON struct {
	Metadata ArtifactMetadata `json:"metadata"`
	Payload  []byte           `json:"payload"`
}

func (a Artifact) MarshalJSON() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(artifactJSON{Metadata: a.metadata, Payload: a.payload})
}

func (a *Artifact) UnmarshalJSON(data []byte) error {
	var encoded artifactJSON
	if err := json.Unmarshal(data, &encoded); err != nil {
		return fmt.Errorf("unmarshal overlay artifact: %w", err)
	}
	decoded, err := NewArtifact(encoded.Metadata, encoded.Payload)
	if err != nil {
		return err
	}
	*a = decoded
	return nil
}

// Deployment is internal-only compatibility state. Generic callers never
// provide numeric generations.
type Deployment struct {
	Generation uint32   `json:"generation"`
	Identity   Identity `json:"identity"`
}

type Status struct {
	Active   *ArtifactIdentity  `json:"active,omitempty"`
	Prepared []ArtifactIdentity `json:"prepared,omitempty"`
	Draining []DrainGeneration  `json:"draining,omitempty"`
	// Activity reports what each serving generation (active or draining) has
	// done to the traffic it processed. Older clients ignore it.
	Activity []GenerationActivity `json:"activity,omitempty"`
	// Steering reports where the runtime intercepts traffic.
	Steering *SteeringStatus `json:"steering,omitempty"`
}

// GenerationActivity is one serving generation's cumulative packet counters.
// Counters only grow within one Lineage; a new lineage for the same identity
// means they restarted from zero. Acted packets are Dropped + Tampered +
// Expanded: the packets the strategy changed.
type GenerationActivity struct {
	Identity  ArtifactIdentity `json:"identity"`
	Lineage   string           `json:"lineage"`
	PacketsIn uint64           `json:"packets_in"`
	BytesIn   uint64           `json:"bytes_in"`
	Unchanged uint64           `json:"unchanged"`
	Dropped   uint64           `json:"dropped"`
	Tampered  uint64           `json:"tampered"`
	Expanded  uint64           `json:"expanded"`
	Errors    uint64           `json:"errors"`
}

// SteeringStatus is the interception the runtime has programmed. Port is the
// TCP listener port whose traffic is steered; Active is false while no
// generation is steering.
type SteeringStatus struct {
	Port   uint16 `json:"port"`
	Active bool   `json:"active"`
}

type DrainGeneration struct {
	Identity             ArtifactIdentity `json:"identity"`
	RemainingConnections uint64           `json:"remaining_connections"`
}

type DrainResult struct {
	Complete             bool   `json:"complete"`
	RemainingConnections uint64 `json:"remaining_connections"`
}

// Adapter is the exact generic v1 lifecycle implemented by technique runtimes.
type Adapter interface {
	Descriptor() Descriptor
	Prepare(context.Context, Artifact) error
	Verify(context.Context, Artifact) error
	ActivateForNewConnections(context.Context, Artifact) error
	DeactivateForNewConnections(context.Context, ArtifactIdentity) error
	Status(context.Context) (Status, error)
	Drain(context.Context, ArtifactIdentity) (DrainResult, error)
	Rollback(context.Context, Artifact) error
	GarbageCollect(context.Context, []ArtifactIdentity) error
}
