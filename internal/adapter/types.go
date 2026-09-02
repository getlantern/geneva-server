// Package adapter defines the transport-neutral versioned local lifecycle
// contract shared by the HTTP adapter and the Geneva controller.
package adapter

import "time"

const (
	TechniqueGeneva          = "geneva"
	SchemaVersionV1   uint32 = 1
	ProtocolVersionV1 uint32 = 1
	MaxArtifactBytes         = 256 << 10
	MaxGenerations           = 32
)

// Identity is the immutable generic deployment identity. Digest is canonical
// bare lowercase SHA-256 hex of the artifact bytes.
type Identity struct {
	Technique string `json:"technique"`
	Revision  string `json:"revision"`
	Digest    string `json:"digest"`
}

// Deployment binds a generic identity to its adapter-local generation.
type Deployment struct {
	Generation uint32   `json:"generation"`
	Identity   Identity `json:"identity"`
}

type Descriptor struct {
	ProtocolVersion         uint32   `json:"protocol_version"`
	Technique               string   `json:"technique"`
	SupportedSchemaVersions []uint32 `json:"supported_schema_versions"`
	RuntimeVersion          string   `json:"runtime_version"`
	MaxArtifactBytes        uint32   `json:"max_artifact_bytes"`
	MaxLiveGenerations      uint32   `json:"max_live_generations"`
	Lifecycle               []string `json:"lifecycle"`
}

type VerifyResult struct {
	Identity      Identity `json:"identity"`
	ResourceClass string   `json:"resource_class"`
	Outbound      string   `json:"outbound"`
	Inbound       string   `json:"inbound"`
}

type DrainResult struct {
	Deployment  Deployment `json:"deployment"`
	Connections int        `json:"connections"`
	Drained     bool       `json:"drained"`
	CheckedAt   time.Time  `json:"checked_at"`
}

type GCResult struct {
	Removed []Deployment `json:"removed"`
	Kept    []Deployment `json:"kept"`
}
