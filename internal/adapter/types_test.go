package adapter

import (
	"encoding/json"
	"testing"
)

func validArtifact(t *testing.T, payload []byte) Artifact {
	t.Helper()
	a, err := NewArtifact(ArtifactMetadata{
		Technique: TechniqueGeneva, Revision: "r1", Digest: Digest(payload), Size: len(payload),
		AdapterProtocol: Version1, RequiredRuntimeName: RuntimeNameGeneva,
		RequiredRuntimeVersion: "test", SchemaVersion: SchemaVersionV1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestArtifactUsesExactGenericV1WireAndDefensiveCopies(t *testing.T) {
	payload := []byte("dna")
	a := validArtifact(t, payload)
	payload[0] = 'X'
	copy := a.Payload()
	copy[0] = 'Y'
	if got := string(a.Payload()); got != "dna" {
		t.Fatalf("artifact payload mutated through caller: %q", got)
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	metadata := raw["metadata"].(map[string]any)
	for _, key := range []string{"content_sha256", "adapter_protocol", "required_runtime_name", "required_runtime_version", "schema_version"} {
		if _, ok := metadata[key]; !ok {
			t.Fatalf("missing generic metadata field %q: %s", key, b)
		}
	}
	var decoded Artifact
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(a) {
		t.Fatalf("artifact JSON round trip differs: %#v %#v", decoded.Metadata(), a.Metadata())
	}
}

func TestArtifactRejectsNonCanonicalDigestAndOversize(t *testing.T) {
	metadata := ArtifactMetadata{
		Technique: TechniqueGeneva, Revision: "r1", Digest: "SHA256:bad", Size: 1,
		AdapterProtocol: Version1, RequiredRuntimeName: RuntimeNameGeneva,
		RequiredRuntimeVersion: "test", SchemaVersion: SchemaVersionV1,
	}
	if _, err := NewArtifact(metadata, []byte("x")); err == nil {
		t.Fatal("accepted noncanonical digest")
	}
	payload := make([]byte, MaxArtifactSize+1)
	metadata.Digest, metadata.Size = Digest(payload), len(payload)
	if _, err := NewArtifact(metadata, payload); err == nil {
		t.Fatal("accepted oversized decoded artifact")
	}
}
