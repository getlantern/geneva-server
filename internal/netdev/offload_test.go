//go:build linux

package netdev

import (
	"slices"
	"testing"
)

func TestParseFeatureOutputPreservesFixedState(t *testing.T) {
	state := parseFeatureOutput([]byte("generic-segmentation-offload: on\n" +
		"tx-gre-segmentation: on [fixed]\n" +
		"large-receive-offload: off [fixed]\n"))
	if got := state["gso"]; !got.enabled || got.fixed {
		t.Fatal("changeable enabled feature was not captured")
	}
	if got := state["tx-gre-segmentation"]; !got.enabled || !got.fixed {
		t.Fatalf("enabled fixed feature state was lost: %+v", got)
	}
	if got := state["lro"]; got.enabled || !got.fixed {
		t.Fatalf("disabled fixed feature state was lost: %+v", got)
	}
}

func TestOriginalFromStateRejectsEnabledFixedOffload(t *testing.T) {
	state := map[string]featureState{
		"gso": {enabled: true, fixed: true},
		"tso": {enabled: false, fixed: true},
	}
	if _, err := originalFromState("eth-test", state); err == nil {
		t.Fatal("enabled fixed offload was accepted")
	}
	state["gso"] = featureState{enabled: false, fixed: true}
	if original, err := originalFromState("eth-test", state); err != nil || len(original.Features) != 0 {
		t.Fatalf("disabled fixed offloads = %+v, %v", original, err)
	}
}

// A virtio NIC can verify RX checksums without allowing that feature to be
// disabled. It must still satisfy every segmentation and TX requirement.
func TestCaptureVirtioReceiveChecksumVerification(t *testing.T) {
	state := parseFeatureOutput([]byte("rx-checksumming: on [fixed]\ntx-checksumming: on\ngeneric-segmentation-offload: on\nlarge-receive-offload: off [fixed]\n"))
	original, err := originalFromState("eth0", state)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(original.Features, "rx") {
		t.Fatal("RX verification must not become runtime-owned")
	}
	if !slices.Contains(original.Features, "tx") || !slices.Contains(original.Features, "gso") {
		t.Fatalf("missing required ownership: %v", original.Features)
	}
	for _, required := range []string{"tx", "gso", "gro", "tso", "sg", "lro", "ufo", "tx-gre-segmentation"} {
		t.Run(required, func(t *testing.T) {
			unsafe := map[string]featureState{"rx": {enabled: true, fixed: true}, required: {enabled: true, fixed: true}}
			if _, err := originalFromState("eth0", unsafe); err == nil {
				t.Fatal("required fixed offload accepted")
			}
		})
	}
}
