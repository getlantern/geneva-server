//go:build linux

package netdev

import "testing"

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
