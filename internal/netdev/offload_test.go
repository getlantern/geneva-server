//go:build linux

package netdev

import "testing"

func TestParseFeatureOutputNeverClaimsFixedFeatures(t *testing.T) {
	state := parseFeatureOutput([]byte("generic-segmentation-offload: on\n" +
		"tx-gre-segmentation: on [fixed]\n" +
		"large-receive-offload: off [fixed]\n"))
	if !state["gso"] {
		t.Fatal("changeable enabled feature was not captured")
	}
	if state["tx-gre-segmentation"] || state["lro"] {
		t.Fatalf("fixed features were claimed: %+v", state)
	}
}
