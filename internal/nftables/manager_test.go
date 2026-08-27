package nftables

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRulesetScoping(t *testing.T) {
	m := New(Config{Table: "geneva_test", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e})
	rs := m.Ruleset()

	// The steering must be scoped to exactly the proxy's TCP port in each
	// direction — nothing else may be diverted into the queues.
	wants := []string{
		"table inet geneva_test {",
		"tcp sport 8080 queue num 100 bypass", // egress
		"tcp dport 8080 queue num 101 bypass", // ingress
		"meta mark 0x67656e accept",           // reinjection loop guard
		"policy accept;",                      // fail-open chain policy
	}
	for _, w := range wants {
		if !strings.Contains(rs, w) {
			t.Errorf("ruleset missing %q\n---\n%s", w, rs)
		}
	}
	// It must not steer UDP or any other port.
	if strings.Contains(rs, "udp") {
		t.Errorf("ruleset unexpectedly references udp:\n%s", rs)
	}
}

// TestInstallRemoveLifecycle exercises the real nft binary. It requires root and
// nftables; otherwise it is skipped. It proves Install is idempotent and Remove
// leaves no table behind.
func TestInstallRemoveLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	ctx := context.Background()
	m := New(Config{Table: "geneva_lifecycle_test", Port: 18080, OutQueue: 200, InQueue: 201, Mark: 0x67656e})
	t.Cleanup(func() { _ = m.Remove(ctx) })

	if err := m.Install(ctx); err != nil {
		t.Fatalf("install: %v", err)
	}
	// Idempotent: a second install must not stack rules or error.
	if err := m.Install(ctx); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !tableExists(t, "geneva_lifecycle_test") {
		t.Fatal("table absent after install")
	}
	if err := m.Remove(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if tableExists(t, "geneva_lifecycle_test") {
		t.Fatal("table present after remove: stale rules leaked")
	}
	// Remove on an absent table is a no-op, not an error.
	if err := m.Remove(ctx); err != nil {
		t.Fatalf("remove of absent table errored: %v", err)
	}
}

func tableExists(t *testing.T, name string) bool {
	t.Helper()
	out, err := exec.Command("nft", "list", "tables", "inet").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v: %s", err, out)
	}
	return strings.Contains(string(out), "table inet "+name)
}
