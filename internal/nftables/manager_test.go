package nftables

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/getlantern/geneva-server/internal/testutil"
)

// anySel is the widest selector: a strategy whose triggers cannot be expressed
// in nftables, so every packet on the port must be queued.
var anySel = Selector{Any: true}

func TestRulesetScoping(t *testing.T) {
	m := New(Config{
		Table: "geneva_test", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e,
		Outbound: anySel, Inbound: anySel,
	})
	rs := m.Ruleset()

	// The steering must be scoped to exactly the proxy's TCP port in each
	// direction — nothing else may be diverted into the queues.
	wants := []string{
		"table inet geneva_test {",
		"meta nfproto ipv4 meta l4proto tcp tcp sport 8080 queue num 100 bypass", // egress
		"meta nfproto ipv4 meta l4proto tcp tcp dport 8080 queue num 101 bypass", // ingress
		"meta mark 0x67656e accept", // reinjection loop guard
		"policy accept;",            // fail-open chain policy
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
	// The table family is inet, which sees IPv6 too. The engine and the
	// reinjector are IPv4-only, so every queue rule must carry the nfproto
	// guard — without it, IPv6 TCP on the proxy's port takes a userspace round
	// trip only to fail open.
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "queue num") && !strings.Contains(line, "meta nfproto ipv4") {
			t.Errorf("queue rule not scoped to IPv4: %q", strings.TrimSpace(line))
		}
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
	m := New(Config{
		Table: "geneva_lifecycle_test", Port: 18080, OutQueue: 200, InQueue: 201, Mark: 0x67656e,
		Outbound: anySel, Inbound: anySel,
	})
	t.Cleanup(func() { _ = m.Remove(ctx) })

	if err := m.Install(ctx); err != nil {
		t.Fatalf("install: %v", err)
	}
	// Idempotent: a second install must not stack rules or error.
	if err := m.Install(ctx); err != nil {
		t.Fatalf("second install: %v", err)
	}
	if !testutil.TableExists(t, "geneva_lifecycle_test") {
		t.Fatal("table absent after install")
	}
	if err := m.Remove(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if testutil.TableExists(t, "geneva_lifecycle_test") {
		t.Fatal("table present after remove: stale rules leaked")
	}
	// Remove on an absent table is a no-op, not an error.
	if err := m.Remove(ctx); err != nil {
		t.Fatalf("remove of absent table errored: %v", err)
	}
}

// TestIdleSelectorsProgramNothing pins the property that makes an unconfigured
// sidecar free: with nothing to match, there is no table at all. A sidecar that
// installed rules and passed packets through would still pay the NFQUEUE round
// trip for every one of them, which measured as a 76% throughput loss on a
// 1-vCPU box.
func TestIdleSelectorsProgramNothing(t *testing.T) {
	m := New(Config{Table: "geneva_idle", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e})
	if !m.Idle() {
		t.Error("manager with no selectors is not idle")
	}
	if rs := m.Ruleset(); rs != "" {
		t.Errorf("idle manager produced a ruleset:\n%s", rs)
	}
}

// TestRulesetFlagScoping is the optimization proper: a strategy that only
// triggers on handshake packets must leave bulk data in the kernel.
func TestRulesetFlagScoping(t *testing.T) {
	m := New(Config{
		Table: "geneva_flags", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e,
		// Exact SYN (the common handshake trigger) plus a wildcard RST.
		Outbound: Selector{Flags: []FlagMatch{{Mask: 0xff, Value: 0x02}}},
		Inbound:  Selector{Flags: []FlagMatch{{Mask: 0x04, Value: 0x04}}},
	})
	rs := m.Ruleset()

	wants := []string{
		"tcp sport 8080 tcp flags & 0xff == syn queue num 100 bypass",
		"tcp dport 8080 tcp flags & rst == rst queue num 101 bypass",
	}
	for _, w := range wants {
		if !strings.Contains(rs, w) {
			t.Errorf("ruleset missing %q\n---\n%s", w, rs)
		}
	}
	// No unconditional queue rule may survive scoping, or bulk data is still
	// taking the round trip.
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "queue num") && !strings.Contains(line, "tcp flags") {
			t.Errorf("unscoped queue rule survived: %q", strings.TrimSpace(line))
		}
	}
}

// TestRulesetMultiFlagParenthesized pins that multi-flag sets are rendered in
// parentheses. Bare pipes parse under nft's own operator precedence, so
// `tcp flags & syn|ack == syn|ack` installs cleanly as a completely different
// match — a wildcard multi-flag trigger like SA* would silently mis-scope.
func TestRulesetMultiFlagParenthesized(t *testing.T) {
	m := New(Config{
		Table: "geneva_multi", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e,
		// A wildcard SYN+ACK trigger and an exact PSH+ACK one.
		Outbound: Selector{Flags: []FlagMatch{{Mask: 0x12, Value: 0x12}}},
		Inbound:  Selector{Flags: []FlagMatch{{Mask: 0xff, Value: 0x18}}},
	})
	rs := m.Ruleset()
	wants := []string{
		"tcp flags & (syn|ack) == (syn|ack)",
		"tcp flags & 0xff == (psh|ack)",
	}
	for _, w := range wants {
		if !strings.Contains(rs, w) {
			t.Errorf("ruleset missing %q\n---\n%s", w, rs)
		}
	}
}

// TestRulesetOneDirection covers an outbound-only strategy: the inbound chain
// must exist (it is where the reinjection guard and policy live) but carry no
// queue rule.
func TestRulesetOneDirection(t *testing.T) {
	m := New(Config{
		Table: "geneva_one", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e,
		Outbound: Selector{Any: true},
	})
	rs := m.Ruleset()
	if strings.Contains(rs, "dport") {
		t.Errorf("inbound queue rule emitted for an outbound-only strategy:\n%s", rs)
	}
	if !strings.Contains(rs, "sport 8080") {
		t.Errorf("outbound queue rule missing:\n%s", rs)
	}
}
