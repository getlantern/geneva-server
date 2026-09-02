package nftables

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/getlantern/geneva-server/internal/generation"
	"github.com/getlantern/geneva-server/internal/testutil"
)

// anySel is the widest selector: a strategy whose triggers cannot be expressed
// in nftables, so every packet on the port must be queued.
var anySel = Selector{Any: true}

func TestRulesetScoping(t *testing.T) {
	m := New(Config{
		Table: "geneva_test", Port: 8080, OutQueue: 100, InQueue: 101,
		Outbound: anySel, Inbound: anySel,
	})
	rs := m.Ruleset()

	// The steering must be scoped to exactly the proxy's TCP port in each
	// direction — nothing else may be diverted into the queues.
	wants := []string{
		"table inet geneva_test {",
		"tcp sport 8080 ct mark & 0xfffff000 == 0x67001000 queue num 100 bypass", // egress
		"tcp dport 8080 ct mark & 0xfffff000 == 0x67001000 queue num 101 bypass", // ingress
		"meta skuid 0 accept", // dedicated reinjection socket owner bypass
		"policy accept;",      // fail-open chain policy
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
		Table: "geneva_lifecycle_test", Port: 18080, OutQueue: 200, InQueue: 201,
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
	m := New(Config{Table: "geneva_idle", Port: 8080, OutQueue: 100, InQueue: 101})
	if !m.Idle() {
		t.Error("manager with no selectors is not idle")
	}
	if rs := m.Ruleset(); rs != "" {
		t.Errorf("idle manager produced a ruleset:\n%s", rs)
	}
}

func TestNeutralBoundaryProgramsAssignmentWithoutSelectors(t *testing.T) {
	m := New(Config{Table: "geneva_neutral", Port: 8080, OutQueue: 100, InQueue: 101, NeutralizeNew: true})
	if m.Idle() {
		t.Fatal("neutral activation boundary was treated as idle")
	}
	rs := m.Ruleset()
	if !strings.Contains(rs, "ct mark set (ct mark & 0xfff) | 0x67000000") {
		t.Fatalf("neutral activation boundary lacks generation-zero assignment:\n%s", rs)
	}
	if strings.Contains(rs, "queue num") {
		t.Fatalf("neutral activation boundary unexpectedly queues packets:\n%s", rs)
	}
}

func TestLegacySelectorsAssignFallbackGeneration(t *testing.T) {
	rs := New(Config{
		Table: "geneva_legacy", Port: 8080, OutQueue: 100, InQueue: 101,
		Outbound: anySel,
	}).Ruleset()
	if !strings.Contains(rs, "ct mark set (ct mark & 0xfff) | 0x67001000") {
		t.Fatalf("legacy selector ruleset lacks generation-one assignment:\n%s", rs)
	}
	if !strings.Contains(rs, "ct mark & 0xfffff000 == 0x67001000 queue num 100 bypass") {
		t.Fatalf("legacy selector ruleset lacks matching generation-one queue rule:\n%s", rs)
	}
}

// TestRulesetFlagScoping is the optimization proper: a strategy that only
// triggers on handshake packets must leave bulk data in the kernel.
func TestRulesetFlagScoping(t *testing.T) {
	m := New(Config{
		Table: "geneva_flags", Port: 8080, OutQueue: 100, InQueue: 101,
		// Exact SYN (the common handshake trigger) plus a wildcard RST.
		Outbound: Selector{Flags: []FlagMatch{{Mask: 0xff, Value: 0x02}}},
		Inbound:  Selector{Flags: []FlagMatch{{Mask: 0x04, Value: 0x04}}},
	})
	rs := m.Ruleset()

	wants := []string{
		"tcp sport 8080 ct mark & 0xfffff000 == 0x67001000 tcp flags & 0xff == syn queue num 100 bypass",
		"tcp dport 8080 ct mark & 0xfffff000 == 0x67001000 tcp flags & rst == rst queue num 101 bypass",
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
		Table: "geneva_multi", Port: 8080, OutQueue: 100, InQueue: 101,
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
		Table: "geneva_one", Port: 8080, OutQueue: 100, InQueue: 101,
		Outbound: Selector{Any: true},
	})
	rs := m.Ruleset()
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "dport") && strings.Contains(line, "queue num") {
			t.Errorf("inbound queue rule emitted for an outbound-only strategy:\n%s", rs)
		}
	}
	if !strings.Contains(rs, "sport 8080") {
		t.Errorf("outbound queue rule missing:\n%s", rs)
	}
}

func TestGenerationAffinityRules(t *testing.T) {
	m := New(Config{
		Table: "geneva_generations", Port: 8080, OutQueue: 100, InQueue: 101,
		ActiveGeneration: 9,
		Generations: []Generation{
			{ID: 8, Outbound: Selector{Any: true}},
			{ID: 9, Inbound: Selector{Any: true}},
		},
	})
	rs := m.Ruleset()
	wants := []string{
		// Preserve the low 12 bits owned by unrelated mark users.
		"ct mark set (ct mark & 0xfff) | 0x67009000",
		// Only original inbound SYNs get the current generation.
		"ct state new tcp flags & (syn|ack) == syn",
		// Both directions select an engine from the same conntrack field.
		"ct mark & 0xfffff000 == 0x67008000",
		"ct mark & 0xfffff000 == 0x67009000",
		"ct mark & 0xfffff000 == 0x67009000",
	}
	for _, want := range wants {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q\n---\n%s", want, rs)
		}
	}
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "queue num") && !strings.Contains(line, "ct mark & 0xfffff000 == 0x67") {
			t.Errorf("queue rule can capture an unmarked pre-existing flow: %s", line)
		}
	}
}

func TestQueueDispatchNeverMutatesPacketMark(t *testing.T) {
	rs := New(Config{Port: 443, OutQueue: 100, InQueue: 101, ActiveGeneration: 2, Generations: []Generation{{ID: 2, Outbound: anySel, Inbound: anySel}}}).Ruleset()
	if strings.Contains(rs, "meta mark set") || strings.Contains(rs, "output_cleanup") || strings.Contains(rs, "input_cleanup") {
		t.Fatalf("NFQUEUE dispatch mutates or cleans skb marks instead of using CTA_MARK metadata:\n%s", rs)
	}
}

func TestGenerationMarksPreserveLanternPacketRoutingBits(t *testing.T) {
	m := New(Config{Port: 443, OutQueue: 100, InQueue: 101, ActiveGeneration: 2, Generations: []Generation{{ID: 2, Outbound: anySel, Inbound: anySel}}})
	rs := m.Ruleset()
	if !strings.Contains(rs, "ct mark set (ct mark & 0xfff) | 0x67002000") {
		t.Fatalf("conntrack assignment does not preserve 0x438/phost bits:\n%s", rs)
	}
	if strings.Contains(rs, "meta mark set") {
		t.Fatalf("packet dispatch mutates exact routing marks:\n%s", rs)
	}
	generationMark, err := generation.Mark(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []uint32{0x438, 1088, 745, 746} {
		if got := existing & ^uint32(0xfffff000); got != existing {
			t.Errorf("routing mark %#x not outside reservation", existing)
		}
		assigned := (existing & ^generation.Mask) | generationMark
		if got := assigned & ^generation.Mask; got != existing {
			t.Errorf("conntrack assignment changed routing mark %#x to %#x", existing, got)
		}
	}
}

func TestTransactionFingerprintCoversAssignmentAndScope(t *testing.T) {
	base := Config{Port: 443, OutQueue: 100, InQueue: 101, ActiveGeneration: 1, Generations: []Generation{{ID: 1, Outbound: anySel}}}
	a := New(base)
	bCfg := base
	bCfg.ActiveGeneration = 2
	bCfg.Generations = append([]Generation(nil), base.Generations...)
	bCfg.Generations = append(bCfg.Generations, Generation{ID: 2, Inbound: anySel})
	b := New(bCfg)
	if a.revisionChain() == b.revisionChain() {
		t.Fatal("different atomic steering transactions share a readback fingerprint")
	}
	if !strings.Contains(a.Ruleset(), "chain "+a.revisionChain()+" {}") {
		t.Fatalf("ruleset lacks its readback fingerprint:\n%s", a.Ruleset())
	}
}
