// Package nftables programs and tears down the narrowly scoped netfilter rules
// that steer a proxy's TCP traffic into the NFQUEUE queues.
//
// All rules live in a single dedicated table (`inet geneva_server` by default).
// The whole table is created on startup and deleted on shutdown, so the runtime
// can never leak a stale rule: deleting the table removes every chain and rule
// it owns atomically, and the table name is disjoint from any other subsystem's.
//
// The steering is scoped to one TCP port in each direction — the proxy's
// listening port — to IPv4, and, when the loaded strategy allows it, to the
// TCP flag combinations that strategy's triggers can actually match. A packet
// no trigger can match is passed through byte-for-byte by the engine, so
// leaving it in the kernel reaches the same result without the round trip; see
// internal/steering. A direction whose forest is empty gets no rule at all,
// which is what makes an unconfigured sidecar free. The table family is `inet`, which sees both
// address families, so the queue rules match `meta nfproto ipv4` explicitly:
// the engine and the reinjector are IPv4-only, so queueing IPv6 would spend
// userspace round trips on packets the engine can only fail open on. Reinjected
// packets carry a firewall mark and are accepted before the queue rule, which
// prevents the raw-socket reinjection loop. Both queue rules use `bypass`, so if
// the sidecar dies the kernel accepts the packets instead of dropping them: a
// crashed sidecar fails open and the proxy keeps serving.
package nftables

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Config describes the steering rules to program.
type Config struct {
	// Table is the dedicated nftables table name (family inet).
	Table string
	// Port is the proxy's TCP listening port. Egress is matched by source port,
	// ingress by destination port.
	Port uint16
	// Outbound and Inbound narrow each direction to the packets the loaded
	// strategy can act on. A zero Selector steers nothing in that direction.
	Outbound Selector
	Inbound  Selector
	// OutQueue receives egress (outbound) packets; InQueue receives ingress.
	OutQueue uint16
	InQueue  uint16
	// Mark is the firewall mark set on reinjected packets so they bypass the
	// queue rather than being re-queued forever.
	Mark uint32
	// NFTPath is the nft binary to invoke (default "nft").
	NFTPath string
}

// Selector narrows a direction's steering to the packets a strategy can match.
//
// It is derived from the strategy's triggers (see internal/steering), not
// configured by hand: Any means "the strategy has a trigger nftables cannot
// express, queue everything", a non-empty Flags means "queue only these flag
// combinations", and the zero value means "this direction can match nothing, so
// steer none of it".
type Selector struct {
	Any   bool
	Flags []FlagMatch
}

// Empty reports whether this direction needs no rule at all.
func (s Selector) Empty() bool { return !s.Any && len(s.Flags) == 0 }

// FlagMatch matches the packets for which `tcp flags & Mask == Value`.
type FlagMatch struct {
	Mask  uint8
	Value uint8
}

// nftFlagNames are the bits of the TCP flags byte in nftables' spelling.
var nftFlagNames = []struct {
	bit  uint8
	name string
}{
	{0x01, "fin"},
	{0x02, "syn"},
	{0x04, "rst"},
	{0x08, "psh"},
	{0x10, "ack"},
	{0x20, "urg"},
	{0x40, "ecn"},
	{0x80, "cwr"},
}

// flagExpr renders one FlagMatch as an nftables match expression.
func flagExpr(m FlagMatch) string {
	if m.Mask == 0xff {
		// Equality over the whole byte: nft compares the masked value against
		// the named set, and an empty set is spelled "0x0".
		return fmt.Sprintf("tcp flags & 0xff == %s", flagNames(m.Value))
	}
	return fmt.Sprintf("tcp flags & %s == %s", flagNames(m.Mask), flagNames(m.Value))
}

// flagNames spells a flags bitmask the way nft accepts it on both sides of a
// comparison: a pipe-joined list of flag names, or a literal for the empty set.
func flagNames(bits uint8) string {
	if bits == 0 {
		return "0x0"
	}
	var names []string
	for _, f := range nftFlagNames {
		if bits&f.bit != 0 {
			names = append(names, f.name)
		}
	}
	return strings.Join(names, "|")
}

// Manager owns the lifecycle of the steering table.
type Manager struct {
	cfg Config
}

// New returns a Manager for cfg, filling in defaults.
func New(cfg Config) *Manager {
	if cfg.Table == "" {
		cfg.Table = "geneva_server"
	}
	if cfg.NFTPath == "" {
		cfg.NFTPath = "nft"
	}
	return &Manager{cfg: cfg}
}

// Ruleset returns the nft script that Install applies. Exposed so the exact
// rules can be inspected and asserted in tests without touching the kernel.
//
// A direction with an empty Selector contributes no queue rule. When both are
// empty the ruleset is empty too, and Install removes the table instead of
// programming one.
func (m *Manager) Ruleset() string {
	if m.Idle() {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", m.cfg.Table)
	// Egress (outbound): the proxy sends from Port toward the client/censor.
	fmt.Fprintf(&b, "\tchain output {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook output priority 0; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark %#x accept\n", m.cfg.Mark)
	for _, rule := range queueRules(m.cfg.Outbound, "sport", m.cfg.Port, m.cfg.OutQueue) {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	fmt.Fprintf(&b, "\t}\n")
	// Ingress (inbound): packets arriving for the proxy's Port.
	fmt.Fprintf(&b, "\tchain input {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook input priority 0; policy accept;\n")
	for _, rule := range queueRules(m.cfg.Inbound, "dport", m.cfg.Port, m.cfg.InQueue) {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Idle reports whether the configured selectors steer nothing, in which case no
// table should exist at all.
func (m *Manager) Idle() bool {
	return m.cfg.Outbound.Empty() && m.cfg.Inbound.Empty()
}

// queueRules renders the queue rules for one direction: one per flag match, or
// a single unconditional rule when the selector is Any.
func queueRules(sel Selector, portKeyword string, port, queue uint16) []string {
	base := fmt.Sprintf("meta nfproto ipv4 meta l4proto tcp tcp %s %d", portKeyword, port)
	verdict := fmt.Sprintf("queue num %d bypass", queue)
	switch {
	case sel.Empty():
		return nil
	case sel.Any:
		return []string{fmt.Sprintf("%s %s", base, verdict)}
	default:
		rules := make([]string, 0, len(sel.Flags))
		for _, f := range sel.Flags {
			rules = append(rules, fmt.Sprintf("%s %s %s", base, flagExpr(f), verdict))
		}
		return rules
	}
}

// Install programs the steering table. Any pre-existing table of the same name
// (left by a prior crash) is removed first, so Install is idempotent and never
// stacks duplicate rules.
func (m *Manager) Install(ctx context.Context) error {
	_ = m.Remove(ctx) // best-effort: clear a stale table from a previous run
	if m.Idle() {
		// Nothing can match, so there is nothing to steer: leaving the table
		// absent is what keeps an unconfigured sidecar off the data path.
		return nil
	}
	if err := m.run(ctx, m.Ruleset()); err != nil {
		return fmt.Errorf("install nftables rules: %w", err)
	}
	return nil
}

// Remove deletes the steering table and everything in it. It is safe to call
// when the table does not exist.
func (m *Manager) Remove(ctx context.Context) error {
	script := fmt.Sprintf("delete table inet %s\n", m.cfg.Table)
	err := m.run(ctx, script)
	if err != nil && isMissingTable(err) {
		return nil
	}
	return err
}

func (m *Manager) run(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, m.cfg.NFTPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s -f -: %w: %s", m.cfg.NFTPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isMissingTable(err error) bool {
	s := err.Error()
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "does not exist")
}
