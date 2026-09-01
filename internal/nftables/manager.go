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

	"github.com/getlantern/geneva-server/internal/censor"
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
	// Censor adds the inbound classification counters: named counters and a
	// chain that sorts arriving packets into them without queueing any of them.
	// See censorRules.
	Censor bool
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

// CensorCounters are the named nftables counters the classification chain sorts
// inbound packets into. The names are the censor event names — derived from the
// censor package's own list rather than respelled here, so nothing has to
// translate between the kernel's view and the metric's and the two cannot
// drift apart.
//
// Counters live in the sidecar's own table, so these names cannot collide with
// anything else on the box.
var CensorCounters = func() []string {
	names := make([]string, len(censor.KernelEvents))
	for i, e := range censor.KernelEvents {
		names[i] = e.String()
	}
	return names
}()

// censorDataMinLength is the packet length above which an inbound TCP packet is
// counted as carrying data.
//
// nftables cannot subtract one header field from another, so "has a payload"
// cannot be expressed exactly — it would be
// `ip length - ihl*4 - dataoffset*4 > 0`. A pure ACK is 40 bytes of headers
// plus options, and 32 bytes of options (timestamps, SACK) is the realistic
// worst case, so anything above 80 bytes carries payload. The failure mode is a
// data segment with fewer than ~28 payload bytes counting as ack_only, which
// does not happen in proxy traffic: a TLS record is far larger.
const censorDataMinLength = 80

// censorRules renders the classification chain. Order is precedence, and each
// rule returns, so every packet lands in exactly one counter — the same
// property the userspace classifier has, and what makes a ratio between two
// counters mean what it appears to mean.
//
// Two of the userspace classifier's buckets have no kernel equivalent and stay
// at zero here. `undecodable` is a decode failure, which cannot happen to a
// packet nobody decodes. `fragment` would need a rule with no port match, since
// a non-initial fragment carries no TCP header to match a port against, and
// counting every fragment on the box for every port is worse than not counting
// it.
func censorRules() []string {
	return []string{
		"chain " + censorChain + " {",
		"\t\ttcp flags & rst == rst counter name \"rst\" return",
		// A listening port never receives a SYN-ACK, so an inbound SYN without
		// ACK is a client opening a connection.
		"\t\ttcp flags & (syn|ack) == syn counter name \"syn\" return",
		"\t\ttcp flags & fin == fin counter name \"fin\" return",
		fmt.Sprintf("\t\tmeta length > %d counter name \"data\" return", censorDataMinLength),
		"\t\tcounter name \"ack_only\" return",
		"\t}",
	}
}

// censorChain is the regular (non-base) chain the input chain jumps into.
const censorChain = "censor_in"

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
	if m.cfg.Censor {
		for _, c := range CensorCounters {
			fmt.Fprintf(&b, "\tcounter %s {}\n", c)
		}
		for _, line := range censorRules() {
			fmt.Fprintf(&b, "\t%s\n", line)
		}
	}
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
	if m.cfg.Censor {
		// Counted before anything else in the chain, so the counts describe what
		// arrived rather than what survived the strategy. Counting changes no
		// verdict: the chain returns without one.
		fmt.Fprintf(&b, "\t\tmeta nfproto ipv4 meta l4proto tcp tcp dport %d jump %s\n", m.cfg.Port, censorChain)
	}
	for _, rule := range queueRules(m.cfg.Inbound, "dport", m.cfg.Port, m.cfg.InQueue) {
		fmt.Fprintf(&b, "\t\t%s\n", rule)
	}
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Idle reports whether the configured selectors steer nothing, in which case no
// table should exist at all.
//
// The censor counters do not make a table non-idle. They ride along with a table
// that exists for steering; they never keep one alive on their own, because a
// box with no strategy is supposed to have nothing of ours in the kernel at all.
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

func isMissingTable(err error) bool { return missingTableMessage(err.Error()) }

// missingTableMessage reports whether an nft error message means "no such
// table". Shared by the two call paths that see the message differently: run
// wraps CombinedOutput into the error string, ReadCounters gets it on
// ExitError.Stderr.
func missingTableMessage(s string) bool {
	return strings.Contains(s, "No such file or directory") || strings.Contains(s, "does not exist")
}
