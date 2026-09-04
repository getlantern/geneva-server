// Package nftables programs and tears down the narrowly scoped netfilter rules
// that steer a proxy's TCP traffic into the NFQUEUE queues.
//
// All rules live in a single dedicated table (`inet geneva_server` by default).
// The whole table is created when steering becomes active and deleted when it
// becomes inactive or the process shuts down, so deleting the table removes
// every chain and rule it owns atomically. The table name is disjoint from any
// other subsystem's.
//
// The steering is scoped to one TCP port in each direction — the proxy's
// listening port — to IPv4, and, when the loaded strategy allows it, to the
// TCP flag combinations that strategy's triggers can actually match. A packet
// no trigger can match is passed through byte-for-byte by the engine, so
// leaving it in the kernel reaches the same result without the round trip; see
// internal/steering. A direction whose forest is empty gets no rule at all,
// which is what makes an unconfigured sidecar free. The table family is `inet`,
// which sees both address families, so queue rules match `meta nfproto ipv4`:
// the engine and the reinjector are IPv4-only, so queueing IPv6 would spend
// userspace round trips on packets the engine can only fail open on. Raw-socket
// reinjections retain the original routing mark and are excluded by the
// dedicated adapter socket's UID, which prevents a reinjection loop without
// changing policy routing. Both queue rules use `bypass`, so if
// the sidecar dies the kernel accepts the packets instead of dropping them: a
// crashed sidecar fails open and the proxy keeps serving.
package nftables

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/generation"
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
	// Generations are the immutable live steering scopes. Queue rules require
	// the generation's conntrack mark, so a widened scope cannot capture an
	// unmarked connection which predates activation.
	Generations []Generation
	// ActiveGeneration is assigned only to unmarked inbound SYNs. Zero stops
	// assigning new connections while retaining rules for draining ones.
	ActiveGeneration uint32
	// NeutralizeNew assigns reserved generation zero without queueing. It is a
	// temporary activation-boundary state used while pre-existing conntracks
	// are marked neutral.
	NeutralizeNew bool
	// Censor adds the inbound classification counters: named counters and a
	// chain that sorts arriving packets into them without queueing any of them.
	// See censorRules.
	Censor bool
	// OutQueue receives egress (outbound) packets; InQueue receives ingress.
	OutQueue uint16
	InQueue  uint16
	// BypassUID owns the adapter's raw socket. Deployment must keep this
	// dedicated service UID distinct from the proxy UID.
	BypassUID uint32
	// NFTPath is the nft binary to invoke (default "nft").
	NFTPath string
}

// Generation is one immutable engine generation's kernel steering scope.
type Generation struct {
	ID       uint32
	Outbound Selector
	Inbound  Selector
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
// A multi-flag list is parenthesized — without the parentheses nft parses the
// bare pipes with its own operator precedence and installs a different match
// than the one written (`flags & syn|ack` becomes `(flags & syn)|ack`).
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
	if len(names) > 1 {
		return "(" + strings.Join(names, "|") + ")"
	}
	return names[0]
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

// Config returns a copy of the effective manager configuration for lifecycle
// verification and diagnostics.
func (m *Manager) Config() Config {
	cfg := m.cfg
	cfg.Generations = append([]Generation(nil), cfg.Generations...)
	return cfg
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
	gens := m.generations()
	// Egress (outbound): the proxy sends from Port toward the client/censor.
	fmt.Fprintf(&b, "\tchain output {\n")
	// A route-type output chain is used because routing marks may be set by the
	// proxy socket. Raw fan-out packets retain their exact original mark and skip
	// enqueue by their dedicated socket UID.
	fmt.Fprintf(&b, "\t\ttype route hook output priority mangle; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta skuid %d accept\n", m.cfg.BypassUID)
	for _, gen := range gens {
		for _, rule := range generationQueueRules(gen, gen.Outbound, "sport", m.cfg.Port, m.cfg.OutQueue) {
			fmt.Fprintf(&b, "\t\t%s\n", rule)
		}
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
	activeGeneration := m.cfg.ActiveGeneration
	if activeGeneration == 0 && !m.cfg.NeutralizeNew && len(m.cfg.Generations) == 0 &&
		(!m.cfg.Outbound.Empty() || !m.cfg.Inbound.Empty()) {
		activeGeneration = 1
	}
	if activeGeneration != 0 || m.cfg.NeutralizeNew {
		mark := generation.Namespace
		if activeGeneration != 0 {
			mark, _ = generation.Mark(activeGeneration)
		}
		// Only an original inbound SYN creates the affinity. Retransmits retain
		// their existing connmark, and the low 12 bits are left to other mark users.
		fmt.Fprintf(&b, "\t\tmeta nfproto ipv4 meta l4proto tcp tcp dport %d ct state new tcp flags & (syn|ack) == syn ct mark & %#x == 0 ct mark set (ct mark & %#x) | %#x\n",
			m.cfg.Port, generation.Mask, ^generation.Mask, mark)
	}
	for _, gen := range gens {
		for _, rule := range generationQueueRules(gen, gen.Inbound, "dport", m.cfg.Port, m.cfg.InQueue) {
			fmt.Fprintf(&b, "\t\t%s\n", rule)
		}
	}
	fmt.Fprintf(&b, "\t}\n")
	// This inert regular chain fingerprints the complete desired configuration.
	// Seeing it on readback proves the whole atomic replacement committed.
	fmt.Fprintf(&b, "\tchain %s {}\n", m.revisionChain())
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

func (m *Manager) revisionChain() string {
	b, err := json.Marshal(m.cfg)
	if err != nil {
		panic(fmt.Sprintf("marshal nftables configuration: %v", err))
	}
	sum := sha256.Sum256(b)
	return "geneva_config_" + hex.EncodeToString(sum[:8])
}

// Idle reports whether the configured selectors steer nothing, in which case no
// table should exist at all.
//
// The censor counters do not make a table non-idle. They ride along with a table
// that exists for steering; they never keep one alive on their own, because a
// box with no strategy is supposed to have nothing of ours in the kernel at all.
func (m *Manager) Idle() bool {
	if m.cfg.NeutralizeNew {
		return false
	}
	for _, gen := range m.generations() {
		if !gen.Outbound.Empty() || !gen.Inbound.Empty() {
			return false
		}
	}
	return m.cfg.ActiveGeneration == 0
}

func (m *Manager) generations() []Generation {
	if len(m.cfg.Generations) != 0 {
		return m.cfg.Generations
	}
	if m.cfg.Outbound.Empty() && m.cfg.Inbound.Empty() {
		return nil
	}
	return []Generation{{ID: 1, Outbound: m.cfg.Outbound, Inbound: m.cfg.Inbound}}
}

func generationQueueRules(gen Generation, sel Selector, portKeyword string, port, queue uint16) []string {
	mark, err := generation.Mark(gen.ID)
	if err != nil || sel.Empty() {
		return nil
	}
	base := fmt.Sprintf("meta nfproto ipv4 meta l4proto tcp tcp %s %d ct mark & %#x == %#x", portKeyword, port, generation.Mask, mark)
	// NFQA_CFG_F_CONNTRACK carries CTA_MARK alongside the packet. The skb mark is
	// never changed for dispatch, so exact routing marks survive accept, bypass,
	// queue-full fail-open, modified verdicts and raw reinjection.
	verdict := fmt.Sprintf("queue num %d bypass", queue)
	switch {
	case sel.Any:
		return []string{base + " " + verdict}
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
	script, err := m.replaceScript(ctx)
	if err != nil {
		return err
	}
	if script == "" {
		return nil
	}
	if err := m.run(ctx, script); err != nil {
		return fmt.Errorf("install nftables rules: %w", err)
	}
	return nil
}

// VerifyInstalled reads the table back and checks its inert configuration
// fingerprint. This makes command timeouts retry-safe: nft replacement is
// atomic, and the fingerprint covers the complete desired configuration.
func (m *Manager) VerifyInstalled(ctx context.Context) error {
	if m.Idle() {
		present, err := m.exists(ctx)
		if err != nil {
			return err
		}
		if present {
			return errors.New("inactive Geneva table still exists")
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, m.cfg.NFTPath, "list", "table", "inet", m.cfg.Table)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("read back nftables rules: %w: %s", err, strings.TrimSpace(string(out)))
	}
	want := "chain " + m.revisionChain()
	if !strings.Contains(string(out), want) {
		return fmt.Errorf("nftables readback lacks desired transaction fingerprint %s", m.revisionChain())
	}
	return nil
}

// InstallVerified installs one atomic replacement and verifies it. If the
// request context expires after the kernel commits, an independent bounded
// readback resolves the otherwise ambiguous result.
func (m *Manager) InstallVerified(ctx context.Context) error {
	installErr := m.Install(ctx)
	if installErr == nil {
		if verifyErr := m.VerifyInstalled(ctx); verifyErr == nil {
			return nil
		} else {
			installErr = fmt.Errorf("verify installed nftables transaction: %w", verifyErr)
		}
	}
	reconcileCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if verifyErr := m.VerifyInstalled(reconcileCtx); verifyErr == nil {
		return nil
	} else {
		return errors.Join(installErr, fmt.Errorf("reconcile ambiguous nftables transaction: %w", verifyErr))
	}
}

// Verify asks nft to validate the exact atomic replacement transaction without
// changing kernel state. Activation calls this before staging a generation.
func (m *Manager) Verify(ctx context.Context) error {
	script, err := m.replaceScript(ctx)
	if err != nil || script == "" {
		return err
	}
	if err := m.runArgs(ctx, script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("verify nftables rules: %w", err)
	}
	return nil
}

func (m *Manager) replaceScript(ctx context.Context) (string, error) {
	present, err := m.exists(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if present {
		fmt.Fprintf(&b, "delete table inet %s\n", m.cfg.Table)
	}
	b.WriteString(m.Ruleset())
	return b.String(), nil
}

func (m *Manager) exists(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, m.cfg.NFTPath, "list", "table", "inet", m.cfg.Table)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return true, nil
	}
	wrapped := fmt.Errorf("%s list table: %w: %s", m.cfg.NFTPath, err, strings.TrimSpace(string(out)))
	if isMissingTable(wrapped) {
		return false, nil
	}
	return false, wrapped
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
	return m.runArgs(ctx, script, "-f", "-")
}

func (m *Manager) runArgs(ctx context.Context, script string, args ...string) error {
	cmd := exec.CommandContext(ctx, m.cfg.NFTPath, args...)
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
