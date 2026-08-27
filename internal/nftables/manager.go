// Package nftables programs and tears down the narrowly scoped netfilter rules
// that steer a proxy's TCP traffic into the NFQUEUE queues.
//
// All rules live in a single dedicated table (`inet geneva_server` by default).
// The whole table is created on startup and deleted on shutdown, so the runtime
// can never leak a stale rule: deleting the table removes every chain and rule
// it owns atomically, and the table name is disjoint from any other subsystem's.
//
// The steering is scoped to one TCP port in each direction — the proxy's
// listening port — so only that proxy's ingress/egress is diverted. Reinjected
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
	// OutQueue receives egress (outbound) packets; InQueue receives ingress.
	OutQueue uint16
	InQueue  uint16
	// Mark is the firewall mark set on reinjected packets so they bypass the
	// queue rather than being re-queued forever.
	Mark uint32
	// NFTPath is the nft binary to invoke (default "nft").
	NFTPath string
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
func (m *Manager) Ruleset() string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", m.cfg.Table)
	// Egress (outbound): the proxy sends from Port toward the client/censor.
	fmt.Fprintf(&b, "\tchain output {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook output priority 0; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta mark %#x accept\n", m.cfg.Mark)
	fmt.Fprintf(&b, "\t\tmeta l4proto tcp tcp sport %d queue num %d bypass\n", m.cfg.Port, m.cfg.OutQueue)
	fmt.Fprintf(&b, "\t}\n")
	// Ingress (inbound): packets arriving for the proxy's Port.
	fmt.Fprintf(&b, "\tchain input {\n")
	fmt.Fprintf(&b, "\t\ttype filter hook input priority 0; policy accept;\n")
	fmt.Fprintf(&b, "\t\tmeta l4proto tcp tcp dport %d queue num %d bypass\n", m.cfg.Port, m.cfg.InQueue)
	fmt.Fprintf(&b, "\t}\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}

// Install programs the steering table. Any pre-existing table of the same name
// (left by a prior crash) is removed first, so Install is idempotent and never
// stacks duplicate rules.
func (m *Manager) Install(ctx context.Context) error {
	_ = m.Remove(ctx) // best-effort: clear a stale table from a previous run
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
