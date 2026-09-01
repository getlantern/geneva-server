//go:build linux

package steering

import (
	"context"
	"fmt"
	"sync"

	"github.com/getlantern/geneva"

	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/netdev"
	"github.com/getlantern/geneva-server/internal/nftables"
)

// Logger is the minimal logging surface the controller needs.
type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// Config describes the box the controller steers on.
type Config struct {
	// Mode is GenevaModeProd or GenevaModeEval, spelled as the flag spells it.
	// The controller needs it because one behaviour is mode-gated: see
	// ObserveInbound.
	Mode        string
	Table       string
	Port        uint16
	OutQueue    uint16
	InQueue     uint16
	Mark        uint32
	NFTPath     string
	EthtoolPath string
	// Iface is the interface whose offloads are torn down while steering is
	// active. Empty leaves the NIC alone, which is only correct where something
	// else guarantees MTU-sized, checksummed packets (a test harness).
	Iface string
	// NoNFT skips programming the kernel entirely, for a box where the rules are
	// managed out of band.
	NoNFT bool
	// CensorCounters adds nftables classification counters to the table
	// whenever one exists, so the censor-reachability signal survives steering
	// being scoped to what the strategy can act on. They classify in the kernel
	// and cost no userspace round trip; nothing is queued for them.
	CensorCounters bool
	// ObserveInbound keeps every inbound packet flowing through userspace while
	// a strategy is loaded, even when that strategy's triggers cannot act on
	// inbound traffic at all. Honoured in eval mode only.
	//
	// It buys the censor-reachability signal (internal/censor), whose
	// inbound-SYN-to-inbound-data ratio is the only estimate we have of a box's
	// IP being burned. What it costs is one round trip per inbound packet,
	// which makes it almost free or very expensive depending on which way the
	// box's bulk traffic runs: measured on a 1-vCPU box, a download-heavy
	// workload lost nothing at all (its inbound direction is stretch-ACKs, one
	// packet per ~33 outbound), while an upload-heavy one lost 40%. Off by
	// default for that reason; deploy/README.md has the numbers.
	ObserveInbound bool
}

// Controller owns the relationship between the loaded strategy and the kernel:
// it installs steering only for the packets the strategy can act on, and takes
// the box off the data path entirely when it can act on nothing.
//
// This is the piece that makes an unconfigured sidecar free. An eval box boots
// with no strategy and a prod box can be rolled back to none, and in both cases
// the right answer is not "queue everything and pass it through" — it is no
// queue at all.
type Controller struct {
	cfg Config
	eng *engine.Engine
	log Logger

	// mu serializes reconciles. A strategy swap is a control-plane event
	// measured in seconds, so a mutex costs nothing and keeps the kernel state,
	// the offload state and the engine's strategy from interleaving.
	mu       sync.Mutex
	scope    Scope
	nft      *nftables.Manager
	offloads *netdev.Disabled
}

// New returns a controller for eng. Nothing is programmed until Apply runs.
func New(eng *engine.Engine, cfg Config, log Logger) *Controller {
	if log == nil {
		log = nopLogger{}
	}
	return &Controller{cfg: cfg, eng: eng, log: log}
}

// DNA returns the currently installed strategy.
func (c *Controller) DNA() string { return c.eng.DNA() }

// Scope returns what the current strategy can act on, for the health surface.
func (c *Controller) Scope() Scope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.scope
}

// State is the health surface's view of what the box is actually steering.
type State struct {
	// Steering is false when no rule is installed, i.e. the sidecar is running
	// but not on the data path.
	Steering bool `json:"steering"`
	// Outbound and Inbound describe each direction: "none", "all", or the flag
	// matches being queued.
	Outbound string `json:"outbound"`
	Inbound  string `json:"inbound"`
	// OffloadsDisabled reports whether the NIC is currently de-offloaded.
	OffloadsDisabled bool `json:"offloads_disabled"`
}

// State snapshots the controller for /healthz.
func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return State{
		Steering:         !c.scope.Idle(),
		Outbound:         describe(c.scope.Outbound),
		Inbound:          describe(c.scope.Inbound),
		OffloadsDisabled: c.offloads != nil,
	}
}

// Start brings the kernel in line with the strategy the engine already holds.
//
// It exists separately from Apply because the initial strategy is loaded by
// engine.New: re-installing it here would count as a hot swap in the metrics,
// and `geneva.strategy_swaps` is the signal a rollout landed. Start therefore
// programs the kernel and records the scope without touching the engine.
func (c *Controller) Start(ctx context.Context) error {
	dna := c.eng.DNA()
	parsed, err := geneva.NewStrategy(dna)
	if err != nil {
		return fmt.Errorf("parse strategy: %w", err)
	}
	desired := c.widen(Of(parsed))

	c.mu.Lock()
	defer c.mu.Unlock()
	if desired.Idle() {
		// Program the idle scope rather than just recording it: an unclean exit
		// (SIGKILL, an OOM, a crash) leaves the table behind, and a table with a
		// reader attached is not the harmless orphan a table without one is —
		// the runtime is about to open its queues, and those stale rules would
		// put a box with no strategy right back on the data path.
		if err := c.program(ctx, desired); err != nil {
			return err
		}
		c.scope = desired
		c.log.Infof("no steering installed: strategy can match nothing; box is off the data path")
		return nil
	}
	if err := c.ensureOffloadsDown(ctx); err != nil {
		return err
	}
	if err := c.program(ctx, desired); err != nil {
		// The offloads are already down and the caller registers no teardown
		// for a Start that failed, so put the NIC back here or it stays
		// de-offloaded until the box is rebuilt.
		c.restoreOffloads(ctx)
		return err
	}
	c.scope = desired
	c.log.Infof("steering installed: outbound=%s inbound=%s",
		describe(desired.Outbound), describe(desired.Inbound))
	return nil
}

// Apply parses dna, brings the kernel in line with what it can act on, and
// installs it in the engine.
//
// Ordering is deliberate and each step is a correctness requirement rather than
// tidiness:
//
//   - Offloads come down before any rule goes up. NFQUEUE delivers packets from
//     a point where segmentation is still pending, so a queue that opens while
//     GSO is on hands the engine super-segments that cannot be reinjected.
//   - Rules are programmed before the engine swaps. Both the old and the new
//     strategy are valid, so whichever runs during the swap window is fine;
//     what must not happen is packets arriving for a strategy that has not
//     loaded, or a strategy loading with nothing to feed it.
//   - Offloads go back up only after the rules are gone, and only when nothing
//     is being steered any more.
func (c *Controller) Apply(ctx context.Context, dna string) error {
	parsed, err := geneva.NewStrategy(dna)
	if err != nil {
		return fmt.Errorf("parse strategy: %w", err)
	}
	if err := geneva.Validate(parsed); err != nil {
		return fmt.Errorf("validate strategy: %w", err)
	}
	desired := c.widen(Of(parsed))

	c.mu.Lock()
	defer c.mu.Unlock()

	if !desired.Idle() {
		if err := c.ensureOffloadsDown(ctx); err != nil {
			return err
		}
	}
	if err := c.program(ctx, desired); err != nil {
		return err
	}
	if err := c.eng.SetStrategy(dna); err != nil {
		return err
	}
	c.scope = desired
	if desired.Idle() {
		c.restoreOffloads(ctx)
		c.log.Infof("steering removed: strategy can match nothing; box is off the data path")
	} else {
		c.log.Infof("steering installed: outbound=%s inbound=%s",
			describe(desired.Outbound), describe(desired.Inbound))
	}
	return nil
}

// Close removes every rule and restores the NIC. Safe to call more than once.
func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	steering := !c.scope.Idle()
	err := c.program(ctx, Scope{})
	c.scope = Scope{}
	c.restoreOffloads(ctx)
	if err != nil {
		return err
	}
	if steering {
		// Logged unconditionally on the way out: "did the table actually go
		// away" is the first question after any crash loop or rollback, and the
		// journal is where it gets answered.
		c.log.Infof("nftables steering removed")
	}
	return nil
}

// widen applies the observation floor: on an eval box with ObserveInbound set, a
// strategy that is doing anything at all also keeps inbound traffic visible to
// the censor classifier.
//
// Two things it deliberately will not do. An idle strategy is left idle — a box
// with nothing to apply stays off the data path, which is the whole point of
// scoping. And in prod mode the floor is never applied, even if the flag
// somehow arrives set: the cost is a userspace round trip per inbound packet
// (measured free on download-heavy traffic but -40% on upload-heavy, and a prod
// box does not get to choose which its users generate) in exchange for a signal
// an eval box produces for free. main.go refuses the combination at startup;
// this is the second lock, for a Controller built by something other than the
// CLI. A prod box that needs inbound packets in userspace asks precisely, by
// giving its strategy an inbound tree.
func (c *Controller) widen(sc Scope) Scope {
	if !c.cfg.ObserveInbound || c.cfg.Mode != modeEval || sc.Idle() {
		return sc
	}
	sc.Inbound = nftables.Selector{Any: true}
	return sc
}

// modeEval is the eval-mode spelling shared with the CLI and the API. Kept
// local rather than imported so this package does not depend on the command.
const modeEval = "eval"

// program makes the kernel match desired, replacing the table wholesale. An
// idle scope removes it.
func (c *Controller) program(ctx context.Context, desired Scope) error {
	if c.cfg.NoNFT {
		return nil
	}
	c.nft = nftables.New(nftables.Config{
		Table:    c.cfg.Table,
		Port:     c.cfg.Port,
		OutQueue: c.cfg.OutQueue,
		InQueue:  c.cfg.InQueue,
		Mark:     c.cfg.Mark,
		NFTPath:  c.cfg.NFTPath,
		Outbound: desired.Outbound,
		Inbound:  desired.Inbound,
		Censor:   c.cfg.CensorCounters,
	})
	// Install removes any existing table first and programs nothing when the
	// scope is idle, so this one call covers install, replace and remove.
	if err := c.nft.Install(ctx); err != nil {
		return err
	}
	return nil
}

func (c *Controller) ensureOffloadsDown(ctx context.Context) error {
	if c.cfg.Iface == "" || c.offloads != nil {
		return nil
	}
	d, err := netdev.Disable(ctx, c.cfg.EthtoolPath, c.cfg.Iface)
	if err != nil {
		return err
	}
	c.offloads = d
	c.log.Infof("NIC offloads adjusted: iface=%s %s", c.cfg.Iface, d.Summary())
	return nil
}

// restoreOffloads puts the NIC back. A failure is logged, not returned: the
// strategy change itself succeeded, and refusing it because a checksum offload
// would not come back on would be the wrong trade.
func (c *Controller) restoreOffloads(ctx context.Context) {
	if c.offloads == nil {
		return
	}
	if err := c.offloads.Restore(ctx); err != nil {
		c.log.Errorf("restore NIC offloads: %v", err)
	} else {
		c.log.Infof("NIC offloads restored on %s", c.cfg.Iface)
	}
	c.offloads = nil
}

// CensorCounts reads the kernel classification counters. It is the read half of
// Config.CensorCounters, handed to censor.NewKernelSource.
//
// The manager is rebuilt on every program call, so this takes the current one
// under the lock rather than caching a pointer. With no table installed there is
// nothing to read and the counts are empty, which is the correct answer for a
// box that is not steering.
func (c *Controller) CensorCounts(ctx context.Context) (map[string]uint64, error) {
	c.mu.Lock()
	nft := c.nft
	c.mu.Unlock()
	if nft == nil {
		return map[string]uint64{}, nil
	}
	return nft.ReadCounters(ctx)
}

// describe renders a selector for logs and the health surface.
func describe(sel nftables.Selector) string {
	switch {
	case sel.Any:
		return "all"
	case sel.Empty():
		return "none"
	default:
		out := ""
		for i, f := range sel.Flags {
			if i > 0 {
				out += ","
			}
			out += fmt.Sprintf("flags&%#02x==%#02x", f.Mask, f.Value)
		}
		return out
	}
}
