// Command geneva-server is the privileged NFQUEUE sidecar. It steers a proxy's
// TCP traffic through a Geneva strategy at the outer IPv4/TCP packet layer,
// without ever touching the encrypted payload.
//
// It runs in one of two modes:
//
//   - prod: the assigned strategy on a fleet box.
//   - eval: a candidate strategy on a dedicated test box, with a per-market
//     canary that captures real header field values for the GA brain.
//
// Both modes support immutable, identity-based lifecycle updates. The raw-DNA
// compatibility API is available only behind an explicit legacy flag.
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/generation"
)

var (
	version = "dev"
	commit  = "none"
)

// markFlag parses a firewall mark from decimal or 0x-prefixed hex.
type markFlag uint32

func (m *markFlag) UnmarshalText(b []byte) error {
	// Accept only decimal and 0x/0X-prefixed hex, per the documented format. Base 0 would
	// also accept octal ("010") and binary ("0b10"), which we deliberately reject.
	s := string(b)
	base := 10
	if len(s) > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X') {
		base = 16
		s = s[2:]
	}
	v, err := strconv.ParseUint(s, base, 32)
	if err != nil {
		return fmt.Errorf("invalid mark %q: %w", string(b), err)
	}
	*m = markFlag(v)
	return nil
}

// runCmd holds the flags for the run subcommand.
type runCmd struct {
	Mode                      string   `arg:"--mode" default:"prod" help:"operating mode: prod or eval"`
	Strategy                  string   `arg:"--strategy" help:"legacy opt-in initial Geneva DNA; normal production starts inactive and uses the v1 lifecycle"`
	StrategyFile              string   `arg:"--strategy-file" help:"path to a file containing the strategy DNA"`
	LegacyStrategyAPI         bool     `arg:"--legacy-strategy-api" help:"enable raw-DNA /strategy compatibility mode instead of the authoritative v1 adapter"`
	Port                      uint16   `arg:"--port,required" help:"proxy TCP port to steer"`
	OutQueue                  uint16   `arg:"--out-queue" default:"100" help:"NFQUEUE number for egress (outbound) packets"`
	InQueue                   uint16   `arg:"--in-queue" default:"101" help:"NFQUEUE number for ingress (inbound) packets"`
	QueueMaxLen               uint32   `arg:"--queue-max-len" default:"65535" help:"maximum packets waiting in each NFQUEUE; overload is kernel fail-open"`
	Mark                      markFlag `arg:"--mark" default:"0x67656e" help:"deprecated compatibility flag; reinjection now preserves the packet's exact routing mark"`
	ReinjectBypassUID         int64    `arg:"--reinject-bypass-uid" default:"-1" help:"dedicated Geneva socket UID excluded before output queueing"`
	GenerationMarkNamespace   markFlag `arg:"--generation-mark-namespace" default:"0x67000000" help:"must acknowledge the fleet-reserved Geneva conntrack namespace 0x67000000/0xfffff000"`
	Table                     string   `arg:"--table" default:"geneva_server" help:"dedicated nftables table name"`
	ControlAddr               string   `arg:"--control-addr" default:"127.0.0.1:8092" help:"address for the control/health HTTP surface"`
	Market                    string   `arg:"--market" default:"unknown" help:"market label for the eval-mode canary pool"`
	CanaryCapacity            int      `arg:"--canary-capacity" default:"64" help:"distinct values captured per field in eval mode"`
	NFTPath                   string   `arg:"--nft" default:"nft" help:"path to the nft binary"`
	NoNFT                     bool     `arg:"--no-nft" help:"unsupported with versioned lifecycle; retained only to reject obsolete configurations clearly"`
	CensorCounters            bool     `arg:"--censor-counters" default:"true" help:"classify inbound packets with nftables counters, so the censor-reachability signal does not depend on steering inbound through userspace"`
	ObserveInbound            bool     `arg:"--observe-inbound" help:"eval mode only: keep inbound packets flowing through userspace for the censor-reachability signal, at a round trip per inbound packet"`
	Iface                     string   `arg:"--iface" help:"steered interface; required in prod so controller-owned NIC offloads are durably restorable"`
	EthtoolPath               string   `arg:"--ethtool" default:"ethtool" help:"path to the ethtool binary (used with --iface)"`
	PprofAddr                 string   `arg:"--pprof-addr" help:"debug only: serve net/http/pprof on this address; never enable on a box carrying client traffic"`
	AdapterStateFile          string   `arg:"--adapter-state-file" default:"/var/lib/geneva-server/adapter-state.json" help:"durable local state for reconstructing live connection generations after restart"`
	MaxGenerations            int      `arg:"--max-generations" default:"3" help:"maximum prepared/live immutable engine generations"`
	MaxScopedGenerations      int      `arg:"--max-scoped-generations" help:"maximum handshake-scoped generations within the total generation budget (default: min(3, total))"`
	MaxEveryPacketGenerations int      `arg:"--max-every-packet-generations" help:"maximum every-packet generations within the total generation budget (default: min(2, total))"`
}

// validateCmd holds the flags for the validate subcommand.
type validateCmd struct {
	Strategy string `arg:"positional" help:"Geneva strategy DNA to validate"`
	File     string `arg:"--file" help:"read the strategy DNA from a file"`
}

type cli struct {
	Run      *runCmd      `arg:"subcommand:run" help:"program nftables, drive the NFQUEUE runtime, serve control/health"`
	Validate *validateCmd `arg:"subcommand:validate" help:"parse and validate a Geneva strategy DNA"`
}

func (cli) Description() string {
	return "geneva-server — Geneva NFQUEUE sidecar for server-side packet manipulation"
}

func (cli) Version() string {
	return fmt.Sprintf("geneva-server %s (%s)", version, commit)
}

var args cli

func main() {
	p := arg.MustParse(&args)
	var err error
	switch {
	case args.Run != nil:
		err = runCommand(args.Run)
	case args.Validate != nil:
		err = validateCommand(args.Validate)
	default:
		p.WriteUsage(os.Stdout)
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runCommand(o *runCmd) error {
	if _, err := o.resolveStrategy(); err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	return runServer(o)
}

// validateCommand checks a strategy DNA and returns an error if it is invalid.
// The GA pre-screen and CI use it to gate proposals before deployment. It parses
// and validates only — no privileges required — so it runs on any platform.
func validateCommand(v *validateCmd) error {
	var dna string
	switch {
	case v.File != "":
		b, err := os.ReadFile(v.File)
		if err != nil {
			return fmt.Errorf("read strategy file: %w", err)
		}
		dna = strings.TrimSpace(string(b))
	case v.Strategy != "":
		dna = strings.TrimSpace(v.Strategy)
	default:
		return fmt.Errorf("provide a strategy as an argument or via --file")
	}
	if _, err := engine.New(dna); err != nil {
		return err
	}
	fmt.Println("strategy is valid")
	return nil
}

// resolveStrategy returns the legacy opt-in initial DNA. Normal production
// starts inactive and is activated only by durable versioned adapter intent.
func (o *runCmd) resolveStrategy() (string, error) {
	if o.Strategy != "" && o.StrategyFile != "" {
		return "", fmt.Errorf("--strategy and --strategy-file are mutually exclusive")
	}
	dna := strings.TrimSpace(o.Strategy)
	if o.StrategyFile != "" {
		b, err := os.ReadFile(o.StrategyFile)
		if err != nil {
			return "", fmt.Errorf("read strategy file: %w", err)
		}
		// Tolerate a trailing newline in an operator-managed file.
		dna = strings.TrimSpace(string(b))
	}
	return dna, nil
}

func (o *runCmd) validate() error {
	if o.Mode != "prod" && o.Mode != "eval" {
		return fmt.Errorf("invalid --mode %q (want prod or eval)", o.Mode)
	}
	if o.ObserveInbound && o.Mode == "prod" {
		// Refused rather than warned about, because the cost lands on real
		// users and the benefit does not need their traffic.
		//
		// Observing inbound means a userspace round trip for every inbound
		// packet, whether or not the strategy can act on one. Measured on a
		// 1-vCPU box: free where clients download (the inbound direction is
		// only stretch-ACKs) but -40% where they upload, and a prod box does
		// not get to choose which its users do. What it buys is the
		// censor-reachability signal, which is an inference from a
		// SYN-to-data ratio — and an eval box, which carries no client
		// traffic, produces that same signal for nothing.
		//
		// A prod box that genuinely needs inbound packets in userspace has a
		// precise way to ask: give its strategy an inbound tree. Steering then
		// follows the strategy, and the packets are queued because something
		// actually acts on them rather than because a flag was set. An inbound
		// pass-through tree is spelled `\/ [TCP:flags:A*]-send-|`.
		return fmt.Errorf("--observe-inbound is not available in prod mode: it costs a userspace round trip " +
			"per inbound packet (measured up to -40%% on upload-heavy traffic) for a signal an eval box " +
			"provides for free; to steer inbound on a prod box, give the strategy an inbound tree")
	}
	if o.OutQueue == o.InQueue {
		return fmt.Errorf("--out-queue and --in-queue must differ")
	}
	if o.QueueMaxLen == 0 {
		o.QueueMaxLen = 65535
	}
	if o.ReinjectBypassUID < -1 || o.ReinjectBypassUID > int64(^uint32(0)) {
		return fmt.Errorf("--reinject-bypass-uid must fit an unsigned 32-bit UID")
	}
	if o.NoNFT {
		return fmt.Errorf("--no-nft is incompatible with the transactional versioned lifecycle; an external programmer/readback adapter is not implemented")
	}
	if o.ReinjectBypassUID == -1 {
		o.ReinjectBypassUID = int64(os.Geteuid())
	}
	if o.GenerationMarkNamespace == 0 {
		o.GenerationMarkNamespace = markFlag(generation.Namespace)
	}
	if uint32(o.GenerationMarkNamespace) != generation.Namespace {
		return fmt.Errorf("--generation-mark-namespace must equal the reserved Geneva namespace %#x (mask %#x)", generation.Namespace, generation.Mask)
	}
	if o.MaxGenerations == 0 {
		o.MaxGenerations = 3
	}
	if o.MaxGenerations < 1 || o.MaxGenerations > int(adapter.MaxLiveGenerationBudget) {
		return fmt.Errorf("--max-generations must be between 1 and %d", adapter.MaxLiveGenerationBudget)
	}
	if o.MaxScopedGenerations == 0 {
		o.MaxScopedGenerations = min(3, o.MaxGenerations)
	}
	if o.MaxScopedGenerations < 1 || o.MaxScopedGenerations > o.MaxGenerations {
		return fmt.Errorf("--max-scoped-generations must be between 1 and --max-generations")
	}
	if o.MaxEveryPacketGenerations == 0 {
		o.MaxEveryPacketGenerations = min(2, o.MaxGenerations)
	}
	if o.MaxEveryPacketGenerations < 1 || o.MaxEveryPacketGenerations > o.MaxGenerations {
		return fmt.Errorf("--max-every-packet-generations must be between 1 and --max-generations")
	}
	if o.Mode == "prod" && strings.TrimSpace(o.Iface) == "" {
		return errors.New("prod mode requires --iface so NIC offload ownership is durable and restorable")
	}
	if !o.LegacyStrategyAPI && (o.Strategy != "" || o.StrategyFile != "") {
		return errors.New("--strategy/--strategy-file require --legacy-strategy-api and cannot be combined with authoritative v1 lifecycle mode")
	}
	if o.Mode == "prod" && !o.LegacyStrategyAPI && strings.TrimSpace(o.AdapterStateFile) == "" {
		return errors.New("authoritative prod mode requires --adapter-state-file for durable generation reconstruction and rollback continuity")
	}
	return nil
}
