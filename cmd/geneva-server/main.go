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
// Both modes support replacing the strategy in place via the control API.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/getlantern/geneva-server/internal/engine"
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
	Mode           string   `arg:"--mode" default:"prod" help:"operating mode: prod or eval"`
	Strategy       string   `arg:"--strategy" help:"Geneva strategy DNA (prod: required unless --strategy-file)"`
	StrategyFile   string   `arg:"--strategy-file" help:"path to a file containing the strategy DNA"`
	Port           uint16   `arg:"--port,required" help:"proxy TCP port to steer"`
	OutQueue       uint16   `arg:"--out-queue" default:"100" help:"NFQUEUE number for egress (outbound) packets"`
	InQueue        uint16   `arg:"--in-queue" default:"101" help:"NFQUEUE number for ingress (inbound) packets"`
	Mark           markFlag `arg:"--mark" default:"0x67656e" help:"firewall mark for reinjected packets (skips the queue); decimal or 0x hex"`
	Table          string   `arg:"--table" default:"geneva_server" help:"dedicated nftables table name"`
	ControlAddr    string   `arg:"--control-addr" default:"127.0.0.1:8092" help:"address for the control/health HTTP surface"`
	Market         string   `arg:"--market" default:"unknown" help:"market label for the eval-mode canary pool"`
	CanaryCapacity int      `arg:"--canary-capacity" default:"64" help:"distinct values captured per field in eval mode"`
	NFTPath        string   `arg:"--nft" default:"nft" help:"path to the nft binary"`
	NoNFT          bool     `arg:"--no-nft" help:"do not program nftables rules (rules managed externally)"`
	ObserveInbound bool     `arg:"--observe-inbound" help:"keep inbound packets flowing through userspace while a strategy is loaded, for the censor-reachability signal; costs a userspace round trip per inbound packet"`
	Iface          string   `arg:"--iface" help:"steered interface; NIC offloads are disabled on it so NFQUEUE yields MTU-sized, checksummed packets (strongly recommended)"`
	EthtoolPath    string   `arg:"--ethtool" default:"ethtool" help:"path to the ethtool binary (used with --iface)"`
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

// resolveStrategy returns the DNA from --strategy or --strategy-file. In prod
// mode a strategy is required; eval may start empty (pass-through until assigned).
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
	// Checked against the resolved DNA, not against the flags: an empty
	// strategy file passed --strategy-file used to satisfy the flag check and
	// boot prod in pass-through. That now also means no steering at all, so a
	// truncated file would take a prod box off the data path silently.
	if dna == "" && o.Mode == "prod" {
		return "", fmt.Errorf("prod mode requires a non-empty strategy (--strategy or --strategy-file)")
	}
	return dna, nil
}

func (o *runCmd) validate() error {
	if o.Mode != "prod" && o.Mode != "eval" {
		return fmt.Errorf("invalid --mode %q (want prod or eval)", o.Mode)
	}
	if o.OutQueue == o.InQueue {
		return fmt.Errorf("--out-queue and --in-queue must differ")
	}
	if o.Mark == 0 {
		// Required whether or not this process programs the rules. With internal
		// rules, a zero mark makes the "accept marked packets" rule match every
		// unmarked packet (mark defaults to 0), so the proxy's traffic is
		// accepted before the queue rule and nothing is ever steered. With
		// --no-nft the mark is still what the reinjector stamps via SO_MARK, and
		// it is the only thing an externally managed ruleset can use to tell a
		// reinjected packet from an original one — a zero mark there means
		// reinjected packets are re-queued forever.
		return fmt.Errorf("--mark must be non-zero")
	}
	return nil
}
