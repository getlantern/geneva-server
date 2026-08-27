// Command geneva-server is the privileged NFQUEUE sidecar. It steers a proxy's
// TCP traffic through a Geneva strategy at the outer IPv4/TCP packet layer,
// without ever touching the encrypted payload.
//
// It runs in one of two modes:
//
//   - prod: applies one fixed strategy assigned to a fleet box. Reload by restart.
//   - eval: applies a candidate strategy on a dedicated test box. The candidate
//     can be replaced at runtime via the control API, and real header field
//     values are captured into a per-market canary pool for the GA brain.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "geneva-server",
		Short:         "Geneva NFQUEUE sidecar for server-side packet manipulation",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       fmt.Sprintf("%s (%s)", version, commit),
	}
	root.AddCommand(runCmd(), validateCmd())
	return root
}

// options are the flags shared by the run command, parsed on any platform so
// the flag surface is stable and testable even where the runtime is not built.
type options struct {
	mode           string
	strategy       string
	strategyFile   string
	port           uint16
	outQueue       uint16
	inQueue        uint16
	mark           uint32
	table          string
	controlAddr    string
	market         string
	canaryCapacity int
	nftPath        string
	noNFT          bool
	iface          string
	ethtoolPath    string
}

func addRunFlags(cmd *cobra.Command, o *options) {
	f := cmd.Flags()
	f.StringVar(&o.mode, "mode", "prod", "operating mode: prod or eval")
	f.StringVar(&o.strategy, "strategy", "", "Geneva strategy DNA (prod: required unless --strategy-file)")
	f.StringVar(&o.strategyFile, "strategy-file", "", "path to a file containing the strategy DNA")
	f.Uint16Var(&o.port, "port", 0, "proxy TCP port to steer (required)")
	f.Uint16Var(&o.outQueue, "out-queue", 100, "NFQUEUE number for egress (outbound) packets")
	f.Uint16Var(&o.inQueue, "in-queue", 101, "NFQUEUE number for ingress (inbound) packets")
	f.Uint32Var(&o.mark, "mark", 0x67656e, "firewall mark for reinjected packets (skips the queue)")
	f.StringVar(&o.table, "table", "geneva_server", "dedicated nftables table name")
	f.StringVar(&o.controlAddr, "control-addr", "127.0.0.1:8092", "address for the control/health HTTP surface")
	f.StringVar(&o.market, "market", "unknown", "market label for the eval-mode canary pool")
	f.IntVar(&o.canaryCapacity, "canary-capacity", 64, "distinct values captured per field in eval mode")
	f.StringVar(&o.nftPath, "nft", "nft", "path to the nft binary")
	f.BoolVar(&o.noNFT, "no-nft", false, "do not program nftables rules (rules managed externally)")
	f.StringVar(&o.iface, "iface", "", "steered interface; NIC offloads are disabled on it so NFQUEUE yields MTU-sized, checksummed packets (strongly recommended)")
	f.StringVar(&o.ethtoolPath, "ethtool", "ethtool", "path to the ethtool binary (used with --iface)")
}

// resolveStrategy returns the DNA from --strategy or --strategy-file. In prod
// mode a strategy is required; eval may start empty (pass-through until assigned).
func (o *options) resolveStrategy() (string, error) {
	if o.strategy != "" && o.strategyFile != "" {
		return "", fmt.Errorf("--strategy and --strategy-file are mutually exclusive")
	}
	if o.strategyFile != "" {
		b, err := os.ReadFile(o.strategyFile)
		if err != nil {
			return "", fmt.Errorf("read strategy file: %w", err)
		}
		// Tolerate a trailing newline in an operator-managed file.
		return strings.TrimSpace(string(b)), nil
	}
	if o.strategy == "" && o.mode == "prod" {
		return "", fmt.Errorf("prod mode requires --strategy or --strategy-file")
	}
	return strings.TrimSpace(o.strategy), nil
}

func (o *options) validate() error {
	if o.mode != "prod" && o.mode != "eval" {
		return fmt.Errorf("invalid --mode %q (want prod or eval)", o.mode)
	}
	if o.port == 0 {
		return fmt.Errorf("--port is required")
	}
	if o.outQueue == o.inQueue {
		return fmt.Errorf("--out-queue and --in-queue must differ")
	}
	return nil
}

// runCmd builds the run command. The heavy lifting is platform-specific
// (runServer is defined only for Linux); the flag surface is shared.
func runCmd() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the sidecar: program nftables, drive the NFQUEUE runtime, serve control/health",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := o.resolveStrategy(); err != nil {
				return err
			}
			if err := o.validate(); err != nil {
				return err
			}
			return runServer(cmd.Context(), o)
		},
	}
	addRunFlags(cmd, o)
	return cmd
}

// validateCmd checks a strategy DNA and exits non-zero if it is invalid. The GA
// pre-screen and CI use it to gate proposals before deployment. It parses and
// validates only — no privileges required — so it runs on any platform.
func validateCmd() *cobra.Command {
	var file string
	cmd := &cobra.Command{
		Use:   "validate [strategy]",
		Short: "Parse and validate a Geneva strategy DNA",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var dna string
			switch {
			case file != "":
				b, err := os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read strategy file: %w", err)
				}
				dna = strings.TrimSpace(string(b))
			case len(args) == 1:
				dna = strings.TrimSpace(args[0])
			default:
				return fmt.Errorf("provide a strategy as an argument or via --file")
			}
			if _, err := engine.New(dna); err != nil {
				return err
			}
			fmt.Println("strategy is valid")
			return nil
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "read the strategy DNA from a file")
	return cmd
}
