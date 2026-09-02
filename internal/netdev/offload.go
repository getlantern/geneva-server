//go:build linux

// Package netdev manages NIC offload features on the steered interface.
//
// NFQUEUE delivers packets from the kernel's egress path, where segmentation
// (GSO/TSO) and checksum offload are still pending: a single "packet" can be a
// super-segment far larger than the MTU, and its checksum may be a placeholder
// the NIC would fill in later. Reinjecting such a packet through a raw socket
// fails or puts a corrupt frame on the wire. Disabling these offloads makes
// NFQUEUE hand us real, MTU-sized, fully-checksummed packets — the same thing
// the canonical Geneva engine requires. This is best-effort: some virtual
// interfaces expose a subset of features as fixed, and that is fine.
package netdev

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// offloadFeatures are disabled on the steered interface. Segmentation offloads
// keep packets MTU-sized; checksum/scatter-gather offloads keep checksums real.
var offloadFeatures = []string{"gso", "tso", "gro", "tx-gre-segmentation", "tx", "rx", "sg", "lro", "ufo"}

// restoreOrder re-enables features in dependency order. Segmentation offloads
// require scatter-gather and tx checksumming, so restoring in the disable order
// makes the kernel reject `tso on` and `gso on` as unsupported and silently
// leaves them off.
var restoreOrder = []string{"sg", "tx", "rx", "gso", "tso", "gro", "tx-gre-segmentation", "lro", "ufo"}

// ethtoolNames maps the short feature names used with `ethtool -K` to the long
// names `ethtool -k` reports state under. Only the features whose state we need
// to read are listed; anything absent is simply attempted blind.
var ethtoolNames = map[string]string{
	"gso":                 "generic-segmentation-offload",
	"tso":                 "tcp-segmentation-offload",
	"gro":                 "generic-receive-offload",
	"tx-gre-segmentation": "tx-gre-segmentation",
	"lro":                 "large-receive-offload",
	"sg":                  "scatter-gather",
	"tx":                  "tx-checksumming",
	"rx":                  "rx-checksumming",
	"ufo":                 "udp-fragmentation-offload",
}

// readFeatures returns which of the offload features are currently on, keyed by
// short name. A feature the driver reports as "[fixed]" is reported by its
// current value and cannot be changed either way, which is what Disable needs
// to know. Features it cannot determine are simply absent from the map.
func readFeatures(ctx context.Context, ethtoolPath, iface string) (map[string]bool, error) {
	out, err := exec.CommandContext(ctx, ethtoolPath, "-k", iface).Output()
	if err != nil {
		return nil, fmt.Errorf("read offloads on %s: %w", iface, err)
	}
	return parseFeatureOutput(out), nil
}

func parseFeatureOutput(out []byte) map[string]bool {
	long := make(map[string]bool, len(ethtoolNames))
	for line := range strings.SplitSeq(string(out), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		on := strings.HasPrefix(value, "on")
		fixed := strings.Contains(value, "[fixed]")
		// A fixed feature is unchangeable in either direction. Never claim it as
		// controller-owned even when the driver reports it on: Disable cannot
		// turn it off and Restore must not later pretend that we did.
		if fixed {
			long[name] = false
			continue
		}
		long[name] = on
	}
	state := make(map[string]bool, len(ethtoolNames))
	for short, name := range ethtoolNames {
		if v, ok := long[name]; ok {
			state[short] = v
		}
	}
	return state
}

// Original is the durable set of features which were on before this
// controller touched the interface. Persisting it before mutation lets a
// restarted controller restore exactly its own changes without claiming
// features which an operator had already disabled.
type Original struct {
	Interface string   `json:"interface"`
	Features  []string `json:"features"`
	skipped   []string
}

// Summary describes what changed, for logging.
func (o *Original) Summary() string {
	if o == nil {
		return "unchanged=[all]"
	}
	return fmt.Sprintf("disabled=[%s] unchanged=[%s]",
		strings.Join(o.Features, " "), strings.Join(o.skipped, " "))
}

// Restore re-enables the features owned by the controller. Failures are collected
// rather than returned on the first one: a partial restore is better than
// stopping halfway, and the caller logs rather than aborts — the sidecar is on
// its way out by the time this runs.
func (o *Original) Restore(ctx context.Context, ethtoolPath string) error {
	if o == nil || len(o.Features) == 0 {
		return nil
	}
	if ethtoolPath == "" {
		ethtoolPath = "ethtool"
	}
	want := make(map[string]bool, len(o.Features))
	for _, f := range o.Features {
		want[f] = true
	}
	var failed []string
	for _, f := range restoreOrder {
		if !want[f] {
			continue
		}
		if err := exec.CommandContext(ctx, ethtoolPath, "-K", o.Interface, f, "on").Run(); err != nil {
			failed = append(failed, f)
		}
	}
	o.Features = append(o.Features[:0], failed...)
	if len(failed) > 0 {
		return fmt.Errorf("could not re-enable offloads on %s: %s", o.Interface, strings.Join(failed, " "))
	}
	return nil
}

// Capture records the exact known-on offloads before mutation.
//
// Individual features that cannot be changed are reported in the returned
// summary rather than as an error: some virtual interfaces expose a subset as
// fixed, and the ones that matter on a given interface are typically
// changeable. Three conditions are hard errors — a missing ethtool, a missing
// interface, and no feature changeable at all — because each of them means
// NFQUEUE would go on receiving GSO/checksum-offloaded packets that cannot be
// reinjected intact.
func Capture(ctx context.Context, ethtoolPath, iface string) (*Original, error) {
	if ethtoolPath == "" {
		ethtoolPath = "ethtool"
	}
	if _, err := exec.LookPath(ethtoolPath); err != nil {
		return nil, fmt.Errorf("ethtool not found (needed to disable NIC offloads on %s): %w", iface, err)
	}
	// A missing interface is a hard error, not a "feature unchanged": otherwise a
	// typo in --iface would silently leave every offload on.
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", iface, err)
	}

	// Read the current state first. A feature that is already off, or that the
	// driver reports as fixed, must not be recorded as something we turned off:
	// Restore would then try to switch it back on and fail. veth reports lro
	// exactly that way.
	state, err := readFeatures(ctx, ethtoolPath, iface)
	if err != nil {
		return nil, err
	}

	var on, skipped []string
	for _, f := range offloadFeatures {
		enabled, known := state[f]
		if !known || !enabled {
			skipped = append(skipped, f)
			continue
		}
		on = append(on, f)
	}
	return &Original{Interface: iface, Features: on, skipped: skipped}, nil
}

// Disable applies a captured ownership record. It is idempotent, so startup
// can safely repeat it whether a crash happened before or after the original
// mutation.
func (o *Original) Disable(ctx context.Context, ethtoolPath string) error {
	if o == nil || len(o.Features) == 0 {
		return nil
	}
	if ethtoolPath == "" {
		ethtoolPath = "ethtool"
	}
	var failed []string
	for _, f := range o.Features {
		if !slices.Contains(offloadFeatures, f) {
			return fmt.Errorf("invalid persisted offload feature %q", f)
		}
		if err := exec.CommandContext(ctx, ethtoolPath, "-K", o.Interface, f, "off").Run(); err != nil {
			failed = append(failed, f)
		}
	}
	if len(failed) != 0 {
		return fmt.Errorf("could not disable offloads on %s: %s", o.Interface, strings.Join(failed, " "))
	}
	return nil
}
