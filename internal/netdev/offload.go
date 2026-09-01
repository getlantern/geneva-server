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
	"strings"
)

// offloadFeatures are disabled on the steered interface. Segmentation offloads
// keep packets MTU-sized; checksum/scatter-gather offloads keep checksums real.
var offloadFeatures = []string{"gso", "tso", "gro", "gre", "tx", "rx", "sg", "lro", "ufo"}

// restoreOrder re-enables features in dependency order. Segmentation offloads
// require scatter-gather and tx checksumming, so restoring in the disable order
// makes the kernel reject `tso on` and `gso on` as unsupported and silently
// leaves them off.
var restoreOrder = []string{"sg", "tx", "rx", "gso", "tso", "gro", "gre", "lro", "ufo"}

// ethtoolNames maps the short feature names used with `ethtool -K` to the long
// names `ethtool -k` reports state under. Only the features whose state we need
// to read are listed; anything absent is simply attempted blind.
var ethtoolNames = map[string]string{
	"gso": "generic-segmentation-offload",
	"tso": "tcp-segmentation-offload",
	"gro": "generic-receive-offload",
	"lro": "large-receive-offload",
	"sg":  "scatter-gather",
	"tx":  "tx-checksumming",
	"rx":  "rx-checksumming",
	"ufo": "udp-fragmentation-offload",
}

// readFeatures returns which of the offload features are currently on, keyed by
// short name. A feature the driver reports as "[fixed]" is reported by its
// current value and cannot be changed either way, which is what Disable needs
// to know. Features it cannot determine are simply absent from the map.
func readFeatures(ctx context.Context, ethtoolPath, iface string) map[string]bool {
	out, err := exec.CommandContext(ctx, ethtoolPath, "-k", iface).Output()
	if err != nil {
		return nil
	}
	long := make(map[string]bool, len(ethtoolNames))
	for line := range strings.SplitSeq(string(out), "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		on := strings.HasPrefix(value, "on")
		fixed := strings.Contains(value, "[fixed]")
		// A fixed feature is unchangeable: record its value so Disable skips it
		// when it is already off and Restore never tries to set it.
		if fixed && !on {
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

// Disabled records the features Disable actually turned off on an interface, so
// Restore can put back exactly those and nothing else.
type Disabled struct {
	ethtoolPath string
	iface       string
	features    []string
	skipped     []string
}

// Summary describes what changed, for logging.
func (d *Disabled) Summary() string {
	if d == nil {
		return "unchanged=[all]"
	}
	return fmt.Sprintf("disabled=[%s] unchanged=[%s]",
		strings.Join(d.features, " "), strings.Join(d.skipped, " "))
}

// Restore re-enables the features Disable turned off. Failures are collected
// rather than returned on the first one: a partial restore is better than
// stopping halfway, and the caller logs rather than aborts — the sidecar is on
// its way out by the time this runs.
func (d *Disabled) Restore(ctx context.Context) error {
	if d == nil || len(d.features) == 0 {
		return nil
	}
	want := make(map[string]bool, len(d.features))
	for _, f := range d.features {
		want[f] = true
	}
	var failed []string
	for _, f := range restoreOrder {
		if !want[f] {
			continue
		}
		cmd := exec.CommandContext(ctx, d.ethtoolPath, "-K", d.iface, f, "on")
		if out, err := cmd.CombinedOutput(); err != nil {
			_ = out
			failed = append(failed, f)
		}
	}
	d.features = nil
	if len(failed) > 0 {
		return fmt.Errorf("could not re-enable offloads on %s: %s", d.iface, strings.Join(failed, " "))
	}
	return nil
}

// Disable turns off segmentation and checksum offloads on iface and returns
// what it changed.
//
// Individual features that cannot be changed are reported in the returned
// summary rather than as an error: some virtual interfaces expose a subset as
// fixed, and the ones that matter on a given interface are typically
// changeable. Three conditions are hard errors — a missing ethtool, a missing
// interface, and no feature changeable at all — because each of them means
// NFQUEUE would go on receiving GSO/checksum-offloaded packets that cannot be
// reinjected intact.
func Disable(ctx context.Context, ethtoolPath, iface string) (*Disabled, error) {
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
	state := readFeatures(ctx, ethtoolPath, iface)

	var ok, skipped []string
	for _, f := range offloadFeatures {
		if on, known := state[f]; known && !on {
			skipped = append(skipped, f)
			continue
		}
		cmd := exec.CommandContext(ctx, ethtoolPath, "-K", iface, f, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			// Feature fixed/unsupported on this interface; not fatal on its own.
			_ = out
			skipped = append(skipped, f)
			continue
		}
		ok = append(ok, f)
	}
	// If nothing could be changed at all, something is wrong (permissions, a
	// context cancellation, an interface that rejects every request) — surface it
	// rather than letting NFQUEUE receive GSO/checksum-offloaded packets.
	if len(ok) == 0 {
		return nil, fmt.Errorf("failed to disable any offload on %q (check CAP_NET_ADMIN); attempted: %s",
			iface, strings.Join(offloadFeatures, " "))
	}
	return &Disabled{ethtoolPath: ethtoolPath, iface: iface, features: ok, skipped: skipped}, nil
}
