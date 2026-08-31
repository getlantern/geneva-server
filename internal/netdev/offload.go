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

// DisableOffload turns off segmentation and checksum offloads on iface.
//
// Individual features that cannot be changed are reported in the returned
// summary rather than as an error: some virtual interfaces expose a subset as
// fixed, and the ones that matter on a given interface are typically
// changeable. Three conditions are hard errors — a missing ethtool, a missing
// interface, and no feature changeable at all — because each of them means
// NFQUEUE would go on receiving GSO/checksum-offloaded packets that cannot be
// reinjected intact.
func DisableOffload(ctx context.Context, ethtoolPath, iface string) (string, error) {
	if ethtoolPath == "" {
		ethtoolPath = "ethtool"
	}
	if _, err := exec.LookPath(ethtoolPath); err != nil {
		return "", fmt.Errorf("ethtool not found (needed to disable NIC offloads on %s): %w", iface, err)
	}
	// A missing interface is a hard error, not a "feature unchanged": otherwise a
	// typo in --iface would silently leave every offload on.
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		return "", fmt.Errorf("interface %q not found: %w", iface, err)
	}
	var ok, skipped []string
	for _, f := range offloadFeatures {
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
		return "", fmt.Errorf("failed to disable any offload on %q (check CAP_NET_ADMIN); attempted: %s",
			iface, strings.Join(offloadFeatures, " "))
	}
	return fmt.Sprintf("disabled=[%s] unchanged=[%s]", strings.Join(ok, " "), strings.Join(skipped, " ")), nil
}
