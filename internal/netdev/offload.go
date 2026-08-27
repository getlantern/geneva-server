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
	"os/exec"
	"strings"
)

// offloadFeatures are disabled on the steered interface. Segmentation offloads
// keep packets MTU-sized; checksum/scatter-gather offloads keep checksums real.
var offloadFeatures = []string{"gso", "tso", "gro", "gre", "tx", "rx", "sg", "lro", "ufo"}

// DisableOffload turns off segmentation and checksum offloads on iface. It never
// fails the caller: unchangeable features are reported in the returned summary
// but do not produce an error, because the ones that matter on a given
// interface are typically changeable and the rest are already effectively off.
func DisableOffload(ctx context.Context, ethtoolPath, iface string) (string, error) {
	if ethtoolPath == "" {
		ethtoolPath = "ethtool"
	}
	if _, err := exec.LookPath(ethtoolPath); err != nil {
		return "", fmt.Errorf("ethtool not found (needed to disable NIC offloads on %s): %w", iface, err)
	}
	var ok, skipped []string
	for _, f := range offloadFeatures {
		cmd := exec.CommandContext(ctx, ethtoolPath, "-K", iface, f, "off")
		if out, err := cmd.CombinedOutput(); err != nil {
			// Feature fixed/unsupported on this interface; not fatal.
			_ = out
			skipped = append(skipped, f)
			continue
		}
		ok = append(ok, f)
	}
	return fmt.Sprintf("disabled=[%s] unchanged=[%s]", strings.Join(ok, " "), strings.Join(skipped, " ")), nil
}
