package nftables

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
)

// ReadCounters returns the packet counts of the table's named counters, keyed by
// counter name.
//
// The counters are read out of the kernel rather than accumulated in userspace
// because that is the whole point of them: the classification happens in
// nftables, no packet takes a userspace round trip, and this call happens once
// per metric export interval instead of once per packet.
//
// A missing table is not an error — an idle sidecar has no table, and its
// counters simply do not exist yet — so the result is empty in that case.
func (m *Manager) ReadCounters(ctx context.Context) (map[string]uint64, error) {
	cmd := exec.CommandContext(ctx, m.cfg.NFTPath, "-j", "list", "counters", "table", "inet", m.cfg.Table)
	out, err := cmd.Output()
	if err != nil {
		if isMissingTableOutput(err) {
			return map[string]uint64{}, nil
		}
		return nil, fmt.Errorf("%s -j list counters: %w", m.cfg.NFTPath, err)
	}
	return parseCounters(out)
}

// counterList is the shape of `nft -j list counters`: a list of objects, each
// carrying at most one of the keys we care about.
type counterList struct {
	Nftables []struct {
		Counter *struct {
			Name    string `json:"name"`
			Packets uint64 `json:"packets"`
		} `json:"counter"`
	} `json:"nftables"`
}

func parseCounters(out []byte) (map[string]uint64, error) {
	var list counterList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse nft counter json: %w", err)
	}
	counts := make(map[string]uint64, len(list.Nftables))
	for _, entry := range list.Nftables {
		if entry.Counter == nil {
			continue // metainfo and anything else nft chooses to emit
		}
		counts[entry.Counter.Name] = entry.Counter.Packets
	}
	return counts, nil
}

// isMissingTableOutput reports whether an nft failure was "no such table". The
// message goes to stderr, which exec.Cmd.Output captures into ExitError.Stderr.
func isMissingTableOutput(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && missingTableMessage(string(exitErr.Stderr))
}
