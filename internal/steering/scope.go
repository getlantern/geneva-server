// Package steering decides which packets have to reach userspace and keeps the
// kernel's view in sync with the loaded strategy.
//
// The sidecar's cost is not the strategy — it is the NFQUEUE round trip. Every
// steered packet is copied to userspace, decoded, handed to the engine and
// verdicted, and on a small VPS that dominates the box's CPU: measured on a
// 1-vCPU staging box, a bulk transfer fell from 105 MB/s to 25 MB/s with the
// sidecar running and *no strategy at all*, while a strategy that duplicated
// every data packet cost only ~4 MB/s beyond that.
//
// The fix is to queue only what a strategy could possibly act on. A Geneva
// strategy is a list of (trigger, action tree) pairs, and a packet that matches
// no trigger comes back out byte-for-byte — so filtering those packets in the
// kernel is not an approximation, it is the same result reached without the
// round trip. Most real strategies trigger on TCP flags (the handshake), which
// nftables can match directly, so bulk data never leaves the kernel at all.
//
// Scoping is also what makes an empty strategy free: no trees means nothing can
// match, which means no rules, which means no steering.
package steering

import (
	"sort"
	"strconv"
	"strings"

	"github.com/getlantern/geneva/actions"
	"github.com/getlantern/geneva/strategy"

	"github.com/getlantern/geneva-server/internal/nftables"
)

// Scope is the per-direction description of what a strategy can act on. It is
// expressed in the selectors nftables programs, so deriving a scope and
// programming the kernel share one vocabulary.
type Scope struct {
	Outbound nftables.Selector
	Inbound  nftables.Selector
}

// Idle reports whether the strategy can act on nothing at all, in which case no
// steering rules are needed and the sidecar has no effect on the box.
func (s Scope) Idle() bool { return s.Outbound.Empty() && s.Inbound.Empty() }

// tcpFlagBits maps Geneva's flag letters to the bits of the TCP flags byte, in
// nftables' order. Geneva also understands 'N' (the NS bit), which lives in the
// reserved nibble rather than the flags byte, so a trigger naming it cannot be
// expressed as a flags match and falls back to Any.
var tcpFlagBits = map[rune]uint8{
	'F': 0x01, // fin
	'S': 0x02, // syn
	'R': 0x04, // rst
	'P': 0x08, // psh
	'A': 0x10, // ack
	'U': 0x20, // urg
	'E': 0x40, // ecn
	'C': 0x80, // cwr
}

// Of derives the scope of a parsed strategy. A nil strategy, or one with no
// action trees, yields a scope that steers nothing.
func Of(s *strategy.Strategy) Scope {
	if s == nil {
		return Scope{}
	}
	return Scope{
		Outbound: selectorOf(s.Outbound),
		Inbound:  selectorOf(s.Inbound),
	}
}

func selectorOf(f strategy.Forest) nftables.Selector {
	var sel nftables.Selector
	for _, tree := range f {
		if tree == nil || tree.Trigger == nil {
			continue
		}
		m, ok := flagMatchOf(tree)
		if !ok {
			// One unexpressible trigger widens the whole direction: the kernel
			// cannot decide what this forest cares about, so it must ask.
			return nftables.Selector{Any: true}
		}
		sel.Flags = append(sel.Flags, m)
	}
	sel.Flags = canonicalFlags(sel.Flags)
	return sel
}

func canonicalFlags(in []nftables.FlagMatch) []nftables.FlagMatch {
	unique := make(map[nftables.FlagMatch]struct{}, len(in))
	for _, match := range in {
		unique[match] = struct{}{}
	}
	out := make([]nftables.FlagMatch, 0, len(unique))
	for candidate := range unique {
		subsumed := false
		for broader := range unique {
			if candidate == broader {
				continue
			}
			// Every packet matching candidate also matches broader when broader
			// constrains only bits candidate already fixes to the same values.
			if broader.Mask & ^candidate.Mask == 0 && candidate.Value&broader.Mask == broader.Value {
				subsumed = true
				break
			}
		}
		if !subsumed {
			out = append(out, candidate)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Mask != out[j].Mask {
			return out[i].Mask < out[j].Mask
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// flagMatchOf reduces one action tree's trigger to a flags match, reporting
// false when it cannot be expressed.
//
// The trigger's value is read back out of its String() form. That is the DNA
// serialization every strategy already round-trips through — it is the wire
// format, not a debug rendering — and the upstream trigger types keep their
// value field private.
func flagMatchOf(tree *actions.ActionTree) (nftables.FlagMatch, bool) {
	t := tree.Trigger
	if t.Protocol() != "TCP" || t.Field() != "flags" {
		return nftables.FlagMatch{}, false
	}
	value, ok := triggerValue(t.String())
	if !ok {
		return nftables.FlagMatch{}, false
	}

	wildcard := strings.HasSuffix(value, "*")
	value = strings.TrimSuffix(value, "*")
	if value == "" {
		return nftables.FlagMatch{}, false
	}

	var want uint8
	for _, c := range value {
		bit, ok := tcpFlagBits[c]
		if !ok {
			return nftables.FlagMatch{}, false
		}
		want |= bit
	}
	if wildcard {
		// "these bits set, others free"
		return nftables.FlagMatch{Mask: want, Value: want}, true
	}
	// Exact equality over the whole flags byte. Geneva's non-wildcard flags
	// match is equality, not "contains": `[TCP:flags:S]` does not fire on a
	// SYN-ACK.
	return nftables.FlagMatch{Mask: 0xff, Value: want}, true
}

// triggerValue extracts the value from a serialized trigger, i.e. "S" from
// "[TCP:flags:S]" and "S" from "[TCP:flags:S:3]" (the trailing field is gas).
func triggerValue(s string) (string, bool) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return "", false
	}
	value := parts[2]
	// Gas is a trailing ":<int>". Flag values never contain a colon themselves,
	// so splitting from the right is unambiguous for the fields we reduce.
	if i := strings.LastIndex(value, ":"); i >= 0 {
		if _, err := strconv.Atoi(value[i+1:]); err == nil {
			value = value[:i]
		}
	}
	return value, true
}
