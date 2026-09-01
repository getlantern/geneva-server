package steering

import (
	"testing"

	"github.com/getlantern/geneva"
	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/getlantern/geneva-server/internal/engine"
	"github.com/getlantern/geneva-server/internal/nftables"
)

func mustScope(t *testing.T, dna string) Scope {
	t.Helper()
	s, err := geneva.NewStrategy(dna)
	if err != nil {
		t.Fatalf("parse %q: %v", dna, err)
	}
	return Of(s)
}

func TestScopeOf(t *testing.T) {
	cases := []struct {
		name     string
		dna      string
		outbound nftables.Selector
		inbound  nftables.Selector
	}{
		{
			// The state an eval box boots in and the state a rollback leaves a
			// prod box in. Nothing may be steered.
			name: "empty",
		},
		{
			name:     "handshake outbound",
			dna:      `[TCP:flags:S]-duplicate-| \/`,
			outbound: nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0xff, Value: 0x02}}},
		},
		{
			// Geneva's non-wildcard flags trigger is equality, so the mask
			// covers the whole byte: [TCP:flags:S] must not fire on SYN-ACK.
			name:     "handshake with gas",
			dna:      `[TCP:flags:S:3]-duplicate-| \/`,
			outbound: nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0xff, Value: 0x02}}},
		},
		{
			name:     "wildcard is a subset match",
			dna:      `[TCP:flags:S*]-duplicate-| \/`,
			outbound: nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0x02, Value: 0x02}}},
		},
		{
			name:    "inbound only",
			dna:     `\/ [TCP:flags:R]-drop-|`,
			inbound: nftables.Selector{Flags: []nftables.FlagMatch{{Mask: 0xff, Value: 0x04}}},
		},
		{
			// A payload trigger cannot be expressed in nftables, so the whole
			// direction widens to everything rather than guessing.
			name:     "payload trigger widens to any",
			dna:      `[TCP:load:GET]-duplicate-| \/`,
			outbound: nftables.Selector{Any: true},
		},
		{
			name:     "ip trigger widens to any",
			dna:      `[IP:ttl:64]-duplicate-| \/`,
			outbound: nftables.Selector{Any: true},
		},
		{
			// One unexpressible trigger poisons its direction even when a
			// sibling tree is narrow: the kernel cannot tell them apart.
			name:     "mixed forest widens to any",
			dna:      `[TCP:flags:S]-duplicate-|[TCP:load:GET]-drop-| \/`,
			outbound: nftables.Selector{Any: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mustScope(t, c.dna)
			assertSelector(t, "outbound", got.Outbound, c.outbound)
			assertSelector(t, "inbound", got.Inbound, c.inbound)
			wantIdle := c.outbound.Empty() && c.inbound.Empty()
			if got.Idle() != wantIdle {
				t.Errorf("Idle() = %v, want %v", got.Idle(), wantIdle)
			}
		})
	}
}

func assertSelector(t *testing.T, dir string, got, want nftables.Selector) {
	t.Helper()
	if got.Any != want.Any {
		t.Errorf("%s Any = %v, want %v", dir, got.Any, want.Any)
	}
	if len(got.Flags) != len(want.Flags) {
		t.Fatalf("%s flags = %+v, want %+v", dir, got.Flags, want.Flags)
	}
	for i := range want.Flags {
		if got.Flags[i] != want.Flags[i] {
			t.Errorf("%s flags[%d] = %+v, want %+v", dir, i, got.Flags[i], want.Flags[i])
		}
	}
}

// TestScopeNeverNarrowerThanStrategy is the invariant the whole optimization
// rests on: a packet the kernel filters out must be a packet the engine would
// have handed back byte-for-byte anyway. If this test can find a packet that the
// selector rejects but the strategy modifies, scoping is silently dropping
// manipulations and the strategy is not being applied.
func TestScopeNeverNarrowerThanStrategy(t *testing.T) {
	dnas := []string{
		"",
		`[TCP:flags:S]-duplicate-| \/`,
		`[TCP:flags:S*]-duplicate-| \/`,
		`[TCP:flags:SA]-tamper{TCP:flags:replace:R}-| \/`,
		`[TCP:flags:PA]-duplicate-| \/`,
		`[TCP:flags:F*]-drop-| \/`,
		`[TCP:flags:S]-duplicate-|[TCP:flags:R]-drop-| \/`,
		`[TCP:load:GET]-duplicate-| \/`,
		`\/ [TCP:flags:R]-drop-|`,
	}
	packets := []struct {
		name  string
		flags uint8
		raw   []byte
	}{
		{"syn", 0x02, buildTCP(t, tcpBits{syn: true}, nil)},
		{"syn-ack", 0x12, buildTCP(t, tcpBits{syn: true, ack: true}, nil)},
		{"ack", 0x10, buildTCP(t, tcpBits{ack: true}, nil)},
		{"psh-ack-data", 0x18, buildTCP(t, tcpBits{psh: true, ack: true}, []byte("GET"))},
		{"rst", 0x04, buildTCP(t, tcpBits{rst: true}, nil)},
		{"fin-ack", 0x11, buildTCP(t, tcpBits{fin: true, ack: true}, nil)},
	}

	for _, dna := range dnas {
		for _, dir := range []strategy.Direction{strategy.DirectionOutbound, strategy.DirectionInbound} {
			sc := mustScope(t, dna)
			sel := sc.Outbound
			if dir == strategy.DirectionInbound {
				sel = sc.Inbound
			}
			for _, p := range packets {
				if selectorMatches(sel, p.flags) {
					continue // the kernel would queue it; nothing to prove
				}
				// A fresh engine per packet: triggers consume gas, and a
				// shared engine would let one case mask another.
				e, err := engine.New(dna)
				if err != nil {
					t.Fatalf("engine.New(%q): %v", dna, err)
				}
				res, err := e.Process(p.raw, dir)
				if err != nil {
					t.Fatalf("dna=%q %s %s: Process: %v", dna, dir, p.name, err)
				}
				if res.Outcome != engine.OutcomeUnchanged {
					t.Errorf("dna=%q %s %s: filtered by scope but engine returned %s — scoping would drop this manipulation",
						dna, dir, p.name, res.Outcome)
				}
			}
		}
	}
}

// selectorMatches mirrors what the nftables rules do, so the test compares the
// kernel's decision against the engine's rather than against itself.
func selectorMatches(sel nftables.Selector, flags uint8) bool {
	if sel.Any {
		return true
	}
	for _, f := range sel.Flags {
		if flags&f.Mask == f.Value {
			return true
		}
	}
	return false
}

type tcpBits struct{ syn, ack, psh, rst, fin bool }

func buildTCP(t *testing.T, bits tcpBits, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 1,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	tcp := &layers.TCP{
		SrcPort: 8080, DstPort: 44000, Seq: 1, Window: 65535,
		SYN: bits.syn, ACK: bits.ack, PSH: bits.psh, RST: bits.rst, FIN: bits.fin,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set network layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}
