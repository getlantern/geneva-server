package censor

import (
	"testing"

	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// build serializes a real IPv4/TCP packet so the hand-rolled header reads are
// tested against gopacket's wire format rather than against bytes this test
// laid out by hand to match the parser.
func build(t *testing.T, tcp *layers.TCP, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 2},
		DstIP:    []byte{10, 0, 0, 1},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("checksum layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	layersToSerialize := []gopacket.SerializableLayer{ip, tcp}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		tcp     *layers.TCP
		payload []byte
		want    Event
	}{
		{"syn", &layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true, Seq: 1}, nil, EventSYN},
		{"rst", &layers.TCP{SrcPort: 1234, DstPort: 443, RST: true, Seq: 2}, nil, EventRST},
		{"fin", &layers.TCP{SrcPort: 1234, DstPort: 443, FIN: true, ACK: true, Seq: 3}, nil, EventFIN},
		{"ack_only", &layers.TCP{SrcPort: 1234, DstPort: 443, ACK: true, Seq: 4}, nil, EventACKOnly},
		{"data", &layers.TCP{SrcPort: 1234, DstPort: 443, PSH: true, ACK: true, Seq: 5}, []byte("hello"), EventData},
		// A censor's injected RST commonly carries the ACK bit; RST must win so
		// the reset is not miscounted as a bare acknowledgement.
		{"rst_with_ack", &layers.TCP{SrcPort: 1234, DstPort: 443, RST: true, ACK: true, Seq: 6}, nil, EventRST},
		// A SYN that somehow carries payload is still a connection attempt.
		{"syn_with_payload", &layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true, Seq: 7}, []byte("x"), EventSYN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(build(t, tc.tcp, tc.payload)); got != tc.want {
				t.Fatalf("classify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyWithTCPOptions(t *testing.T) {
	// A SYN with options has a longer data offset; the payload-length arithmetic
	// must account for it rather than reading the options as payload.
	tcp := &layers.TCP{
		SrcPort: 1234, DstPort: 443, SYN: true, Seq: 1,
		Options: []layers.TCPOption{{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4},
		}},
	}
	if got := classify(build(t, tcp, nil)); got != EventSYN {
		t.Fatalf("classify = %v, want syn", got)
	}

	// The same header with the SYN cleared and no payload is a bare ACK, which
	// only holds if the option bytes are excluded from the payload length.
	tcp2 := &layers.TCP{
		SrcPort: 1234, DstPort: 443, ACK: true, Seq: 1,
		Options: tcp.Options,
	}
	if got := classify(build(t, tcp2, nil)); got != EventACKOnly {
		t.Fatalf("classify = %v, want ack_only", got)
	}
}

func TestClassifyRejectsNonTCPAndMalformed(t *testing.T) {
	udp := []byte{0x45, 0, 0, 28}
	udp = append(udp, make([]byte, 24)...)
	udp[9] = 17 // UDP

	cases := map[string][]byte{
		"too short":       {0x45, 0, 0, 20},
		"not ipv4":        append([]byte{0x60}, make([]byte, 39)...),
		"not tcp":         udp,
		"truncated tcp":   append([]byte{0x45, 0, 0, 40, 0, 0, 0, 0, 0, 6}, make([]byte, 15)...),
		"bad ihl":         append([]byte{0x41, 0, 0, 40, 0, 0, 0, 0, 0, 6}, make([]byte, 30)...),
		"data offset < 5": func() []byte { p := make([]byte, 40); p[0] = 0x45; p[3] = 40; p[9] = 6; return p }(),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classify(raw); got != EventUndecodable {
				t.Fatalf("classify = %v, want undecodable", got)
			}
		})
	}
}

func TestObserveIgnoresOutbound(t *testing.T) {
	o := New()
	syn := build(t, &layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true, Seq: 1}, nil)

	o.Observe(syn, strategy.DirectionOutbound)
	if got := o.Count(EventSYN); got != 0 {
		t.Fatalf("outbound packet counted: syn = %d", got)
	}

	o.Observe(syn, strategy.DirectionInbound)
	if got := o.Count(EventSYN); got != 1 {
		t.Fatalf("syn = %d, want 1", got)
	}
}

func TestObserveCountsUndecodable(t *testing.T) {
	o := New()
	o.Observe([]byte{0x45, 0, 0}, strategy.DirectionInbound)
	if got := o.Count(EventUndecodable); got != 1 {
		t.Fatalf("undecodable = %d, want 1", got)
	}
}

// TestSnapshotReportsEveryEvent guards the "a zero is a zero, not a missing
// series" property: a market with no data packets at all is exactly the burned
// box we need to see, so that series must not simply be absent.
func TestSnapshotReportsEveryEvent(t *testing.T) {
	snap := New().Snapshot()
	for _, name := range []string{"rst", "syn", "fin", "data", "ack_only", "fragment", "undecodable"} {
		if _, ok := snap.Events[name]; !ok {
			t.Fatalf("event %q missing from snapshot", name)
		}
	}
	if len(snap.Events) != int(eventCount) {
		t.Fatalf("snapshot has %d events, want %d", len(snap.Events), eventCount)
	}
}

// TestNonInitialFragmentsAreNotClassified pins the fragment split. A fragment
// with a nonzero offset still reads as protocol TCP, so without the check its
// payload bytes would be read as TCP flags and counted as a real event — and a
// censor that fragments is exactly when the counters must not lie.
func TestNonInitialFragmentsAreNotClassified(t *testing.T) {
	// A first fragment: MF set but offset zero, so the TCP header is present
	// and it is classified normally.
	first := build(t, &layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true, Seq: 1}, nil)
	first[6] = 0x20
	if got := classify(first); got != EventSYN {
		t.Fatalf("first fragment = %v, want syn", got)
	}

	// The same bytes with a nonzero fragment offset carry no TCP header.
	later := append([]byte(nil), first...)
	later[6], later[7] = 0x00, 0xb9 // offset 185 (1480 bytes in)
	if got := classify(later); got != EventFragment {
		t.Fatalf("later fragment = %v, want fragment", got)
	}

	o := New()
	o.Observe(later, strategy.DirectionInbound)
	// Kept out of undecodable: a fragment is legitimate traffic, and
	// undecodable has to stay a signal that the steering rules are wrong.
	if got := o.Count(EventUndecodable); got != 0 {
		t.Fatalf("undecodable = %d, want 0", got)
	}
	if got := o.Count(EventSYN); got != 0 {
		t.Fatalf("fragment counted as syn: %d", got)
	}
	if got := o.Count(EventFragment); got != 1 {
		t.Fatalf("fragment = %d, want 1", got)
	}
}

// TestEveryPacketIsBucketed pins the sum invariant the ratios rely on: an
// inbound packet always increments exactly one counter, whatever it is.
func TestEveryPacketIsBucketed(t *testing.T) {
	o := New()
	packets := [][]byte{
		build(t, &layers.TCP{SrcPort: 1, DstPort: 443, SYN: true, Seq: 1}, nil),
		build(t, &layers.TCP{SrcPort: 1, DstPort: 443, PSH: true, ACK: true, Seq: 2}, []byte("x")),
		{0x45, 0, 0}, // undecodable
	}
	frag := append([]byte(nil), packets[0]...)
	frag[6], frag[7] = 0x00, 0xb9
	packets = append(packets, frag)

	for _, p := range packets {
		o.Observe(p, strategy.DirectionInbound)
	}
	var total uint64
	for _, c := range o.Snapshot().Events {
		total += c
	}
	if total != uint64(len(packets)) {
		t.Fatalf("counted %d of %d observed packets", total, len(packets))
	}
}
