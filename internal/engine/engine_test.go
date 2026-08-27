package engine

import (
	"encoding/binary"
	"testing"

	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildTCP builds a serialized IPv4/TCP packet with a valid checksum and length.
func buildTCP(t *testing.T, seq uint32, flags tcpFlags, payload []byte) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       1234,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}
	tcp := &layers.TCP{
		SrcPort: 8080,
		DstPort: 44000,
		Seq:     seq,
		Window:  65535,
		SYN:     flags.syn,
		ACK:     flags.ack,
		PSH:     flags.psh,
		RST:     flags.rst,
		FIN:     flags.fin,
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

type tcpFlags struct{ syn, ack, psh, rst, fin bool }

func mustEngine(t *testing.T, dna string) *Engine {
	t.Helper()
	e, err := New(dna)
	if err != nil {
		t.Fatalf("New(%q): %v", dna, err)
	}
	return e
}

// decode re-parses a serialized IPv4 packet.
func decode(t *testing.T, raw []byte) (*layers.IPv4, *layers.TCP) {
	t.Helper()
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Default)
	if err := pkt.ErrorLayer(); err != nil {
		t.Fatalf("decode: %v", err.Error())
	}
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ip == nil || tcp == nil {
		t.Fatalf("packet missing IPv4/TCP layers")
	}
	return ip, tcp
}

// assertChecksums verifies the IPv4 header and TCP checksums are correct on the
// wire. This is the engine's core contract: the library must hand back packets
// whose derived fields are consistent (except where a strategy deliberately
// corrupts them, which these non-corrupting strategies never do).
func assertChecksums(t *testing.T, raw []byte) {
	t.Helper()
	if len(raw) < 20 {
		t.Fatalf("packet too short: %d bytes", len(raw))
	}
	ihl := int(raw[0]&0x0f) * 4
	if sum := ones(raw[:ihl]); sum != 0xffff {
		t.Errorf("IPv4 checksum invalid: ones-complement sum = %#04x, want 0xffff", sum)
	}
	total := int(binary.BigEndian.Uint16(raw[2:4]))
	if total > len(raw) {
		t.Fatalf("IP total length %d exceeds packet %d", total, len(raw))
	}
	tcpSeg := raw[ihl:total]
	// Pseudo-header: src(4) dst(4) zero(1) proto(1) tcplen(2).
	pseudo := make([]byte, 12+len(tcpSeg))
	copy(pseudo[0:4], raw[12:16])
	copy(pseudo[4:8], raw[16:20])
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSeg)))
	copy(pseudo[12:], tcpSeg)
	if sum := ones(pseudo); sum != 0xffff {
		t.Errorf("TCP checksum invalid: ones-complement sum = %#04x, want 0xffff", sum)
	}
}

// ones returns the 16-bit ones-complement sum of b. A valid checksummed buffer
// (checksum field included) sums to 0xffff.
func ones(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func TestUnchanged_EmptyStrategy(t *testing.T) {
	e := mustEngine(t, "")
	raw := buildTCP(t, 1000, tcpFlags{psh: true, ack: true}, []byte("hello world"))
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeUnchanged {
		t.Fatalf("outcome = %v, want unchanged", res.Outcome)
	}
	if len(res.Packets) != 1 || !bytesEqual(res.Packets[0], raw) {
		t.Fatalf("packet altered by empty strategy")
	}
}

func TestUnchanged_PassthroughTree(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:PA]-| \/`)
	raw := buildTCP(t, 1000, tcpFlags{psh: true, ack: true}, []byte("hello"))
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeUnchanged {
		t.Fatalf("outcome = %v, want unchanged", res.Outcome)
	}
}

func TestDropped(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:R]-drop-| \/`)
	raw := buildTCP(t, 1000, tcpFlags{rst: true}, nil)
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeDropped {
		t.Fatalf("outcome = %v, want dropped", res.Outcome)
	}
	if len(res.Packets) != 0 {
		t.Fatalf("dropped packet emitted %d packets", len(res.Packets))
	}
	if e.Snapshot().Dropped != 1 {
		t.Fatalf("dropped counter = %d, want 1", e.Snapshot().Dropped)
	}
}

func TestDuplicated(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:PA]-duplicate-| \/`)
	raw := buildTCP(t, 5000, tcpFlags{psh: true, ack: true}, []byte("payload"))
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeExpanded {
		t.Fatalf("outcome = %v, want expanded", res.Outcome)
	}
	if len(res.Packets) != 2 {
		t.Fatalf("duplicate emitted %d packets, want 2", len(res.Packets))
	}
	for i, p := range res.Packets {
		assertChecksums(t, p)
		_, tcp := decode(t, p)
		if tcp.Seq != 5000 {
			t.Errorf("packet %d seq = %d, want 5000 (duplicate preserves seq)", i, tcp.Seq)
		}
	}
}

func TestTampered_Flags(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:S]-tamper{TCP:flags:replace:SA}-| \/`)
	raw := buildTCP(t, 42, tcpFlags{syn: true}, nil)
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeTampered {
		t.Fatalf("outcome = %v, want tampered", res.Outcome)
	}
	assertChecksums(t, res.Packets[0])
	_, tcp := decode(t, res.Packets[0])
	if !tcp.SYN || !tcp.ACK {
		t.Fatalf("flags not replaced: SYN=%v ACK=%v", tcp.SYN, tcp.ACK)
	}
}

func TestTampered_TTL(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:PA]-tamper{IP:ttl:replace:5}-| \/`)
	raw := buildTCP(t, 42, tcpFlags{psh: true, ack: true}, []byte("data"))
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	assertChecksums(t, res.Packets[0])
	ip, _ := decode(t, res.Packets[0])
	if ip.TTL != 5 {
		t.Fatalf("ttl = %d, want 5", ip.TTL)
	}
}

func TestFragmented(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:PA]-fragment{TCP:8:true}-| \/`)
	payload := []byte("0123456789ABCDEF") // 16 bytes
	raw := buildTCP(t, 7000, tcpFlags{psh: true, ack: true}, payload)
	res, err := e.Process(raw, strategy.DirectionOutbound)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeExpanded || len(res.Packets) != 2 {
		t.Fatalf("outcome=%v packets=%d, want expanded/2", res.Outcome, len(res.Packets))
	}
	var combined []byte
	var seqs []uint32
	for i, p := range res.Packets {
		assertChecksums(t, p)
		ip, tcp := decode(t, p)
		seqs = append(seqs, tcp.Seq)
		combined = append(combined, tcp.Payload...)
		if int(ip.Length) != len(p) {
			t.Errorf("fragment %d IP length %d != packet %d", i, ip.Length, len(p))
		}
	}
	if string(combined) != string(payload) {
		t.Fatalf("reassembled payload %q != original %q", combined, payload)
	}
	// Second fragment carries the first fragment's payload length as seq offset.
	if seqs[1] != seqs[0]+8 {
		t.Errorf("second fragment seq = %d, want %d (first seq + 8)", seqs[1], seqs[0]+8)
	}
}

func TestInboundBranchingRejectedAtParse(t *testing.T) {
	// Branching actions are outbound-only; validation must reject an inbound
	// duplicate so the runtime never has to reconcile >1 inbound packet.
	if _, err := New(`\/ [TCP:flags:A]-duplicate-|`); err == nil {
		t.Fatal("expected inbound duplicate to be rejected")
	}
}

func TestOverheadMetrics(t *testing.T) {
	e := mustEngine(t, `[TCP:flags:PA]-duplicate-| \/`)
	raw := buildTCP(t, 1, tcpFlags{psh: true, ack: true}, []byte("abcdefgh"))
	if _, err := e.Process(raw, strategy.DirectionOutbound); err != nil {
		t.Fatal(err)
	}
	snap := e.Snapshot()
	if snap.PacketsIn != 1 || snap.PacketsOut != 2 {
		t.Fatalf("packets in/out = %d/%d, want 1/2", snap.PacketsIn, snap.PacketsOut)
	}
	if snap.PacketOverhead != 1.0 {
		t.Fatalf("packet overhead = %v, want 1.0", snap.PacketOverhead)
	}
}
