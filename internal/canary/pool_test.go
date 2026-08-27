package canary

import (
	"testing"

	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func synPacket(t *testing.T, window uint16, ttl uint8, mss uint16) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: ttl, Id: 999, Protocol: layers.IPProtocolTCP,
		SrcIP: []byte{10, 0, 0, 2}, DstIP: []byte{10, 0, 0, 1},
	}
	tcp := &layers.TCP{
		SrcPort: 44000, DstPort: 8080, Seq: 1, SYN: true, Window: window,
		Options: []layers.TCPOption{{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{byte(mss >> 8), byte(mss)},
		}},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func contains(vals []uint32, v uint32) bool {
	for _, x := range vals {
		if x == v {
			return true
		}
	}
	return false
}

func TestColdStartSeed(t *testing.T) {
	p := NewPool("RU", 64)
	s := p.Snapshot()
	if s.Market != "RU" {
		t.Errorf("market = %q, want RU", s.Market)
	}
	if s.Captured != 0 {
		t.Errorf("captured = %d before any Observe, want 0", s.Captured)
	}
	// Cold-start values must be present so the brain can mutate before live data.
	if !contains(s.TTLs, 64) || !contains(s.TTLs, 128) {
		t.Errorf("cold-start TTLs missing common values: %v", s.TTLs)
	}
	if !contains(s.MSS, 1460) {
		t.Errorf("cold-start MSS missing 1460: %v", s.MSS)
	}
}

func TestObserveCapturesRealValues(t *testing.T) {
	p := NewPool("IR", 64)
	p.Observe(synPacket(t, 64240, 42, 1414), strategy.DirectionInbound)
	s := p.Snapshot()
	if s.Captured != 1 {
		t.Fatalf("captured = %d, want 1", s.Captured)
	}
	if !contains(s.Windows, 64240) {
		t.Errorf("window 64240 not captured: %v", s.Windows)
	}
	if !contains(s.TTLs, 42) {
		t.Errorf("ttl 42 not captured: %v", s.TTLs)
	}
	if !contains(s.MSS, 1414) {
		t.Errorf("mss 1414 not captured: %v", s.MSS)
	}
	if !contains(s.Flags, 0x02) { // SYN
		t.Errorf("SYN flag not captured: %v", s.Flags)
	}
}

func TestPoolCapBounded(t *testing.T) {
	p := NewPool("CN", 4) // tiny cap; cold start already fills several fields
	before := len(p.Snapshot().Windows)
	for i := 0; i < 100; i++ {
		p.Observe(synPacket(t, uint16(10000+i), 55, 1400), strategy.DirectionOutbound)
	}
	after := p.Snapshot().Windows
	if len(after) > 4 {
		t.Fatalf("window pool exceeded cap: %d values", len(after))
	}
	if len(after) < before {
		t.Fatalf("pool shrank: before=%d after=%d", before, len(after))
	}
}

func TestObserveIgnoresNonTCP(t *testing.T) {
	p := NewPool("RU", 64)
	p.Observe([]byte{0x45, 0, 0, 20}, strategy.DirectionInbound) // truncated garbage
	if p.Snapshot().Captured != 0 {
		t.Fatal("garbage packet counted as capture")
	}
}
