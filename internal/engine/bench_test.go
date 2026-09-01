package engine

import (
	"fmt"
	"testing"

	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// The per-packet cost of the engine is what NFQUEUE steering multiplies by the
// packet rate, so it is the number to watch: at 1 Gbps with 1500-byte frames a
// box sees ~83k packets/s per direction, and every microsecond of per-packet
// work is 8.3% of a core.
//
// The cases are chosen to separate the three costs that make up Process:
// the private copy, the gopacket decode, and the strategy application. A
// pass-through engine pays the first two and nothing else, which is why an
// unconfigured sidecar is not free.
func BenchmarkProcess(b *testing.B) {
	data := buildTCP(b, 1, tcpFlags{ack: true, psh: true}, make([]byte, 1460))
	syn := buildTCP(b, 1, tcpFlags{syn: true}, nil)

	cases := []struct {
		name string
		dna  string
		raw  []byte
	}{
		// What an eval box runs before the brain assigns it anything, and what
		// a rolled-back prod box runs after PUT "".
		{"passthrough/data1460", "", data},
		{"passthrough/syn", "", syn},
		// A realistic prod shape: the trigger cannot match a data packet, so
		// every byte of bulk traffic is decoded for nothing.
		{"handshake-trigger/data1460", `[TCP:flags:S]-duplicate-| \/`, data},
		{"handshake-trigger/syn", `[TCP:flags:S]-duplicate-| \/`, syn},
		// The common manipulation: one packet in, one packet out, every data
		// packet rewritten. This is the shape the in-queue modified verdict
		// makes cheap.
		{"tamper-data/data1460", `[TCP:flags:PA]-tamper{TCP:window:replace:100}-| \/`, data},
		// Worst case: the trigger matches every data packet and the action
		// duplicates it, so a second packet has to reach the wire somehow.
		{"duplicate-data/data1460", `[TCP:flags:PA]-duplicate-| \/`, data},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			e := mustEngine(b, c.dna)
			// A reused scratch, as the NFQUEUE runtime does: one per queue
			// goroutine. Benchmarking with nil would measure an allocator the
			// hot path does not touch.
			scratch := &Scratch{}
			b.SetBytes(int64(len(c.raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := e.Process(c.raw, strategy.DirectionOutbound, scratch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDecode isolates the gopacket half of Process. Anything Process costs
// beyond this is the copy plus the strategy itself.
func BenchmarkDecode(b *testing.B) {
	for _, size := range []int{0, 1460} {
		raw := buildTCP(b, 1, tcpFlags{ack: true, psh: true}, make([]byte, size))
		b.Run(fmt.Sprintf("payload%d", size), func(b *testing.B) {
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				buf := make([]byte, len(raw))
				copy(buf, raw)
				pkt := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
				if pkt.ErrorLayer() != nil {
					b.Fatal("decode failed")
				}
			}
		})
	}
}
