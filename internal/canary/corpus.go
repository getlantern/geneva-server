package canary

import "github.com/gopacket/gopacket/layers"

// coldStart holds plausible header values that commonly appear on real TCP/IPv4
// flows. It seeds the pool so the brain can mutate against realistic values
// before the test box has observed any live traffic. Live captures are added on
// top and, being counted, quickly dominate the distribution.
var coldStart = struct {
	windows []uint32
	ttls    []uint32
	mss     []uint32
	wscale  []uint32
	flags   []uint32
	options []uint32
}{
	// Common receive windows seen from Linux/Windows/macOS stacks.
	windows: []uint32{65535, 64240, 29200, 5840, 14600, 42780},
	// Initial TTLs by OS family (64 Linux/macOS, 128 Windows, 255 some routers).
	ttls: []uint32{64, 128, 255},
	// Typical MSS values (Ethernet, PPPoE, common tunnels).
	mss: []uint32{1460, 1440, 1412, 1380, 1360, 536},
	// Window-scale shifts commonly negotiated.
	wscale: []uint32{7, 8, 6, 10, 0},
	// Flag bitmaps for the handshake and steady state: S, SA, A, PA, FA, R, RA.
	flags: []uint32{0x02, 0x12, 0x10, 0x18, 0x11, 0x04, 0x14},
	// Option kinds present on a typical SYN.
	options: []uint32{
		uint32(layers.TCPOptionKindMSS),
		uint32(layers.TCPOptionKindSACKPermitted),
		uint32(layers.TCPOptionKindTimestamps),
		uint32(layers.TCPOptionKindNop),
		uint32(layers.TCPOptionKindWindowScale),
	},
}

func (p *Pool) seedColdStart() {
	for _, v := range coldStart.windows {
		p.windows.add(v)
	}
	for _, v := range coldStart.ttls {
		p.ttls.add(v)
	}
	for _, v := range coldStart.mss {
		p.mss.add(v)
	}
	for _, v := range coldStart.wscale {
		p.wscale.add(v)
	}
	for _, v := range coldStart.flags {
		p.flags.add(v)
	}
	for _, v := range coldStart.options {
		p.options.add(v)
	}
}
