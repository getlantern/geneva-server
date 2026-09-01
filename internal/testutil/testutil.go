// Package testutil holds test helpers shared by the packages that build
// packets for the engine and program nftables. It is imported only from tests.
package testutil

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TCPFlags selects the flag bits BuildTCP sets on the packet.
type TCPFlags struct{ SYN, ACK, PSH, RST, FIN bool }

// BuildTCP builds a serialized IPv4/TCP packet with a valid checksum and length.
func BuildTCP(t testing.TB, seq uint32, flags TCPFlags, payload []byte) []byte {
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
		SYN:     flags.SYN,
		ACK:     flags.ACK,
		PSH:     flags.PSH,
		RST:     flags.RST,
		FIN:     flags.FIN,
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

// TableExists reports whether an inet nftables table of the given name is
// currently installed. It shells out to nft, so callers must already have
// established that nft is present and the test may touch the kernel.
func TableExists(t testing.TB, name string) bool {
	t.Helper()
	out, err := exec.Command("nft", "list", "tables", "inet").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list tables: %v: %s", err, out)
	}
	return strings.Contains(string(out), "table inet "+name)
}
