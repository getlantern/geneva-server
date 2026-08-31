//go:build linux

package nfqueue

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// Reinjector writes complete IPv4 packets back onto the wire through a raw
// socket. It is used for outbound packets, where a single queued packet may be
// replaced by zero or more packets (duplicate/fragment) that the in-queue
// verdict cannot express.
//
// The socket carries a firewall mark so the reinjected packets match the
// nftables "accept marked" rule and skip the queue, breaking what would
// otherwise be an infinite reinjection loop.
//
// The socket is IPPROTO_RAW (IP_HDRINCL implied): the kernel does not prepend
// an IP header and does not touch the TCP checksum, so a strategy's TCP-layer
// manipulation — including a deliberately invalid TCP checksum — reaches the
// wire verbatim. The kernel does recompute the IPv4 *header* checksum on send;
// that is correct for every normal and TCP-tampering strategy and is a known v1
// limitation only for the rare strategy that deliberately corrupts the IPv4
// header checksum itself.
type Reinjector struct {
	fd int
}

// NewReinjector opens a raw IPv4 socket that stamps every sent packet with mark.
func NewReinjector(mark uint32) (*Reinjector, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw socket (needs CAP_NET_RAW): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	if mark != 0 {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("set SO_MARK (needs CAP_NET_ADMIN): %w", err)
		}
	}
	return &Reinjector{fd: fd}, nil
}

// Inject sends one complete IPv4 packet. The destination is taken from the
// packet's own IPv4 header, so the caller need not supply it separately.
func (r *Reinjector) Inject(packet []byte) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short to reinject: %d bytes", len(packet))
	}
	var addr unix.SockaddrInet4
	copy(addr.Addr[:], packet[16:20]) // IPv4 destination address
	if err := unix.Sendto(r.fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("sendto %s: %w", net.IP(packet[16:20]), err)
	}
	return nil
}

// Close releases the raw socket.
func (r *Reinjector) Close() error {
	if r.fd >= 0 {
		err := unix.Close(r.fd)
		r.fd = -1
		return err
	}
	return nil
}
