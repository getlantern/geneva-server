//go:build linux

package nfqueue

import (
	"fmt"
	"net"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/getlantern/geneva-server/internal/generation"
)

// Reinjector writes complete IPv4 packets back onto the wire through a raw
// socket. It is used for outbound packets, where a single queued packet may be
// replaced by zero or more packets (duplicate/fragment) that the in-queue
// verdict cannot express.
//
// The socket is owned by the dedicated Geneva service UID, which nftables
// excludes from its output queue. SO_MARK is set per send to the packet's exact
// original routing mark; no private generation or loop-guard bits participate
// in the initial route lookup.
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
	mu sync.Mutex
}

// NewReinjector opens a raw IPv4 socket and verifies SO_MARK capability.
func NewReinjector() (*Reinjector, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("open raw socket (needs CAP_NET_RAW): %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, 1); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set SO_MARK (needs CAP_NET_ADMIN): %w", err)
	}
	return &Reinjector{fd: fd}, nil
}

// Inject sends one complete IPv4 packet. The destination is taken from the
// packet's own IPv4 header, so the caller need not supply it separately.
func (r *Reinjector) Inject(packet []byte, routingMark uint32) error {
	if len(packet) < 20 {
		return fmt.Errorf("packet too short to reinject: %d bytes", len(packet))
	}
	mark, err := reinjectionMark(routingMark)
	if err != nil {
		return err
	}
	var addr unix.SockaddrInet4
	copy(addr.Addr[:], packet[16:20]) // IPv4 destination address
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := unix.SetsockoptInt(r.fd, unix.SOL_SOCKET, unix.SO_MARK, int(mark)); err != nil {
		return fmt.Errorf("set per-packet SO_MARK: %w", err)
	}
	if err := unix.Sendto(r.fd, packet, 0, &addr); err != nil {
		return fmt.Errorf("sendto %s: %w", net.IP(packet[16:20]), err)
	}
	return nil
}

func reinjectionMark(routingMark uint32) (uint32, error) {
	if routingMark&generation.Mask != 0 {
		return 0, fmt.Errorf("routing mark %#x overlaps Geneva reservation %#x", routingMark, generation.Mask)
	}
	return routingMark, nil
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
