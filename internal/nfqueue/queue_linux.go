//go:build linux

package nfqueue

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// This file is the sidecar's netlink hot path.
//
// It exists because the generic Go netlink stack is far too expensive per
// packet. A CPU profile of a tamper-every-packet strategy put 41% of the
// sidecar's time in syscalls and ~30% in the garbage collector and the
// scheduler feeding it, against under 10% in the Geneva engine. The cause was
// not the engine or even NFQUEUE: mdlayher/netlink's Receive allocates a fresh
// page-sized buffer per call, does a MSG_PEEK recvmsg to size the message, then
// a second recvmsg to read it, then allocates again to parse it. That is two
// syscalls and several allocations for every packet, before any work happens.
//
// So the setup — dial, bind, copy mode, queue length — still goes through
// mdlayher/netlink, where it is readable and runs once. The per-packet path
// takes the raw fd and does the minimum:
//
//   - One recvmsg into a reusable buffer, which returns however many packets
//     the kernel has queued rather than exactly one.
//   - Parsing in place. A packet's payload is a subslice of the read buffer,
//     valid until the next read, which is precisely the window in which the
//     verdict is issued.
//   - Accept verdicts batched to one syscall per read. NFQNL_MSG_VERDICT_BATCH
//     verdicts every packet id up to the one given, and ids increase
//     monotonically, so a run of accepts collapses into a single message. The
//     batch is flushed before any individual verdict for a later id, or a
//     batch would swallow a packet meant to be dropped or rewritten.
//   - Verdict messages marshalled into a reusable buffer.
//
// The result is one syscall per read plus one per manipulated packet, instead
// of three or more per packet, and no per-packet allocation at all.

// Netlink and nfnetlink constants. Spelled out here rather than pulled from a
// dependency: they are kernel ABI, they do not change, and the hot path should
// not have to guess at another library's mapping of them.
const (
	nfnlSubsysQueue = 0x03

	nfqnlMsgPacket       = 0
	nfqnlMsgVerdict      = 1
	nfqnlMsgConfig       = 2
	nfqnlMsgVerdictBatch = 3

	// Packet attributes.
	nfqaPacketHdr  = 1
	nfqaVerdictHdr = 2
	nfqaPayload    = 10
	nfqaCapLen     = 13

	// Config attributes and commands.
	nfqaCfgCmd         = 1
	nfqaCfgParams      = 2
	nfqaCfgQueueMaxLen = 3
	nfqaCfgMask        = 4
	nfqaCfgFlags       = 5

	nfqnlCfgCmdBind     = 1
	nfqnlCfgCmdUnbind   = 2
	nfqnlCfgCmdPfBind   = 3
	nfqnlCfgCmdPfUnbind = 4

	// Copy modes.
	nfqnlCopyPacket = 2

	// Verdicts, from netfilter.h.
	nfDrop   = 0
	nfAccept = 1

	nlmsgHdrLen  = 16
	nfgenmsgLen  = 4
	nlaHdrLen    = 4
	nlmsgAlignTo = 4

	// readBufSize holds many MTU-sized packets, or one 64 KB packet from an
	// interface whose offloads are still on, in a single read.
	readBufSize = 256 << 10

	// maxQueueLen is how many packets the kernel will hold for this queue
	// before dropping (and, with the bypass flag on the rules, accepting) them.
	maxQueueLen = 0xffff

	// rcvBufSize is the socket buffer. NFQUEUE reports ENOBUFS and drops
	// packets when this fills, and a burst plus a slow strategy is exactly how
	// that happens.
	rcvBufSize = 4 << 20
)

// ErrTruncated reports a packet the kernel copied only part of. It is a
// configuration error (copy length too small), and the only safe response is to
// accept the packet unmodified rather than reinject a fragment of it.
var ErrTruncated = errors.New("kernel truncated the captured packet")

// queue is one bound NFQUEUE and its verdict channel.
type queue struct {
	con    *netlink.Conn
	rc     syscall.RawConn
	num    uint16
	family uint8

	rbuf []byte
	vbuf []byte

	// pendingAccept is the highest packet id accepted but not yet verdicted,
	// held back so a run of accepts can go out as one batch message.
	pendingAccept uint32
	hasPending    bool

	// send writes a marshalled netlink message. A field rather than a method so
	// the batching and marshalling can be tested without a kernel.
	send func([]byte) error
}

// openQueue dials netlink, binds queue num, and configures copy mode.
func openQueue(num uint16, maxPacketLen uint32, maxQueueLen uint32) (*queue, error) {
	con, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, fmt.Errorf("dial netlink: %w", err)
	}
	q := &queue{
		con: con,
		num: num,
		// AF_INET, matching an engine and reinjector that are IPv4-only. The
		// kernel does not read this field for the messages it is sent with here
		// — the queue bind and the verdicts — which is why v0.0.1 worked with it
		// left at zero. Set explicitly all the same: an implicit AF_UNSPEC in an
		// IPv4-only sidecar reads as an oversight rather than a decision.
		family: unix.AF_INET,
		rbuf:   make([]byte, readBufSize),
		vbuf:   make([]byte, 0, 4096),
	}
	if err := con.SetReadBuffer(rcvBufSize); err != nil {
		// Not fatal: a smaller buffer means ENOBUFS under burst, which is
		// counted and logged, not a failure to run.
		_ = err
	}
	rc, err := con.SyscallConn()
	if err != nil {
		_ = con.Close()
		return nil, fmt.Errorf("raw netlink conn: %w", err)
	}
	q.rc = rc
	q.send = q.writeRaw

	// The same sequence libnetfilter_queue performs: drop any stale handler for
	// the family, bind the family, bind the queue, then set copy mode and depth.
	steps := []struct {
		what  string
		resid uint16
		attrs []netlink.Attribute
	}{
		{"unbind family", 0, []netlink.Attribute{{Type: nfqaCfgCmd, Data: cfgCmd(nfqnlCfgCmdPfUnbind, q.family)}}},
		{"bind family", 0, []netlink.Attribute{{Type: nfqaCfgCmd, Data: cfgCmd(nfqnlCfgCmdPfBind, q.family)}}},
		{"bind queue", num, []netlink.Attribute{{Type: nfqaCfgCmd, Data: cfgCmd(nfqnlCfgCmdBind, q.family)}}},
		{"set copy mode", num, []netlink.Attribute{{Type: nfqaCfgParams, Data: cfgParams(maxPacketLen)}}},
		{"set queue length", num, []netlink.Attribute{{Type: nfqaCfgQueueMaxLen, Data: be32(maxQueueLen)}}},
	}
	for _, s := range steps {
		if err := q.config(s.resid, s.attrs); err != nil {
			_ = con.Close()
			return nil, fmt.Errorf("%s: %w", s.what, err)
		}
	}
	return q, nil
}

// config sends one NFQNL_MSG_CONFIG message. Setup only — this is the path that
// may allocate freely.
func (q *queue) config(resid uint16, attrs []netlink.Attribute) error {
	data, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return err
	}
	body := make([]byte, 0, nfgenmsgLen+len(data))
	body = append(body, q.family, unix.NFNETLINK_V0, 0, 0)
	binary.BigEndian.PutUint16(body[2:4], resid)
	body = append(body, data...)

	_, err = q.con.Send(netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((nfnlSubsysQueue << 8) | nfqnlMsgConfig),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: body,
	})
	if err != nil {
		return err
	}
	// Read the ack so a failure surfaces here rather than as a mystery later.
	if _, err := q.con.Receive(); err != nil {
		return err
	}
	return nil
}

// Close releases the queue. It does not send an explicit unbind: the kernel
// drops the binding when the socket closes, and an unbind here would have to
// read its own ack off a socket a reader may still be draining — which
// deadlocked shutdown until the container was killed.
func (q *queue) Close() error {
	return q.con.Close()
}

// interrupt unblocks a reader parked in recvmsg by putting the read deadline in
// the past. Cancelling the context alone does not do it: the read is waiting on
// socket readiness inside the runtime poller, not on the context.
func (q *queue) interrupt() {
	_ = q.con.SetReadDeadline(time.Now().Add(-time.Second))
}

// packet is one queued packet: its id and its bytes. The payload aliases the
// queue's read buffer and is only valid until the next read.
type packet struct {
	id      uint32
	payload []byte
	// truncated is set when the kernel copied less than the packet's real
	// length, which makes the payload unsafe to manipulate or reinject.
	truncated bool
}

// read performs one recvmsg and calls fn for every packet it returned, in
// order. Any accept verdicts fn defers are flushed before read returns, so no
// packet is ever left waiting on the next read.
func (q *queue) read(ctx context.Context, fn func(packet) error) error {
	n, err := q.recvmsg()
	if err != nil {
		return err
	}
	if err := forEachPacket(ctx, q.rbuf[:n], fn); err != nil {
		return err
	}
	return q.flush()
}

// forEachPacket walks the netlink messages in one read and calls fn for each
// NFQNL_MSG_PACKET among them, in order.
//
// Neither messages nor attributes are padded at the end of a buffer, so every
// step is clamped to what is left: stepping by the aligned length walks off the
// end of the last one, which is exactly how this crashed the first time it met
// a real kernel.
func forEachPacket(ctx context.Context, b []byte, fn func(packet) error) error {
	for len(b) >= nlmsgHdrLen {
		msgLen := int(binary.LittleEndian.Uint32(b[0:4]))
		msgType := binary.LittleEndian.Uint16(b[4:6])
		if msgLen < nlmsgHdrLen || msgLen > len(b) {
			return fmt.Errorf("malformed netlink message: len %d in %d bytes", msgLen, len(b))
		}
		if msgType == uint16((nfnlSubsysQueue<<8)|nfqnlMsgPacket) {
			p, err := parsePacket(b[nlmsgHdrLen:msgLen])
			if err != nil {
				return err
			}
			if err := fn(p); err != nil {
				return err
			}
		}
		b = b[min(nlmsgAlign(msgLen), len(b)):]
		if ctx.Err() != nil {
			return nil
		}
	}
	return nil
}

// recvmsg reads once into the reusable buffer, waiting for readiness through
// the runtime poller rather than blocking a thread.
func (q *queue) recvmsg() (int, error) {
	var n int
	var rerr error
	err := q.rc.Read(func(fd uintptr) bool {
		var flags int
		n, _, flags, _, rerr = unix.Recvmsg(int(fd), q.rbuf, nil, 0)
		if rerr == unix.EAGAIN || rerr == unix.EWOULDBLOCK {
			return false // not ready; wait and try again
		}
		if rerr == nil && flags&unix.MSG_TRUNC != 0 {
			rerr = fmt.Errorf("netlink message longer than the %d-byte read buffer", len(q.rbuf))
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	if rerr != nil {
		return 0, rerr
	}
	return n, nil
}

// parsePacket extracts the id and payload from one NFQNL_MSG_PACKET body.
func parsePacket(body []byte) (packet, error) {
	if len(body) < nfgenmsgLen {
		return packet{}, errors.New("nfnetlink message shorter than its header")
	}
	var p packet
	var capLen uint32
	attrs := body[nfgenmsgLen:]
	for len(attrs) >= nlaHdrLen {
		alen := int(binary.LittleEndian.Uint16(attrs[0:2]))
		atype := binary.LittleEndian.Uint16(attrs[2:4]) & 0x3fff // strip nested/byte-order bits
		if alen < nlaHdrLen || alen > len(attrs) {
			return packet{}, fmt.Errorf("malformed netlink attribute: len %d in %d bytes", alen, len(attrs))
		}
		data := attrs[nlaHdrLen:alen]
		switch atype {
		case nfqaPacketHdr:
			if len(data) < 4 {
				return packet{}, errors.New("short nfqnl_msg_packet_hdr")
			}
			p.id = binary.BigEndian.Uint32(data[0:4])
		case nfqaPayload:
			p.payload = data
		case nfqaCapLen:
			if len(data) >= 4 {
				capLen = binary.BigEndian.Uint32(data[0:4])
			}
		}
		// The kernel does not pad the last attribute in a message, so the
		// aligned step can point past the end: advance to exactly the end
		// rather than overrunning it.
		step := min(nlmsgAlign(alen), len(attrs))
		attrs = attrs[step:]
	}
	// NFQA_CAP_LEN is only present when the kernel copied less than the whole
	// packet, which is the copy-length case: the bytes we hold are a prefix, so
	// any manipulation of them would put a corrupt packet on the wire.
	if capLen != 0 && int(capLen) > len(p.payload) {
		p.truncated = true
	}
	return p, nil
}

// accept defers an accept verdict into the current batch.
func (q *queue) accept(id uint32) {
	// Ids increase monotonically, so keeping the highest is enough: the batch
	// verdict covers every id below it.
	if !q.hasPending || id > q.pendingAccept {
		q.pendingAccept = id
	}
	q.hasPending = true
}

// flush emits the pending batch accept, if any.
func (q *queue) flush() error {
	if !q.hasPending {
		return nil
	}
	id := q.pendingAccept
	q.hasPending = false
	return q.sendVerdict(nfqnlMsgVerdictBatch, id, nfAccept, nil)
}

// verdict issues an immediate verdict for one packet, flushing any deferred
// accepts first. Without that flush a batch message would verdict this packet's
// id as well, overriding the decision being made here.
func (q *queue) verdict(id uint32, v int, replacement []byte) error {
	if q.hasPending && q.pendingAccept < id {
		if err := q.flush(); err != nil {
			return err
		}
	}
	q.hasPending = false
	return q.sendVerdict(nfqnlMsgVerdict, id, v, replacement)
}

// sendVerdict marshals into the reusable verdict buffer and writes it.
func (q *queue) sendVerdict(msgType int, id uint32, v int, replacement []byte) error {
	return q.send(q.marshalVerdict(msgType, id, v, replacement))
}

// marshalVerdict builds a verdict message in the reusable buffer.
func (q *queue) marshalVerdict(msgType int, id uint32, v int, replacement []byte) []byte {
	total := nlmsgHdrLen + nfgenmsgLen + nlaHdrLen + 8
	if replacement != nil {
		total += nlaHdrLen + nlmsgAlign(len(replacement))
	}
	if cap(q.vbuf) < total {
		q.vbuf = make([]byte, 0, total*2)
	}
	b := q.vbuf[:total]
	for i := range b {
		b[i] = 0
	}

	binary.LittleEndian.PutUint32(b[0:4], uint32(total))
	binary.LittleEndian.PutUint16(b[4:6], uint16((nfnlSubsysQueue<<8)|msgType))
	binary.LittleEndian.PutUint16(b[6:8], uint16(netlink.Request))
	// Sequence and port id stay zero: the kernel does not correlate verdicts,
	// and nothing reads an ack for them.

	off := nlmsgHdrLen
	b[off] = q.family
	b[off+1] = unix.NFNETLINK_V0
	binary.BigEndian.PutUint16(b[off+2:off+4], q.num)
	off += nfgenmsgLen

	// struct nfqnl_msg_verdict_hdr { __be32 verdict; __be32 id; }
	binary.LittleEndian.PutUint16(b[off:off+2], uint16(nlaHdrLen+8))
	binary.LittleEndian.PutUint16(b[off+2:off+4], nfqaVerdictHdr)
	binary.BigEndian.PutUint32(b[off+4:off+8], uint32(v))
	binary.BigEndian.PutUint32(b[off+8:off+12], id)
	off += nlaHdrLen + 8

	if replacement != nil {
		binary.LittleEndian.PutUint16(b[off:off+2], uint16(nlaHdrLen+len(replacement)))
		binary.LittleEndian.PutUint16(b[off+2:off+4], nfqaPayload)
		copy(b[off+nlaHdrLen:], replacement)
	}
	return b
}

// writeRaw sends one marshalled message, waiting for writability through the
// runtime poller rather than blocking a thread.
func (q *queue) writeRaw(b []byte) error {
	var werr error
	err := q.rc.Write(func(fd uintptr) bool {
		werr = unix.Sendmsg(int(fd), b, nil, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}, 0)
		if werr == unix.EAGAIN || werr == unix.EWOULDBLOCK {
			return false
		}
		return true
	})
	if err != nil {
		return err
	}
	return werr
}

func nlmsgAlign(n int) int { return (n + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1) }

func cfgCmd(cmd, family uint8) []byte { return []byte{cmd, 0, 0, family} }

func cfgParams(maxPacketLen uint32) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[0:4], maxPacketLen)
	b[4] = nfqnlCopyPacket
	return b
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}
