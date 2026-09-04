//go:build linux

package nfqueue

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type fakeConfigExecutor struct {
	message netlink.Message
	err     error
}

func (f *fakeConfigExecutor) Execute(m netlink.Message) ([]netlink.Message, error) {
	f.message = m
	return nil, f.err
}

func TestRequiredFailOpenQueueConfiguration(t *testing.T) {
	steps := queueConfigSteps(unix.AF_INET, 123, 0xffff, 77)
	var step *configStep
	for i := range steps {
		if steps[i].what == "enable required fail-open and conntrack metadata" {
			step = &steps[i]
			break
		}
	}
	if step == nil || step.resid != 123 || len(step.attrs) != 2 {
		t.Fatalf("fail-open step = %+v", step)
	}
	values := map[uint16]uint32{}
	for _, attr := range step.attrs {
		if len(attr.Data) != 4 {
			t.Fatalf("attribute %d length = %d", attr.Type, len(attr.Data))
		}
		values[attr.Type] = binary.BigEndian.Uint32(attr.Data)
	}
	wantFlags := uint32(nfqaCfgFFailOpen | nfqaCfgFConntrack)
	if values[nfqaCfgMask] != wantFlags || values[nfqaCfgFlags] != wantFlags {
		t.Fatalf("fail-open mask/flags = %#x/%#x", values[nfqaCfgMask], values[nfqaCfgFlags])
	}

	wantErr := errors.New("kernel rejected flag")
	fake := &fakeConfigExecutor{err: wantErr}
	q := &queue{cfg: fake, family: unix.AF_INET}
	if err := q.config(step.resid, step.attrs); !errors.Is(err, wantErr) {
		t.Fatalf("config error = %v, want kernel ACK error", err)
	}
	if fake.message.Header.Flags != netlink.Request|netlink.Acknowledge {
		t.Fatalf("config flags = %#x", fake.message.Header.Flags)
	}
}

// Run explicitly inside an isolated network namespace before release:
// GENEVA_NFQUEUE_INTEGRATION=1 go test ./internal/nfqueue -run TestOpenQueueIntegration
func TestOpenQueueIntegration(t *testing.T) {
	if os.Getenv("GENEVA_NFQUEUE_INTEGRATION") != "1" {
		t.Skip("set GENEVA_NFQUEUE_INTEGRATION=1 inside an isolated root network namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_NET_ADMIN")
	}
	q, err := openQueue(62000, 0xffff, 8)
	if err != nil {
		t.Fatalf("kernel did not acknowledge required fail-open configuration: %v", err)
	}
	if collision, err := openQueue(62000, 0xffff, 8); err == nil {
		_ = collision.Close()
		t.Fatal("second listener acquired an already-bound NFQUEUE")
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

// buildPacketBody assembles an NFQNL_MSG_PACKET body the way the kernel does,
// so the parser is tested against the wire format rather than against itself.
func buildPacketBody(id uint32, payload []byte, capLen uint32) []byte {
	return buildMarkedPacketBody(id, 0, 0, payload, capLen)
}

func buildMarkedPacketBody(id, generationMark, routingMark uint32, payload []byte, capLen uint32) []byte {
	b := []byte{unix.AF_INET, unix.NFNETLINK_V0, 0, 0} // nfgenmsg; res_id big-endian

	// struct nfqnl_msg_packet_hdr { __be32 packet_id; __be16 hw_protocol; __u8 hook; }
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], id)
	b = append(b, attr(nfqaPacketHdr, hdr)...)
	if generationMark != 0 {
		m := make([]byte, 4)
		binary.BigEndian.PutUint32(m, generationMark)
		ct := attr(ctaMark|0x4000, m) // NLA_F_NET_BYTEORDER
		b = append(b, attr(nfqaCt|0x8000, ct)...)
	}
	if routingMark != 0 {
		m := make([]byte, 4)
		binary.BigEndian.PutUint32(m, routingMark)
		b = append(b, attr(nfqaMark, m)...)
	}

	if capLen != 0 {
		cl := make([]byte, 4)
		binary.BigEndian.PutUint32(cl, capLen)
		b = append(b, attr(nfqaCapLen, cl)...)
	}
	// Payload last, as the kernel sends it.
	b = append(b, attr(nfqaPayload, payload)...)
	return b
}

func attr(typ uint16, data []byte) []byte {
	out := make([]byte, nlmsgAlign(nlaHdrLen+len(data)))
	binary.LittleEndian.PutUint16(out[0:2], uint16(nlaHdrLen+len(data)))
	binary.LittleEndian.PutUint16(out[2:4], typ)
	copy(out[nlaHdrLen:], data)
	return out
}

func TestParsePacket(t *testing.T) {
	payload := []byte{0x45, 0x00, 0x00, 0x28, 0xde, 0xad, 0xbe, 0xef}

	t.Run("id and payload", func(t *testing.T) {
		p, err := parsePacket(buildPacketBody(0x01020304, payload, 0))
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		if p.id != 0x01020304 {
			t.Errorf("id = %#x, want %#x", p.id, 0x01020304)
		}
		if string(p.payload) != string(payload) {
			t.Errorf("payload = % x, want % x", p.payload, payload)
		}
		if p.truncated {
			t.Error("packet reported truncated with no NFQA_CAP_LEN")
		}
	})

	t.Run("conntrack metadata selects generation without skb mutation", func(t *testing.T) {
		p, err := parsePacket(buildMarkedPacketBody(9, 0x6702a000, 0x438, payload, 0))
		if err != nil {
			t.Fatal(err)
		}
		if p.generationMark != 0x6702a000 {
			t.Fatalf("conntrack mark = %#x", p.generationMark)
		}
		if p.routingMark != 0x438 {
			t.Fatalf("routing mark = %#x", p.routingMark)
		}
	})

	t.Run("payload aliases the buffer", func(t *testing.T) {
		// The whole point of the fast path: no copy per packet. If this ever
		// starts copying, the allocation cost comes back.
		body := buildPacketBody(1, payload, 0)
		p, err := parsePacket(body)
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		body[len(body)-1] = 0x99
		if p.payload[len(p.payload)-1] != 0x99 {
			t.Error("payload was copied out of the read buffer")
		}
	})

	t.Run("truncated capture is flagged", func(t *testing.T) {
		// The kernel copied 8 bytes of a 1500-byte packet: manipulating that
		// prefix would put a corrupt packet on the wire.
		p, err := parsePacket(buildPacketBody(7, payload, 1500))
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		if !p.truncated {
			t.Error("short capture not flagged as truncated")
		}
	})

	t.Run("full-length capture is not flagged", func(t *testing.T) {
		p, err := parsePacket(buildPacketBody(7, payload, uint32(len(payload))))
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		if p.truncated {
			t.Error("full capture flagged as truncated")
		}
	})

	t.Run("unpadded final attribute", func(t *testing.T) {
		// The kernel pads attributes to 4 bytes except the last one in a
		// message, where the padding is simply absent. Stepping over it by the
		// aligned length walks off the end of the buffer — which is exactly
		// what crashed the first version of this parser against a real kernel.
		odd := []byte{0x45, 0x00, 0x00, 0x25, 0x01} // 5 bytes: attr len 9, aligned 12
		body := buildPacketBody(3, odd, 0)
		body = body[:len(body)-3] // drop the trailing pad the helper added
		p, err := parsePacket(body)
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		if string(p.payload) != string(odd) {
			t.Errorf("payload = % x, want % x", p.payload, odd)
		}
	})

	t.Run("malformed attribute rejected", func(t *testing.T) {
		body := buildPacketBody(1, payload, 0)
		// Claim an attribute longer than the buffer.
		binary.LittleEndian.PutUint16(body[4:6], 0xffff)
		if _, err := parsePacket(body); err == nil {
			t.Error("oversized attribute accepted")
		}
	})

	t.Run("short message rejected", func(t *testing.T) {
		if _, err := parsePacket([]byte{0x02}); err == nil {
			t.Error("truncated nfgenmsg accepted")
		}
	})
}

// wrapMsg puts a body in a netlink message header of the given type.
func wrapMsg(msgType uint16, body []byte) []byte {
	b := make([]byte, nlmsgHdrLen+len(body))
	binary.LittleEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.LittleEndian.PutUint16(b[4:6], msgType)
	copy(b[nlmsgHdrLen:], body)
	return b
}

func TestForEachPacket(t *testing.T) {
	ctx := context.Background()
	packetType := uint16((nfnlSubsysQueue << 8) | nfqnlMsgPacket)

	t.Run("several packets in one read", func(t *testing.T) {
		// The point of the fast path: one syscall can return many packets.
		var buf []byte
		for _, id := range []uint32{10, 11, 12} {
			msg := wrapMsg(packetType, buildPacketBody(id, []byte{0x45, 0, 0, 0x28}, 0))
			buf = append(buf, msg...)
			buf = append(buf, make([]byte, nlmsgAlign(len(msg))-len(msg))...)
		}
		var ids []uint32
		if err := forEachPacket(ctx, buf, func(p packet) error {
			ids = append(ids, p.id)
			return nil
		}); err != nil {
			t.Fatalf("forEachPacket: %v", err)
		}
		if len(ids) != 3 || ids[0] != 10 || ids[1] != 11 || ids[2] != 12 {
			t.Errorf("ids = %v, want [10 11 12]", ids)
		}
	})

	t.Run("unpadded final message", func(t *testing.T) {
		// A message whose length is not a multiple of 4 and which sits at the
		// end of the buffer: the aligned step would run past it.
		body := buildPacketBody(1, []byte{0x45, 0x00, 0x00, 0x25, 0x01}, 0)
		body = body[:len(body)-3]
		var seen int
		if err := forEachPacket(ctx, wrapMsg(packetType, body), func(packet) error {
			seen++
			return nil
		}); err != nil {
			t.Fatalf("forEachPacket: %v", err)
		}
		if seen != 1 {
			t.Errorf("saw %d packets, want 1", seen)
		}
	})

	t.Run("non-packet messages are skipped", func(t *testing.T) {
		buf := wrapMsg(uint16(netlink.Error), []byte{0, 0, 0, 0})
		if err := forEachPacket(ctx, buf, func(packet) error {
			t.Error("callback ran for a non-packet message")
			return nil
		}); err != nil {
			t.Fatalf("forEachPacket: %v", err)
		}
	})

	t.Run("lying message length rejected", func(t *testing.T) {
		buf := wrapMsg(packetType, buildPacketBody(1, []byte{0x45}, 0))
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(buf)+64))
		if err := forEachPacket(ctx, buf, func(packet) error { return nil }); err == nil {
			t.Error("message longer than the buffer accepted")
		}
	})
}

func TestMarshalVerdict(t *testing.T) {
	q := &queue{num: 100, family: unix.AF_INET}

	t.Run("plain verdict", func(t *testing.T) {
		b := q.marshalVerdict(nfqnlMsgVerdict, 0x11223344, nfAccept, nil)
		if got := int(binary.LittleEndian.Uint32(b[0:4])); got != len(b) {
			t.Errorf("nlmsg_len = %d, want %d", got, len(b))
		}
		if got, want := binary.LittleEndian.Uint16(b[4:6]), uint16((nfnlSubsysQueue<<8)|nfqnlMsgVerdict); got != want {
			t.Errorf("nlmsg_type = %#x, want %#x", got, want)
		}
		if got, want := binary.LittleEndian.Uint16(b[6:8]), uint16(netlink.Request); got != want {
			t.Errorf("nlmsg_flags = %#x, want %#x", got, want)
		}
		// nfgenmsg: res_id carries the queue number, big-endian.
		if got := binary.BigEndian.Uint16(b[nlmsgHdrLen+2 : nlmsgHdrLen+4]); got != 100 {
			t.Errorf("res_id = %d, want 100", got)
		}
		off := nlmsgHdrLen + nfgenmsgLen
		if got, want := binary.LittleEndian.Uint16(b[off+2:off+4]), uint16(nfqaVerdictHdr); got != want {
			t.Errorf("attr type = %d, want %d", got, want)
		}
		if got := binary.BigEndian.Uint32(b[off+4 : off+8]); got != nfAccept {
			t.Errorf("verdict = %d, want %d", got, nfAccept)
		}
		if got := binary.BigEndian.Uint32(b[off+8 : off+12]); got != 0x11223344 {
			t.Errorf("id = %#x, want %#x", got, 0x11223344)
		}
	})

	t.Run("verdict with replacement packet", func(t *testing.T) {
		replacement := []byte{1, 2, 3, 4, 5}
		b := q.marshalVerdict(nfqnlMsgVerdict, 9, nfAccept, replacement)
		off := nlmsgHdrLen + nfgenmsgLen + nlaHdrLen + 8
		if got, want := binary.LittleEndian.Uint16(b[off+2:off+4]), uint16(nfqaPayload); got != want {
			t.Errorf("payload attr type = %d, want %d", got, want)
		}
		if got, want := int(binary.LittleEndian.Uint16(b[off:off+2])), nlaHdrLen+len(replacement); got != want {
			t.Errorf("payload attr len = %d, want %d", got, want)
		}
		if got := string(b[off+nlaHdrLen : off+nlaHdrLen+len(replacement)]); got != string(replacement) {
			t.Errorf("payload = % x, want % x", got, replacement)
		}
	})

	t.Run("buffer is reused across calls", func(t *testing.T) {
		q := &queue{num: 1}
		first := q.marshalVerdict(nfqnlMsgVerdict, 1, nfAccept, nil)
		second := q.marshalVerdict(nfqnlMsgVerdict, 2, nfAccept, nil)
		if &first[0] != &second[0] {
			t.Error("verdict buffer reallocated between calls")
		}
		// Stale bytes from a longer previous message must not survive.
		long := q.marshalVerdict(nfqnlMsgVerdict, 3, nfAccept, []byte{9, 9, 9, 9})
		short := q.marshalVerdict(nfqnlMsgVerdict, 4, nfAccept, nil)
		if len(short) >= len(long) {
			t.Fatalf("expected the short message to be shorter: %d vs %d", len(short), len(long))
		}
		if got := int(binary.LittleEndian.Uint32(short[0:4])); got != len(short) {
			t.Errorf("nlmsg_len = %d, want %d after reuse", got, len(short))
		}
	})
}

// TestVerdictBatching is the correctness half of the syscall optimization: a
// batch verdict applies to every packet id up to the one it names, so a
// deferred run of accepts must be flushed before an individual verdict for a
// later packet — otherwise the batch would accept a packet that was meant to be
// dropped or rewritten.
func TestVerdictBatching(t *testing.T) {
	type msg struct {
		typ int
		id  uint32
		v   int
	}
	var sent []msg
	newQueue := func() *queue {
		q := &queue{num: 100}
		q.send = func(b []byte) error {
			off := nlmsgHdrLen + nfgenmsgLen
			sent = append(sent, msg{
				typ: int(binary.LittleEndian.Uint16(b[4:6]) & 0xff),
				v:   int(binary.BigEndian.Uint32(b[off+4 : off+8])),
				id:  binary.BigEndian.Uint32(b[off+8 : off+12]),
			})
			return nil
		}
		return q
	}

	t.Run("a run of accepts becomes one batch message", func(t *testing.T) {
		sent = nil
		q := newQueue()
		q.accept(1)
		q.accept(2)
		q.accept(3)
		if len(sent) != 0 {
			t.Fatalf("accepts sent eagerly: %+v", sent)
		}
		if err := q.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if len(sent) != 1 {
			t.Fatalf("got %d messages, want 1: %+v", len(sent), sent)
		}
		if sent[0].typ != nfqnlMsgVerdictBatch || sent[0].id != 3 || sent[0].v != nfAccept {
			t.Errorf("got %+v, want batch accept of id 3", sent[0])
		}
	})

	t.Run("pending accepts flush before a later drop", func(t *testing.T) {
		sent = nil
		q := newQueue()
		q.accept(1)
		q.accept(2)
		if err := q.verdict(3, nfDrop, nil); err != nil {
			t.Fatalf("verdict: %v", err)
		}
		if len(sent) != 2 {
			t.Fatalf("got %d messages, want 2: %+v", len(sent), sent)
		}
		if sent[0].typ != nfqnlMsgVerdictBatch || sent[0].id != 2 {
			t.Errorf("first message = %+v, want batch accept of id 2", sent[0])
		}
		if sent[1].typ != nfqnlMsgVerdict || sent[1].id != 3 || sent[1].v != nfDrop {
			t.Errorf("second message = %+v, want drop of id 3", sent[1])
		}
	})

	t.Run("nothing is sent twice", func(t *testing.T) {
		sent = nil
		q := newQueue()
		q.accept(5)
		if err := q.verdict(6, nfAccept, []byte{1, 2, 3}); err != nil {
			t.Fatalf("verdict: %v", err)
		}
		if err := q.flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if len(sent) != 2 {
			t.Errorf("got %d messages, want 2 (batch for 5, mod-accept for 6): %+v", len(sent), sent)
		}
	})
}
