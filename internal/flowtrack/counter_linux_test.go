//go:build linux

package flowtrack

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	ct "github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"
)

func TestCountIsBoundedWhileConntrackDumpIsBusy(t *testing.T) {
	dumpSlot <- struct{}{}
	defer func() { <-dumpSlot }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := (Counter{}).Count(ctx, 1, 443)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Count error = %v, want deadline exceeded", err)
	}
}

func TestNeutralizeDeadlineRetainsDumpSlotUntilTransactionReturns(t *testing.T) {
	original := neutralizeNetlink
	t.Cleanup(func() { neutralizeNetlink = original })
	started := make(chan struct{})
	release := make(chan struct{})
	neutralizeNetlink = func(uint16) (int, error) {
		close(started)
		<-release
		return 1, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (Counter{}).Neutralize(ctx, 443)
		done <- err
	}()
	<-started
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Neutralize error = %v, want deadline exceeded", err)
	}
	select {
	case dumpSlot <- struct{}{}:
		<-dumpSlot
		t.Fatal("neutralization released the dump slot before its kernel transaction returned")
	default:
	}

	close(release)
	deadline := time.After(time.Second)
	for {
		select {
		case dumpSlot <- struct{}{}:
			<-dumpSlot
			return
		case <-deadline:
			t.Fatal("neutralization did not release the dump slot after its transaction returned")
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func TestAdapterFlowIsOuterIPv4TCPToProxyPort(t *testing.T) {
	flow := ct.Flow{TupleOrig: ct.Tuple{
		IP:    ct.IPTuple{SourceAddress: net.ParseIP("192.0.2.1"), DestinationAddress: net.ParseIP("192.0.2.2")},
		Proto: ct.ProtoTuple{Protocol: unix.IPPROTO_TCP, DestinationPort: 443},
	}}
	if !adapterFlow(flow, 443) {
		t.Fatal("matching outer IPv4/TCP flow was excluded")
	}
	for name, mutate := range map[string]func(*ct.Flow){
		"wrong port": func(f *ct.Flow) { f.TupleOrig.Proto.DestinationPort = 80 },
		"UDP":        func(f *ct.Flow) { f.TupleOrig.Proto.Protocol = unix.IPPROTO_UDP },
		"IPv6": func(f *ct.Flow) {
			f.TupleOrig.IP.SourceAddress = net.ParseIP("2001:db8::1")
			f.TupleOrig.IP.DestinationAddress = net.ParseIP("2001:db8::2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := flow
			mutate(&other)
			if adapterFlow(other, 443) {
				t.Fatal("non-adapter flow was counted")
			}
		})
	}
}

func TestNeutralMarkPreservesAllBitsOutsideReservation(t *testing.T) {
	for _, mark := range []uint32{0, 0x438, 0x440, 745, 0x00000fff} {
		got := neutralMark(mark)
		if got&0xfffff000 != 0x67000000 {
			t.Fatalf("neutral namespace for %#x = %#x", mark, got)
		}
		if got&0x00000fff != mark&0x00000fff {
			t.Fatalf("neutralization changed non-Geneva bits: %#x -> %#x", mark, got)
		}
	}
}
