//go:build linux

// Package flowtrack reads the kernel conntrack table to decide when an
// immutable Geneva engine generation is safe to garbage-collect.
package flowtrack

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ct "github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"

	"github.com/getlantern/geneva-server/internal/generation"
)

// Counter counts live, adapter-owned TCP flows.
//
// IdleAfter, when positive, leaves out ESTABLISHED flows that have carried no
// packet for that long. A connection the path killed without a FIN or RST
// (a censor dropping a flow after its handshake, a client that vanished)
// stays ESTABLISHED in conntrack for nf_conntrack_tcp_timeout_established,
// five days by default, and would hold its generation's drain open for all of
// it. Idleness is read from conntrack itself: an entry's remaining timeout
// restarts at the established timeout on every packet, so a live connection
// keeps counting however long it lasts.
//
// While a flow retransmits or has data outstanding, the kernel re-arms its
// timer at the much shorter max-retrans or unacknowledged timeout instead.
// Such a timer says nothing about idle time, so the flow counts; if the path
// has killed it, that short timer removes the entry soon anyway.
type Counter struct {
	IdleAfter time.Duration
}

// establishedTimeoutPath is where the kernel exposes the timeout an
// ESTABLISHED TCP entry restarts at on every packet. maxRetransTimeoutPath and
// unacknowledgedTimeoutPath hold the shorter timeouts it restarts at instead
// while the flow retransmits or has unacknowledged data.
var (
	establishedTimeoutPath    = "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"
	maxRetransTimeoutPath     = "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_max_retrans"
	unacknowledgedTimeoutPath = "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_unacknowledged"
)

// tcpConntrackEstablished is the kernel's TCP_CONNTRACK_ESTABLISHED state.
const tcpConntrackEstablished = 3

// liveness decides which dumped flows still hold a drain open.
type liveness struct {
	idleAfter   time.Duration
	established time.Duration
	// shortTimer is the longest timeout an ESTABLISHED entry can restart at
	// while it retransmits or has unacknowledged data. A remaining timeout at
	// or below it may have been re-armed by the latest packet.
	shortTimer time.Duration
}

// newLiveness reads the conntrack TCP timeouts. Without them idleness cannot
// be measured, so every flow counts: holding a drain open is the safe mistake.
func (c Counter) newLiveness() liveness {
	if c.IdleAfter <= 0 {
		return liveness{}
	}
	established, ok := readTimeout(establishedTimeoutPath)
	if !ok {
		return liveness{}
	}
	maxRetrans, ok := readTimeout(maxRetransTimeoutPath)
	if !ok {
		return liveness{}
	}
	unacknowledged, ok := readTimeout(unacknowledgedTimeoutPath)
	if !ok {
		return liveness{}
	}
	return liveness{
		idleAfter:   c.IdleAfter,
		established: established,
		shortTimer:  max(maxRetrans, unacknowledged),
	}
}

func readTimeout(path string) (time.Duration, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	seconds, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil || seconds == 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// live reports whether a flow still counts toward a drain.
func (l liveness) live(flow ct.Flow) bool {
	if l.idleAfter <= 0 || l.established <= 0 {
		return true
	}
	tcp := flow.ProtoInfo.TCP
	if tcp == nil || tcp.State != tcpConntrackEstablished {
		return true
	}
	remaining := time.Duration(flow.Timeout) * time.Second
	if remaining >= l.established || remaining <= l.shortTimer {
		return true
	}
	return l.established-remaining < l.idleAfter
}

// Conntrack's netlink dump does not accept a context. Keep lifecycle calls
// bounded by running at most one dump at a time and allowing the caller to
// leave when its context expires. A timed-out dump retains the slot until the
// kernel operation returns, preventing repeated requests from accumulating
// blocked netlink goroutines.
var dumpSlot = make(chan struct{}, 1)

// Count returns flows whose full Geneva namespace+generation bits match id and
// whose original tuple targeted the configured proxy port. Connmark bits
// outside the adapter reservation are intentionally ignored.
func (c Counter) Count(ctx context.Context, id uint32, port uint16) (int, error) {
	mark, err := generation.Mark(id)
	if err != nil {
		return 0, err
	}
	return count(ctx, ct.Filter{Mark: mark, Mask: generation.Mask}, port, c.newLiveness())
}

// Counts returns one consistent namespace snapshot grouped by generation.
// Startup uses it to find orphan marks without racing several separate dumps.
// It deliberately ignores IdleAfter: it decides which generation IDs are still
// in use, and an ID must not be handed to new DNA while any entry, idle or
// not, still carries its mark.
func (Counter) Counts(ctx context.Context, port uint16) (map[uint32]int, error) {
	flows, err := dump(ctx, ct.Filter{Mark: generation.Namespace, Mask: 0xff000000})
	if err != nil {
		return nil, err
	}
	counts := make(map[uint32]int)
	for _, flow := range flows {
		id, ok := generation.ID(flow.Mark)
		if ok && adapterFlow(flow, port) {
			counts[id]++
		}
	}
	return counts, nil
}

// Neutralize marks every existing unowned outer IPv4/TCP connection to the
// proxy port with reserved generation zero. A temporary nft rule neutralizes
// concurrent new SYNs, making the activation boundary race-free.
func (Counter) Neutralize(ctx context.Context, port uint16) (int, error) {
	return updateNeutral(ctx, port)
}

func count(ctx context.Context, filter ct.Filter, port uint16, alive liveness) (int, error) {
	flows, err := dump(ctx, filter)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, flow := range flows {
		if adapterFlow(flow, port) && alive.live(flow) {
			n++
		}
	}
	return n, nil
}

func adapterFlow(flow ct.Flow, port uint16) bool {
	return flow.TupleOrig.IP.SourceAddress.To4() != nil &&
		flow.TupleOrig.IP.DestinationAddress.To4() != nil &&
		flow.TupleOrig.Proto.Protocol == unix.IPPROTO_TCP &&
		flow.TupleOrig.Proto.DestinationPort == port
}

func dump(ctx context.Context, filter ct.Filter) ([]ct.Flow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case dumpSlot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	type result struct {
		flows []ct.Flow
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-dumpSlot }()
		flows, err := dumpNetlink(filter)
		done <- result{flows: flows, err: err}
	}()
	select {
	case r := <-done:
		return r.flows, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func dumpNetlink(filter ct.Filter) ([]ct.Flow, error) {
	c, err := ct.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("dial conntrack netlink: %w", err)
	}
	defer func() { _ = c.Close() }()
	flows, err := c.DumpFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("dump conntrack: %w", err)
	}
	return flows, nil
}

func updateNeutral(ctx context.Context, port uint16) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case dumpSlot <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	type result struct {
		updated int
		err     error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-dumpSlot }()
		updated, err := neutralizeNetlinkTransaction(ctx, port)
		done <- result{updated: updated, err: err}
	}()
	select {
	case r := <-done:
		return r.updated, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

type neutralConntrack interface {
	Close() error
	DumpFilter(ct.Filter) ([]ct.Flow, error)
	Update(ct.Flow) error
}

// dialNeutralConntrack is a test seam around the context-free conntrack
// library. Production cancellation closes the connection to interrupt a
// pending dump; the post-dump context check is still authoritative because a
// socket implementation may not unblock immediately.
var dialNeutralConntrack = func() (neutralConntrack, error) { return ct.Dial(nil) }

func neutralizeNetlinkTransaction(ctx context.Context, port uint16) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c, err := dialNeutralConntrack()
	if err != nil {
		return 0, fmt.Errorf("dial conntrack netlink: %w", err)
	}
	interruptDone := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = c.Close()
		close(interruptDone)
	})
	defer func() {
		if stopInterrupt() {
			_ = c.Close()
			return
		}
		<-interruptDone
	}()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	flows, err := c.DumpFilter(ct.Filter{})
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return 0, contextErr
		}
		return 0, fmt.Errorf("dump conntrack for neutral boundary: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	updated := 0
	for _, flow := range flows {
		if !adapterFlow(flow, port) || flow.Mark&generation.Mask != 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return updated, err
		}
		flow.Mark = neutralMark(flow.Mark)
		if err := c.Update(flow); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return updated, contextErr
			}
			return updated, fmt.Errorf("neutralize conntrack: %w", err)
		}
		updated++
	}
	return updated, nil
}

func neutralMark(mark uint32) uint32 {
	return (mark & ^generation.Mask) | generation.Namespace
}
