//go:build linux

// Package flowtrack reads the kernel conntrack table to decide when an
// immutable Geneva engine generation is safe to garbage-collect.
package flowtrack

import (
	"context"
	"fmt"

	ct "github.com/ti-mo/conntrack"
	"golang.org/x/sys/unix"

	"github.com/getlantern/geneva-server/internal/generation"
)

// Counter counts live, adapter-owned TCP flows.
type Counter struct{}

// Conntrack's netlink dump does not accept a context. Keep lifecycle calls
// bounded by running at most one dump at a time and allowing the caller to
// leave when its context expires. A timed-out dump retains the slot until the
// kernel operation returns, preventing repeated requests from accumulating
// blocked netlink goroutines.
var dumpSlot = make(chan struct{}, 1)

// Count returns flows whose full Geneva namespace+generation bits match id and
// whose original tuple targeted the configured proxy port. Connmark bits
// outside the adapter reservation are intentionally ignored.
func (Counter) Count(ctx context.Context, id uint32, port uint16) (int, error) {
	mark, err := generation.Mark(id)
	if err != nil {
		return 0, err
	}
	return count(ctx, ct.Filter{Mark: mark, Mask: generation.Mask}, port)
}

// Counts returns one consistent namespace snapshot grouped by generation.
// Startup uses it to find orphan marks without racing several separate dumps.
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

func count(ctx context.Context, filter ct.Filter, port uint16) (int, error) {
	flows, err := dump(ctx, filter)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, flow := range flows {
		if adapterFlow(flow, port) {
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
		updated, err := neutralizeNetlink(port)
		done <- result{updated: updated, err: err}
	}()
	select {
	case r := <-done:
		return r.updated, r.err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// neutralizeNetlink is a test seam around the library's synchronous dump and
// update transaction. The caller keeps dumpSlot owned until this returns even
// when its context has already expired, so a wedged kernel cannot accumulate
// goroutines or overlapping namespace mutations.
var neutralizeNetlink = neutralizeNetlinkTransaction

func neutralizeNetlinkTransaction(port uint16) (int, error) {
	c, err := ct.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("dial conntrack netlink: %w", err)
	}
	defer func() { _ = c.Close() }()
	flows, err := c.DumpFilter(ct.Filter{})
	if err != nil {
		return 0, fmt.Errorf("dump conntrack for neutral boundary: %w", err)
	}
	updated := 0
	for _, flow := range flows {
		if !adapterFlow(flow, port) || flow.Mark&generation.Mask != 0 {
			continue
		}
		flow.Mark = neutralMark(flow.Mark)
		if err := c.Update(flow); err != nil {
			return updated, fmt.Errorf("neutralize conntrack: %w", err)
		}
		updated++
	}
	return updated, nil
}

func neutralMark(mark uint32) uint32 {
	return (mark & ^generation.Mask) | generation.Namespace
}
