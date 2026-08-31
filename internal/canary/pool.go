// Package canary captures real TCP/IPv4 header field values from live proxy
// traffic so the GA brain can mutate triggers and tamper actions against values
// that actually occur on the wire, instead of random ones that would match
// nothing.
//
// It is used only in eval mode, on test boxes we control. Capture is bounded
// (distinct values per field, capped) and lock-guarded for concurrent packet
// callbacks. A small static cold-start corpus seeds the pool so the brain has
// plausible values before the first real packet arrives.
package canary

import (
	"sync"

	"github.com/getlantern/geneva/strategy"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// FieldPool holds a bounded set of distinct observed values for one field,
// preserving insertion order and counting total observations.
type FieldPool struct {
	cap   int
	order []uint32
	seen  map[uint32]uint64 // value -> observation count
	total uint64
}

func newFieldPool(cap int) *FieldPool {
	return &FieldPool{cap: cap, seen: make(map[uint32]uint64)}
}

func (f *FieldPool) add(v uint32) {
	f.total++
	if _, ok := f.seen[v]; ok {
		f.seen[v]++
		return
	}
	if len(f.order) >= f.cap {
		return // pool full; keep the earliest-seen distinct values
	}
	f.seen[v] = 1
	f.order = append(f.order, v)
}

// Values returns the distinct captured values in insertion order.
func (f *FieldPool) Values() []uint32 {
	out := make([]uint32, len(f.order))
	copy(out, f.order)
	return out
}

// Pool is the per-market capture of header field values.
type Pool struct {
	market string
	cap    int

	mu       sync.Mutex
	windows  *FieldPool // TCP window sizes
	ttls     *FieldPool // IPv4 TTLs
	ipIDs    *FieldPool // IPv4 identification
	mss      *FieldPool // TCP MSS option values
	wscale   *FieldPool // TCP window-scale option values
	flags    *FieldPool // TCP flag bitmaps observed
	options  *FieldPool // TCP option kinds present
	captured uint64
}

// NewPool creates a per-field-capacity pool for a market and seeds it with the
// static cold-start corpus.
func NewPool(market string, capacity int) *Pool {
	if capacity <= 0 {
		capacity = 64
	}
	p := &Pool{
		market:  market,
		cap:     capacity,
		windows: newFieldPool(capacity),
		ttls:    newFieldPool(capacity),
		ipIDs:   newFieldPool(capacity),
		mss:     newFieldPool(capacity),
		wscale:  newFieldPool(capacity),
		flags:   newFieldPool(capacity),
		options: newFieldPool(capacity),
	}
	p.seedColdStart()
	return p
}

// Observe implements the nfqueue.Observer contract. It never retains raw.
func (p *Pool) Observe(raw []byte, _ strategy.Direction) {
	pkt := gopacket.NewPacket(raw, layers.LayerTypeIPv4, gopacket.Lazy)
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ip == nil || tcp == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.captured++
	p.ttls.add(uint32(ip.TTL))
	p.ipIDs.add(uint32(ip.Id))
	p.windows.add(uint32(tcp.Window))
	p.flags.add(uint32(tcpFlagBits(tcp)))
	for _, opt := range tcp.Options {
		p.options.add(uint32(opt.OptionType))
		switch opt.OptionType {
		case layers.TCPOptionKindMSS:
			if len(opt.OptionData) == 2 {
				p.mss.add(uint32(opt.OptionData[0])<<8 | uint32(opt.OptionData[1]))
			}
		case layers.TCPOptionKindWindowScale:
			if len(opt.OptionData) == 1 {
				p.wscale.add(uint32(opt.OptionData[0]))
			}
		}
	}
}

func tcpFlagBits(t *layers.TCP) uint16 {
	var f uint16
	set := func(b bool, mask uint16) {
		if b {
			f |= mask
		}
	}
	set(t.FIN, 0x01)
	set(t.SYN, 0x02)
	set(t.RST, 0x04)
	set(t.PSH, 0x08)
	set(t.ACK, 0x10)
	set(t.URG, 0x20)
	set(t.ECE, 0x40)
	set(t.CWR, 0x80)
	return f
}

// Snapshot is a JSON-friendly view of the pool for the control API.
type Snapshot struct {
	Market   string   `json:"market"`
	Captured uint64   `json:"captured"`
	Windows  []uint32 `json:"tcp_windows"`
	TTLs     []uint32 `json:"ip_ttls"`
	IPIDs    []uint32 `json:"ip_ids"`
	MSS      []uint32 `json:"tcp_mss"`
	WScale   []uint32 `json:"tcp_wscale"`
	Flags    []uint32 `json:"tcp_flags"`
	Options  []uint32 `json:"tcp_option_kinds"`
}

// Snapshot returns the current captured values.
func (p *Pool) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Snapshot{
		Market:   p.market,
		Captured: p.captured,
		Windows:  p.windows.Values(),
		TTLs:     p.ttls.Values(),
		IPIDs:    p.ipIDs.Values(),
		MSS:      p.mss.Values(),
		WScale:   p.wscale.Values(),
		Flags:    p.flags.Values(),
		Options:  p.options.Values(),
	}
}
