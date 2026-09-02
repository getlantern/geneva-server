// Package generation defines the conntrack-mark namespace used to keep a TCP
// connection on one immutable Geneva engine generation.
package generation

import "fmt"

// The high byte identifies Geneva, the next 12 bits carry the generation ID,
// and the low 12 bits are preserved for existing Lantern routing marks. The
// repo-wide audit which established this reservation found packet marks 0x438
// and 0x440/1088 for TPROXY, and phost route-table marks starting at 745, all
// contained in those low 12 bits; it found no CONNMARK save/restore into
// conntrack. The namespace is an explicit installation contract checked by the
// command line rather than an opportunistic high-byte match.
const (
	Mask      uint32 = 0xfffff000
	Namespace uint32 = 0x67000000
	MaxID     uint32 = 0x0fff
)

// Mark returns the namespaced conntrack mark for id.
func Mark(id uint32) (uint32, error) {
	if id == 0 || id > MaxID {
		return 0, fmt.Errorf("generation must be between 1 and %d", MaxID)
	}
	return Namespace | id<<12, nil
}

// ID extracts a Geneva generation ID from a packet or conntrack mark.
func ID(mark uint32) (uint32, bool) {
	if mark&0xff000000 != Namespace {
		return 0, false
	}
	id := (mark >> 12) & MaxID
	return id, id != 0
}
