//go:build linux

package nfqueue

import (
	"testing"

	"github.com/getlantern/geneva-server/internal/generation"
)

func TestReinjectionMarkPreservesExactRoutingIdentity(t *testing.T) {
	for _, routingMark := range []uint32{0x438, 0x440, 745} {
		got, err := reinjectionMark(routingMark)
		if err != nil {
			t.Fatal(err)
		}
		if got != routingMark {
			t.Fatalf("SO_MARK = %#x, want exact routing identity %#x", got, routingMark)
		}
	}
	if _, err := reinjectionMark(generation.Namespace | 1); err == nil {
		t.Fatal("accepted routing mark overlapping private Geneva bits")
	}
}
