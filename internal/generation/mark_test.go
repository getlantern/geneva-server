package generation

import "testing"

func TestMarkRoundTripPreservesNamespace(t *testing.T) {
	mark, err := Mark(42)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := ID(mark | 0x438); !ok || got != 42 {
		t.Fatalf("ID(%#x) = %d, %v; want 42, true", mark|0x438, got, ok)
	}
	if _, ok := ID(0x42002a00); ok {
		t.Fatal("foreign mark selected a Geneva generation")
	}
}

func TestMarkPreservesKnownLanternRoutingMarks(t *testing.T) {
	mark, err := Mark(17)
	if err != nil {
		t.Fatal(err)
	}
	for _, existing := range []uint32{0x438, 1088, 745, 746, 747} {
		combined := existing | mark
		if got := combined &^ Mask; got != existing {
			t.Errorf("existing mark %#x became %#x", existing, got)
		}
	}
}

func TestMarkRejectsReservedIDs(t *testing.T) {
	for _, id := range []uint32{0, MaxID + 1} {
		if _, err := Mark(id); err == nil {
			t.Fatalf("Mark(%d) succeeded", id)
		}
	}
}
