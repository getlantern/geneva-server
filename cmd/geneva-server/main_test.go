package main

import (
	"strings"
	"testing"
)

func TestMarkFlagUnmarshalText(t *testing.T) {
	tests := []struct {
		in      string
		want    markFlag
		wantErr bool
	}{
		{in: "0", want: 0},
		{in: "100", want: 100},
		{in: "4294967295", want: 0xffffffff}, // uint32 max
		{in: "0x67656e", want: 0x67656e},
		{in: "0X10", want: 0x10},
		{in: "010", want: 10}, // leading zero is decimal, NOT octal
		{in: "0b10", wantErr: true},
		{in: "0o17", wantErr: true},
		{in: "0x", wantErr: true},
		{in: "notanumber", wantErr: true},
		{in: "4294967296", wantErr: true}, // overflows uint32
		{in: "-1", wantErr: true},
	}

	for _, tt := range tests {
		var m markFlag
		err := m.UnmarshalText([]byte(tt.in))
		if tt.wantErr {
			if err == nil {
				t.Errorf("UnmarshalText(%q) = %#x, want error", tt.in, m)
			}
			continue
		}
		if err != nil {
			t.Errorf("UnmarshalText(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if m != tt.want {
			t.Errorf("UnmarshalText(%q) = %#x, want %#x", tt.in, m, tt.want)
		}
	}
}

// TestValidateAllowsDeprecatedMarkZero pins that the old high-bit loop guard
// no longer participates in steering. Reinjection uses the packet's exact
// routing mark and the dedicated adapter socket UID.
func TestValidateAllowsDeprecatedMarkZero(t *testing.T) {
	for _, noNFT := range []bool{false, true} {
		o := &runCmd{Mode: "prod", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0, NoNFT: noNFT, ReinjectBypassUID: -1}
		if noNFT {
			o.ReinjectBypassUID = 65534
		}
		if err := o.validate(); err != nil {
			t.Errorf("deprecated --mark affected validation with --no-nft=%v: %v", noNFT, err)
		}
	}
}

func TestNoNFTRequiresExplicitReinjectionUIDContract(t *testing.T) {
	o := &runCmd{Mode: "prod", Port: 443, OutQueue: 100, InQueue: 101, NoNFT: true, ReinjectBypassUID: -1}
	if err := o.validate(); err == nil || !strings.Contains(err.Error(), "--reinject-bypass-uid") {
		t.Fatalf("no-nft without reinjection UID contract error = %v", err)
	}
	o.ReinjectBypassUID = 4242
	if err := o.validate(); err != nil {
		t.Fatalf("explicit no-nft reinjection UID rejected: %v", err)
	}
}

// TestObserveInboundRefusedInProd pins the mode gate. Observing inbound costs a
// userspace round trip per inbound packet — measured free on download-heavy
// traffic but -40% on upload-heavy, and a prod box does not get to choose which
// its users generate — in exchange for a signal an eval box produces for free.
// A prod box that needs inbound packets in userspace asks for them precisely, by
// giving its strategy an inbound tree.
func TestObserveInboundRefusedInProd(t *testing.T) {
	base := func(mode string, observe bool) *runCmd {
		return &runCmd{
			Mode: mode, Port: 443, OutQueue: 100, InQueue: 101,
			Mark: 0x67656e, ObserveInbound: observe,
		}
	}
	if err := base("prod", true).validate(); err == nil {
		t.Error("validate accepted --observe-inbound in prod mode")
	}
	if err := base("eval", true).validate(); err != nil {
		t.Errorf("validate rejected --observe-inbound in eval mode: %v", err)
	}
	if err := base("prod", false).validate(); err != nil {
		t.Errorf("validate rejected prod without the flag: %v", err)
	}
}

func TestValidateGenerationBudget(t *testing.T) {
	for _, n := range []int{-1, 33} {
		o := &runCmd{Mode: "eval", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0x67656e, MaxGenerations: n}
		if err := o.validate(); err == nil {
			t.Errorf("accepted max generations %d", n)
		}
	}
	o := &runCmd{Mode: "eval", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0x67656e}
	if err := o.validate(); err != nil || o.MaxGenerations != 3 || o.MaxScopedGenerations != 3 || o.MaxEveryPacketGenerations != 1 {
		t.Fatalf("default budgets = total %d scoped %d every %d, %v", o.MaxGenerations, o.MaxScopedGenerations, o.MaxEveryPacketGenerations, err)
	}
	o = &runCmd{Mode: "eval", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0x67656e, MaxGenerations: 1}
	if err := o.validate(); err != nil || o.MaxScopedGenerations != 1 || o.MaxEveryPacketGenerations != 1 {
		t.Fatalf("single-generation defaults = scoped %d every %d, %v", o.MaxScopedGenerations, o.MaxEveryPacketGenerations, err)
	}
	o = &runCmd{Mode: "eval", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0x67656e, MaxGenerations: 2, MaxScopedGenerations: 3}
	if err := o.validate(); err == nil {
		t.Fatal("accepted scoped budget above total")
	}
}
