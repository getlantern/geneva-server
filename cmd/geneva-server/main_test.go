package main

import "testing"

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

// TestValidateRequiresNonZeroMark pins that the mark is required even with
// --no-nft. The mark is what the reinjector stamps via SO_MARK, and with rules
// managed externally it is the only thing that ruleset can use to tell a
// reinjected packet from an original one — at zero, reinjected packets are
// re-queued forever.
func TestValidateRequiresNonZeroMark(t *testing.T) {
	for _, noNFT := range []bool{false, true} {
		o := &runCmd{Mode: "prod", Port: 443, OutQueue: 100, InQueue: 101, Mark: 0, NoNFT: noNFT}
		if err := o.validate(); err == nil {
			t.Errorf("validate accepted --mark=0 with --no-nft=%v", noNFT)
		}
		o.Mark = 0x67656e
		if err := o.validate(); err != nil {
			t.Errorf("validate rejected a valid config with --no-nft=%v: %v", noNFT, err)
		}
	}
}
