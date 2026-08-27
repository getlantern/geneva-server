//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

// runServer is unavailable off Linux: the sidecar depends on NFQUEUE, raw
// sockets, and nftables. The validate subcommand still works everywhere.
func runServer(_ *runCmd) error {
	return fmt.Errorf("geneva-server run requires Linux (NFQUEUE); this is %s", runtime.GOOS)
}
