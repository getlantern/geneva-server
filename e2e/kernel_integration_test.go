//go:build linux

package e2e

import (
	"os"
	"os/exec"
	"testing"
)

// TestKernelGenerationLifecycle is the discoverable release gate for behavior
// which string/fake tests cannot prove. It runs the sidecar and proxy in one
// real Docker network namespace and is intentionally opt-in for ordinary CI.
func TestKernelGenerationLifecycle(t *testing.T) {
	if os.Getenv("GENEVA_KERNEL_INTEGRATION") != "1" {
		t.Skip("set GENEVA_KERNEL_INTEGRATION=1 and run as root before release")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root for network namespaces, nftables, conntrack and NFQUEUE")
	}
	for _, tool := range []string{"docker", "sha256sum", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required: %v", tool, err)
		}
	}
	cmd := exec.Command("bash", "./kernel-generations.sh")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
