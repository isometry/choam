//go:build !unix

package simulate

import "os/exec"

// killProcessGroupOnCancel is a no-op where process groups are unavailable;
// cmd.WaitDelay still bounds the wait for orphaned pipe holders.
func killProcessGroupOnCancel(*exec.Cmd) {}
