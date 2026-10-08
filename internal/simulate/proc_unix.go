//go:build unix

package simulate

import (
	"os/exec"
	"syscall"
)

// killProcessGroupOnCancel runs cmd in its own process group and makes
// cancellation SIGKILL the whole group: a timed-out `go` must not leave a
// child (git, a VCS helper) behind holding cmd's stdout/stderr pipes open.
func killProcessGroupOnCancel(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
