//go:build windows

package sshclient

import (
	"os/exec"
	"syscall"
)

// Captured helpers need no separate console. Interactive SSH never calls
// this helper, so the user's PowerShell session remains fully visible.
func hideCapturedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}
