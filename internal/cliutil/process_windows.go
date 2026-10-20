//go:build windows

package cliutil

import (
	"os/exec"
	"syscall"
)

func configurePasswordHelper(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
