//go:build !windows

package cliutil

import "os/exec"

func configurePasswordHelper(cmd *exec.Cmd) {}
