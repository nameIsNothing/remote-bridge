//go:build !windows

package sshclient

import "os/exec"

func hideCapturedProcess(*exec.Cmd) {}
