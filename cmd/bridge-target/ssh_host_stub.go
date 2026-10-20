//go:build !windows

package main

import "errors"

func runSSHServiceHost(args []string) int { return 2 }

func sshControllerStartMillis(pid int) (int64, error) {
	return 0, errors.New("Windows service host is not supported on this platform")
}
