//go:build darwin || linux

package main

import "remote-bridge/internal/unixssh"

func runPlatformTarget(args []string) (int, bool) {
	if len(args) == 0 {
		return unixssh.Run(nil), true
	}
	switch args[0] {
	case "ssh":
		return unixssh.Run(args[1:]), true
	case "ssh-unix-run":
		return unixssh.Controller(args[1:]), true
	case "ssh-unix-host":
		if len(args) != 2 {
			return 2, true
		}
		return unixssh.Guardian(args[1]), true
	case "ssh-unix-session":
		if len(args) != 2 {
			return 2, true
		}
		return unixssh.Session(args[1]), true
	}
	return 0, false
}
