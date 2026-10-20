//go:build !windows

package main

import "net"

func confirmSSHPairing(_ string, _ *net.UDPAddr) bool { return false }
