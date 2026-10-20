//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"errors"
	"os"
	"syscall"
)

func trySSHSessionLock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errSSHSessionBusy
		}
		return nil, err
	}
	return file, nil
}
