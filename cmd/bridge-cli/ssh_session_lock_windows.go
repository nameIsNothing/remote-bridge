//go:build windows

package main

import (
	"errors"
	"os"
	"syscall"
)

func trySSHSessionLock(path string) (*os.File, error) {
	widePath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(widePath, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if errors.Is(err, syscall.Errno(32)) || errors.Is(err, syscall.Errno(33)) {
		return nil, errSSHSessionBusy
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
