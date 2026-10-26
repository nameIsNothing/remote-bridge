package unixssh

import (
	"os"
	"syscall"
	"unsafe"
)

func interactiveTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	var state syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&state)))
	return err == 0
}
