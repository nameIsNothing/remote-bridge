//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func managedWindowsAvailable() bool { return true }
func managedShowError(message string) {
	text, _ := syscall.UTF16PtrFromString(message)
	title, _ := syscall.UTF16PtrFromString("Remote Bridge · 连接未完成")
	syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
