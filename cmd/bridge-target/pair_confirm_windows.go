//go:build windows

package main

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// confirmSSHPairing uses the standard Windows consent dialog.  It is not a
// privilege-escalation mechanism: the target user explicitly approves only a
// public key, while the private key remains on the management machine.
func confirmSSHPairing(manager string, source *net.UDPAddr) bool {
	address := "未知地址"
	if source != nil {
		address = source.IP.String()
	}
	text := fmt.Sprintf("管理机 %s (%s) 请求临时 SSH 公钥配对。\n\n允许后，管理机可在当前窗口有效期内执行 PowerShell 命令。\n只会写入公钥，不会传输或保存管理机密码。", manager, address)
	title := "Remote Bridge SSH 配对确认"
	user32 := syscall.NewLazyDLL("user32.dll")
	messageBox := user32.NewProc("MessageBoxW")
	messagePtr, _ := syscall.UTF16PtrFromString(text)
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	const mbYesNo = 0x00000004
	const mbIconQuestion = 0x00000020
	ret, _, _ := messageBox.Call(0, uintptr(unsafe.Pointer(messagePtr)), uintptr(unsafe.Pointer(titlePtr)), mbYesNo|mbIconQuestion)
	return ret == 6 // IDYES
}
