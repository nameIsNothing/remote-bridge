//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	managerConsoleKernel32    = syscall.NewLazyDLL("kernel32.dll")
	managerConsoleProcessList = managerConsoleKernel32.NewProc("GetConsoleProcessList")
	managerConsoleWindow      = managerConsoleKernel32.NewProc("GetConsoleWindow")
)

// A double-clicked console belongs to this process alone. A shared terminal
// already retains printed errors, and a background caller must never wait
// for input. The caller limits this helper to failed, argument-free startup.
func pauseManagerOnStartupError() {
	// CREATE_NO_WINDOW may still report this PID alone, but has no console
	// window to preserve. Avoid blocking callers that capture process pipes.
	window, _, _ := managerConsoleWindow.Call()
	if window == 0 {
		return
	}
	var processes [2]uint32
	count, _, _ := managerConsoleProcessList.Call(uintptr(unsafe.Pointer(&processes[0])), uintptr(len(processes)))
	if count != 1 || processes[0] != uint32(os.Getpid()) {
		return
	}
	fmt.Fprintln(os.Stderr, "启动未完成。按回车关闭窗口。")
	// EOF or a read error also releases the console; no credentials are read.
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
