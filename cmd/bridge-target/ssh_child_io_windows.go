//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type sshStartupInfoEx struct {
	info       syscall.StartupInfo
	attributes *byte
}

type sshChildStartup struct {
	startup     sshStartupInfoEx
	attributes  []byte
	handles     []syscall.Handle
	initialized bool
}

// Supply real standard handles even when the service has no console. OpenSSH
// logs to stderr with -e, preserving both startup and authentication records
// in a protected, share-readable file. An explicit list excludes controller, job
// and all other service handles from inheritance.
func newSSHChildStartup(root string) (_ *sshChildStartup, returnedErr error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("SSH 启动日志目录必须是绝对路径")
	}
	logPath := filepath.Join(root, sshRuntimeLogName)
	if err := validateSSHOwnedPath(logPath); err != nil {
		return nil, err
	}
	input, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	defer input.Close()
	output, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("创建 SSH 启动错误日志：%w", err)
	}
	defer output.Close()
	startup := &sshChildStartup{}
	defer func() {
		if returnedErr != nil {
			startup.Close()
		}
	}()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, err
	}
	for _, file := range []*os.File{input, output} {
		var handle syscall.Handle
		if err := syscall.DuplicateHandle(current, syscall.Handle(file.Fd()), current, &handle, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return nil, err
		}
		startup.handles = append(startup.handles, handle)
	}
	var size uintptr
	initialize := guiKernel32.NewProc("InitializeProcThreadAttributeList")
	_, _, _ = initialize.Call(0, 1, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 64<<10 {
		return nil, errors.New("无法确定 SSH 子进程句柄列表大小")
	}
	startup.attributes = make([]byte, size)
	startup.startup.attributes = &startup.attributes[0]
	if ok, _, err := initialize.Call(uintptr(unsafe.Pointer(startup.startup.attributes)), 1, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return nil, fmt.Errorf("初始化 SSH 子进程句柄列表：%w", err)
	}
	startup.initialized = true
	if ok, _, err := guiKernel32.NewProc("UpdateProcThreadAttribute").Call(
		uintptr(unsafe.Pointer(startup.startup.attributes)), 0, 0x00020002, // PROC_THREAD_ATTRIBUTE_HANDLE_LIST
		uintptr(unsafe.Pointer(&startup.handles[0])), uintptr(len(startup.handles))*unsafe.Sizeof(startup.handles[0]), 0, 0,
	); ok == 0 {
		return nil, fmt.Errorf("设置 SSH 子进程句柄列表：%w", err)
	}
	startup.startup.info = syscall.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(startup.startup)),
		Flags:      syscall.STARTF_USESHOWWINDOW | syscall.STARTF_USESTDHANDLES,
		ShowWindow: syscall.SW_HIDE,
		StdInput:   startup.handles[0], StdOutput: startup.handles[1], StdErr: startup.handles[1],
	}
	return startup, nil
}

func (startup *sshChildStartup) Close() {
	if startup.initialized {
		guiKernel32.NewProc("DeleteProcThreadAttributeList").Call(uintptr(unsafe.Pointer(startup.startup.attributes)))
		startup.initialized = false
	}
	for _, handle := range startup.handles {
		_ = syscall.CloseHandle(handle)
	}
	startup.handles = nil
	runtime.KeepAlive(startup)
}
