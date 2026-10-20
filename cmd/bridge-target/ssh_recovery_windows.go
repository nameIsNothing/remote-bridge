//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

type nativeSSHRecoveryOperations struct{}

func (nativeSSHRecoveryOperations) Candidates() ([]sshRecoveryCandidate, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)
	entry := syscall.ProcessEntry32{Size: uint32(unsafe.Sizeof(syscall.ProcessEntry32{}))}
	var candidates []sshRecoveryCandidate
	for err = syscall.Process32First(snapshot, &entry); err == nil; err = syscall.Process32Next(snapshot, &entry) {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if sshRecoveryName(name) {
			candidates = append(candidates, sshRecoveryCandidate{pid: entry.ProcessID, name: name})
		}
	}
	if !errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return candidates, nil
}

func (nativeSSHRecoveryOperations) Open(pid uint32, terminate bool) (sshRecoveryProcess, error) {
	access := uint32(0x00100000 | 0x1000) // SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION
	if terminate {
		access |= 0x0001 // PROCESS_TERMINATE
	}
	handle, err := syscall.OpenProcess(access, false, pid)
	if errors.Is(err, syscall.Errno(87)) { // Process disappeared before OpenProcess.
		return nil, os.ErrProcessDone
	}
	if err != nil {
		return nil, err
	}
	return &nativeSSHRecoveryProcess{handle: handle}, nil
}

type nativeSSHRecoveryProcess struct{ handle syscall.Handle }

func (p *nativeSSHRecoveryProcess) Image() (string, error) {
	if p.exited() {
		return "", os.ErrProcessDone
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, err := guiKernel32.NewProc("QueryFullProcessImageNameW").Call(uintptr(p.handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 {
		if p.exited() {
			return "", os.ErrProcessDone
		}
		return "", err
	}
	return syscall.UTF16ToString(buffer[:size]), nil
}

func (p *nativeSSHRecoveryProcess) exited() bool {
	state, _, _ := guiKernel32.NewProc("WaitForSingleObject").Call(uintptr(p.handle), 0)
	return state == 0 // WAIT_OBJECT_0
}

func (p *nativeSSHRecoveryProcess) Terminate() error {
	if p.exited() {
		return nil
	}
	if err := syscall.TerminateProcess(p.handle, 0); err != nil && !p.exited() {
		return err
	}
	return nil
}

func (p *nativeSSHRecoveryProcess) Wait(ctx context.Context) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		state, _, err := guiKernel32.NewProc("WaitForSingleObject").Call(uintptr(p.handle), 100)
		switch state {
		case 0:
			return nil
		case 258: // WAIT_TIMEOUT
		default:
			return fmt.Errorf("WaitForSingleObject：%w", err)
		}
	}
	return errors.New("进程未在 5 秒内完全退出")
}

func (p *nativeSSHRecoveryProcess) Close() { _ = syscall.CloseHandle(p.handle) }
