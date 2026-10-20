//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

func hideTargetHelper(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }
func sshProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, _, _ := guiKernel32.NewProc("OpenProcess").Call(0x00100000, 0, uintptr(pid))
	if process == 0 {
		return false
	}
	defer guiKernel32.NewProc("CloseHandle").Call(process)
	status, _, _ := guiKernel32.NewProc("WaitForSingleObject").Call(process, 0)
	return status == 258
}

type sshJobLimits struct {
	ProcessTime, JobTime                                       int64
	Flags                                                      uint32
	MinWorkingSet, MaxWorkingSet                               uintptr
	ActiveLimit                                                uint32
	Affinity                                                   uintptr
	Priority, Scheduling                                       uint32
	IO                                                         [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}

func assignSSHJob(pid int) (uintptr, error) {
	job, _, err := guiKernel32.NewProc("CreateJobObjectW").Call(0, 0)
	if job == 0 {
		return 0, err
	}
	limits := sshJobLimits{Flags: 0x00002000} // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if ok, _, err := guiKernel32.NewProc("SetInformationJobObject").Call(job, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		closeSSHJob(job)
		return 0, err
	}
	process, _, err := guiKernel32.NewProc("OpenProcess").Call(0x0100|0x0001, 0, uintptr(pid))
	if process == 0 {
		closeSSHJob(job)
		return 0, fmt.Errorf("无法管理本次 SSH 服务进程：%w", err)
	}
	defer guiKernel32.NewProc("CloseHandle").Call(process)
	if ok, _, err := guiKernel32.NewProc("AssignProcessToJobObject").Call(job, process); ok == 0 {
		closeSSHJob(job)
		return 0, err
	}
	return job, nil
}

func closeSSHJob(job uintptr) { guiKernel32.NewProc("CloseHandle").Call(job) }

func validateSSHOwnedPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil || !filepath.IsAbs(path) {
		return fmt.Errorf("临时目录必须使用绝对路径")
	}
	for current := abs; ; current = filepath.Dir(current) {
		pointer, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attributes, err := syscall.GetFileAttributes(pointer)
		if err == nil && attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("临时目录包含链接或重解析点，未执行系统修改：%s", current)
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func sshProgramDataDirectory() string {
	buffer := make([]uint16, 260)
	result, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("SHGetFolderPathW").Call(0, 0x0023, 0, 0, uintptr(unsafe.Pointer(&buffer[0])))
	if result != 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer)
}

func acquireTargetLock() (func(), error) {
	name, _ := syscall.UTF16PtrFromString(`Global\RemoteBridge-TemporarySSH-Entry`)
	handle, _, err := guiKernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, fmt.Errorf("无法锁定本次连接配置：%v", err)
	}
	// A held named kernel object reserves one entry without thread ownership.
	if err == syscall.Errno(183) {
		guiKernel32.NewProc("CloseHandle").Call(handle)
		return nil, fmt.Errorf("另一个 Remote Bridge 窗口已在配置或连接，请先结束旧入口")
	}
	return func() { guiKernel32.NewProc("CloseHandle").Call(handle) }, nil
}

func installedSSHCandidates() []string {
	system := make([]uint16, 260)
	guiKernel32.NewProc("GetSystemDirectoryW").Call(uintptr(unsafe.Pointer(&system[0])), uintptr(len(system)))
	programFiles := make([]uint16, 260)
	syscall.NewLazyDLL("shell32.dll").NewProc("SHGetFolderPathW").Call(0, 0x0026, 0, 0, uintptr(unsafe.Pointer(&programFiles[0])))
	return []string{filepath.Join(syscall.UTF16ToString(system), "OpenSSH", "sshd.exe"), filepath.Join(syscall.UTF16ToString(programFiles), "OpenSSH", "sshd.exe")}
}
func trustedInstalledSSHD(path string) bool {
	for _, candidate := range installedSSHCandidates() {
		if samePath(path, candidate) {
			return true
		}
	}
	return false
}
func nativeTargetIsAdministrator() bool {
	value, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin").Call()
	return value != 0
}
