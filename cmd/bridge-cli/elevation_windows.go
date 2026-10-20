//go:build windows

package main

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const (
	seeMaskNoCloseProcess = 0x00000040
	swShowNormal          = 1
	waitObject0           = 0x00000000
	infiniteWait          = 0xffffffff
	errorCancelled        = 1223
)

var (
	shell32             = syscall.NewLazyDLL("shell32.dll")
	shellExecuteExWProc = shell32.NewProc("ShellExecuteExW")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	waitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	getExitCodeProcess  = kernel32.NewProc("GetExitCodeProcess")
	closeHandle         = kernel32.NewProc("CloseHandle")
)

// shellExecuteInfo mirrors SHELLEXECUTEINFOW. uintptr is used for Windows
// handles/pointers so the layout is correct for both amd64 and 386 builds.
type shellExecuteInfo struct {
	cbSize         uint32
	fMask          uint32
	hwnd           uintptr
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       uintptr
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      uintptr
	dwHotKey       uint32
	hIconOrMonitor uintptr
	hProcess       uintptr
}

// launchElevated uses the ShellExecuteExW "runas" verb, which always presents
// the normal Windows UAC consent UI. It waits for the elevated child and
// returns that child's exit code; it never changes the requested execution
// level of the whole bridge-cli binary.
func launchElevated(executable string, args []string) (int, error) {
	if strings.TrimSpace(executable) == "" {
		return -1, errors.New("elevated executable path is empty")
	}
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return -1, fmt.Errorf("encode UAC verb: %w", err)
	}
	file, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return -1, fmt.Errorf("encode executable path: %w", err)
	}
	parameters, err := syscall.UTF16PtrFromString(joinWindowsArgs(args))
	if err != nil {
		return -1, fmt.Errorf("encode elevated arguments: %w", err)
	}
	info := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: parameters,
		nShow:        swShowNormal,
	}
	result, _, callErr := shellExecuteExWProc.Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		if windowsErrorCode(callErr) == errorCancelled {
			return -1, errElevationCancelled
		}
		if callErr == nil {
			return -1, errors.New("ShellExecuteExW failed to start elevated bridge-cli")
		}
		return -1, fmt.Errorf("ShellExecuteExW: %w", callErr)
	}
	if info.hProcess == 0 {
		return -1, errors.New("ShellExecuteExW returned no child process handle")
	}
	defer func() { _, _, _ = closeHandle.Call(info.hProcess) }()
	waitResult, _, waitErr := waitForSingleObject.Call(info.hProcess, infiniteWait)
	if waitResult != waitObject0 {
		if waitErr == nil {
			return -1, errors.New("waiting for elevated bridge-cli failed")
		}
		return -1, fmt.Errorf("waiting for elevated bridge-cli: %w", waitErr)
	}
	var exitCode uint32
	gotCode, _, codeErr := getExitCodeProcess.Call(info.hProcess, uintptr(unsafe.Pointer(&exitCode)))
	if gotCode == 0 {
		if codeErr == nil {
			return -1, errors.New("GetExitCodeProcess failed")
		}
		return -1, fmt.Errorf("GetExitCodeProcess: %w", codeErr)
	}
	return int(exitCode), nil
}

func windowsErrorCode(err error) uint32 {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}

func joinWindowsArgs(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, quoteWindowsArg(arg))
	}
	return strings.Join(quoted, " ")
}

// quoteWindowsArg follows CommandLineToArgvW quoting rules. Current trust
// targets are already restricted to a no-whitespace grammar, but keeping the
// launcher correct for paths and future validated arguments avoids accidental
// parameter merging.
func quoteWindowsArg(value string) string {
	if value != "" && !strings.ContainsAny(value, " \t\n\v\"") {
		return value
	}
	var out strings.Builder
	out.WriteByte('"')
	backslashes := 0
	for _, r := range value {
		if r == '\\' {
			backslashes++
			continue
		}
		if r == '"' {
			out.WriteString(strings.Repeat("\\", backslashes*2+1))
			out.WriteRune(r)
			backslashes = 0
			continue
		}
		if backslashes > 0 {
			out.WriteString(strings.Repeat("\\", backslashes))
			backslashes = 0
		}
		out.WriteRune(r)
	}
	if backslashes > 0 {
		out.WriteString(strings.Repeat("\\", backslashes*2))
	}
	out.WriteByte('"')
	return out.String()
}
