//go:build windows

package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// The native launcher uses sshd arguments rather than Go test flags. This
// explicit child-only fixture exits before the test harness parses them.
func init() {
	if os.Getenv("REMOTE_BRIDGE_TEST_IO_CHILD") != "1" {
		return
	}
	for _, kind := range []int{syscall.STD_INPUT_HANDLE, syscall.STD_OUTPUT_HANDLE, syscall.STD_ERROR_HANDLE} {
		handle, err := syscall.GetStdHandle(kind)
		if err != nil || handle == 0 || handle == syscall.InvalidHandle {
			os.Exit(11)
		}
		if _, err := syscall.GetFileType(handle); err != nil {
			os.Exit(12)
		}
	}
	value, _ := strconv.ParseUint(os.Getenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_HANDLE"), 10, 64)
	buffer := make([]uint16, 32768)
	size, _, _ := guiKernel32.NewProc("GetFinalPathNameByHandleW").Call(uintptr(value), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
	if size > 0 && size < uintptr(len(buffer)) {
		actual := strings.TrimPrefix(syscall.UTF16ToString(buffer[:size]), `\\?\`)
		if samePath(actual, os.Getenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_PATH")) {
			os.Exit(13)
		}
	}
	_, outErr := io.WriteString(os.Stdout, "ssh-startup-stdout-fixture\n")
	_, errorErr := io.WriteString(os.Stderr, "ssh-startup-stderr-fixture\n")
	if outErr != nil || errorErr != nil {
		os.Exit(14)
	}
	if os.Getenv("REMOTE_BRIDGE_TEST_IO_HOLD") == "1" {
		// Safe synthetic sshd-style authentication output. Keep the child and
		// inherited stderr handle open so the parent must read the live file.
		if _, err := io.WriteString(os.Stderr, "sshd: Accepted publickey for fixture-user from 192.0.2.10 port 2222 ssh2: ED25519 SHA256:fixture-fingerprint\n"); err != nil {
			os.Exit(15)
		}
		for {
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Exit(0)
}

func TestNativeSSHChildReceivesOnlyExplicitStandardHandles(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	image := filepath.Join(root, "sshd.exe")
	destination, err := os.OpenFile(image, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy child: %v, %v", copyErr, closeErr)
	}
	unrelatedPath := filepath.Join(root, "excluded-handle-fixture.txt")
	unrelated, err := os.Create(unrelatedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Close()
	current, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var inheritable syscall.Handle
	if err := syscall.DuplicateHandle(current, syscall.Handle(unrelated.Fd()), current, &inheritable, 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(inheritable)
	t.Setenv("REMOTE_BRIDGE_TEST_IO_CHILD", "1")
	t.Setenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_HANDLE", strconv.FormatUint(uint64(inheritable), 10))
	t.Setenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_PATH", unrelatedPath)
	child, err := createSuspendedSSHD(sshHostOptions{root: root, sshd: image})
	if err != nil {
		t.Fatal(err)
	}
	var job uintptr
	defer func() {
		if err := stopSSHHostChild(child, job); err != nil {
			t.Errorf("fixture cleanup: %v", err)
		}
	}()
	log := filepath.Join(root, "sshd-startup.log")
	before, err := os.Stat(log)
	if err != nil || before.Size() != 0 || !sshHostHandleAlive(child.Process) {
		t.Fatalf("child ran before job assignment: %v, %v", before, err)
	}
	job, err = assignSSHJob(int(child.ProcessId))
	if err != nil {
		t.Fatal(err)
	}
	if previous, _, err := sshHostResumeThread.Call(uintptr(child.Thread)); uint32(previous) == ^uint32(0) {
		t.Fatal(err)
	}
	_ = syscall.CloseHandle(child.Thread)
	child.Thread = 0
	if status, err := syscall.WaitForSingleObject(child.Process, 5000); err != nil || status != syscall.WAIT_OBJECT_0 {
		t.Fatalf("child did not exit: %d, %v", status, err)
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(child.Process, &code); err != nil || code != 0 {
		t.Fatalf("standard handles or exclusion failed: exit=%d, err=%v", code, err)
	}
	data, err := os.ReadFile(log)
	if err != nil || string(data) != "ssh-startup-stdout-fixture\nssh-startup-stderr-fixture\n" {
		t.Fatalf("early output lost: %q, %v", data, err)
	}
}

func TestNativeSSHChildLogCanBeReadWhileChildIsAlive(t *testing.T) {
	root := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	image := filepath.Join(root, "sshd.exe")
	destination, err := os.OpenFile(image, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy child: %v, %v", copyErr, closeErr)
	}
	t.Setenv("REMOTE_BRIDGE_TEST_IO_CHILD", "1")
	t.Setenv("REMOTE_BRIDGE_TEST_IO_HOLD", "1")
	t.Setenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_HANDLE", "0")
	t.Setenv("REMOTE_BRIDGE_TEST_IO_EXCLUDED_PATH", "")
	child, err := createSuspendedSSHD(sshHostOptions{root: root, sshd: image})
	if err != nil {
		t.Fatal(err)
	}
	var job uintptr
	defer func() {
		if err := stopSSHHostChild(child, job); err != nil {
			t.Errorf("live-log fixture cleanup: %v", err)
		}
	}()
	job, err = assignSSHJob(int(child.ProcessId))
	if err != nil {
		t.Fatal(err)
	}
	if previous, _, err := sshHostResumeThread.Call(uintptr(child.Thread)); uint32(previous) == ^uint32(0) {
		t.Fatal(err)
	}
	_ = syscall.CloseHandle(child.Thread)
	child.Thread = 0

	path := filepath.Join(root, "sshd-startup.log")
	const marker = "Accepted publickey for fixture-user"
	deadline := time.Now().Add(5 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		if !sshHostHandleAlive(child.Process) {
			t.Fatal("fixture exited before the parent observed its live output")
		}
		data, err = os.ReadFile(path)
		if err == nil && strings.Contains(string(data), marker) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || !strings.Contains(string(data), marker) {
		t.Fatalf("parent could not read authentication marker before child exit: %q, %v", data, err)
	}
	if !sshHostHandleAlive(child.Process) {
		t.Fatal("fixture exited before live-log read completed")
	}
	if !strings.Contains(string(data), "ssh-startup-stderr-fixture") {
		t.Fatalf("shared stderr output missing from readable log: %q", data)
	}
}

func TestSSHChildStartupDoesNotOverwriteExistingLog(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sshd-startup.log")
	if err := os.WriteFile(path, []byte("existing-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if startup, err := newSSHChildStartup(root); err == nil || startup != nil {
		if startup != nil {
			startup.Close()
		}
		t.Fatal("existing startup log was replaced")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing-fixture" {
		t.Fatalf("existing log changed: %q, %v", data, err)
	}
}
