//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSSHRecoveryChildFixture(t *testing.T) {
	if os.Getenv("REMOTE_BRIDGE_TEST_RECOVERY_CHILD") != "1" {
		return
	}
	time.Sleep(time.Minute)
	os.Exit(0)
}

func startSSHRecoveryFixture(t *testing.T, program string) *exec.Cmd {
	t.Helper()
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(program), 0700); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(current)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.OpenFile(program, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0700)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	source.Close()
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("fixture copy failed: %v %v", copyErr, closeErr)
	}
	command := exec.Command(program, "-test.run=^TestSSHRecoveryChildFixture$")
	command.Env = append(os.Environ(), "REMOTE_BRIDGE_TEST_RECOVERY_CHILD=1")
	hideTargetHelper(command)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	return command
}

type scopedNativeRecovery struct {
	nativeSSHRecoveryOperations
	pids map[uint32]bool
}

// The real OS snapshot and handles are exercised; only test-owned PIDs are
// supplied to the engine so this test never inspects or stops workstation SSH.
func (ops scopedNativeRecovery) Candidates() ([]sshRecoveryCandidate, error) {
	rows, err := ops.nativeSSHRecoveryOperations.Candidates()
	var selected []sshRecoveryCandidate
	for _, row := range rows {
		if ops.pids[row.pid] {
			selected = append(selected, row)
		}
	}
	return selected, err
}

func TestNativeSSHRecoveryStopsOnlyTheOwnedOrphanImage(t *testing.T) {
	root := t.TempDir()
	owned := startSSHRecoveryFixture(t, filepath.Join(root, "openssh", "OpenSSH-Win64", "sshd-session.exe"))
	foreign := startSSHRecoveryFixture(t, filepath.Join(t.TempDir(), "sshd-session.exe"))
	other := startSSHRecoveryFixture(t, filepath.Join(root, "openssh", "unrelated.exe"))
	ops := scopedNativeRecovery{pids: map[uint32]bool{uint32(owned.Process.Pid): true, uint32(foreign.Process.Pid): true, uint32(other.Process.Pid): true}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := recoverSSHProcesses(ctx, "fixture", root, ops); err != nil {
		t.Fatal(err)
	}
	if sshProcessAlive(owned.Process.Pid) {
		t.Fatal("owned orphan survived recovery")
	}
	if !sshProcessAlive(foreign.Process.Pid) || !sshProcessAlive(other.Process.Pid) {
		t.Fatal("recovery affected another executable or another instance")
	}
}
