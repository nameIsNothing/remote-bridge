//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func sshHostTestArguments(now time.Time) []string {
	id := "ssh-host-unit-test"
	root := sshRuntimeDirectory(id)
	return []string{
		"--instance", id,
		"--root", root,
		"--sshd", filepath.Join(root, "openssh", "OpenSSH Win64", "sshd.exe"),
		"--controller", "12345",
		"--controller-start", strconv.FormatInt(now.Add(-time.Minute).UnixMilli(), 10),
		"--expires", now.Add(20 * time.Minute).Format(time.RFC3339),
	}
}

func changeSSHHostArgument(args []string, flag, value string) []string {
	changed := append([]string(nil), args...)
	for i := 0; i < len(changed)-1; i++ {
		if changed[i] == flag {
			changed[i+1] = value
			return changed
		}
	}
	return append(changed, flag, value)
}

func TestSSHHostOptionsBindInstanceExecutableAndLifetime(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	args := sshHostTestArguments(now)
	options, err := parseSSHHostOptions(args, now)
	if err != nil {
		t.Fatal(err)
	}
	if options.instance != args[1] || !samePath(options.root, sshRuntimeDirectory(options.instance)) || options.controller != 12345 || !options.expires.Equal(now.Add(20*time.Minute)) {
		t.Fatalf("unexpected options: %#v", options)
	}
	// Known installed paths are permitted without consulting PATH or requiring
	// a package file to exist. Parsing itself does not start/install anything.
	for _, installed := range installedSSHCandidates() {
		if !filepath.IsAbs(installed) {
			continue
		}
		if _, err := parseSSHHostOptions(changeSSHHostArgument(args, "--sshd", installed), now); err != nil {
			t.Errorf("installed path %q: %v", installed, err)
		}
	}
}

func TestSSHHostOptionsRejectUnboundOrStaleArguments(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	args := sshHostTestArguments(now)
	root := args[3]
	tests := []struct {
		name, flag, value string
	}{
		{"missing_instance", "--instance", ""},
		{"traversal_instance", "--instance", "../another"},
		{"different_instance", "--instance", "ssh-other-instance"},
		{"relative_root", "--root", "relative"},
		{"other_root", "--root", filepath.Join(filepath.Dir(root), "ssh-other-instance")},
		{"root_whitespace", "--root", root + " "},
		{"root_newline", "--root", root + "\n"},
		{"root_nul", "--root", root + "\x00"},
		{"sshd_path_search", "--sshd", "sshd.exe"},
		{"sshd_outside_package", "--sshd", filepath.Join(filepath.Dir(root), "openssh", "sshd.exe")},
		{"sshd_next_to_package", "--sshd", filepath.Join(root, "openssh-other", "sshd.exe")},
		{"sshd_package_traversal", "--sshd", filepath.Join(root, "openssh", "..", "sshd.exe")},
		{"sshd_win32_dot_component", "--sshd", root + `\openssh\.. \sshd.exe`},
		{"sshd_win32_space_component", "--sshd", root + `\openssh\package \sshd.exe`},
		{"sshd_other_executable", "--sshd", filepath.Join(root, "openssh", "not-sshd.exe")},
		{"sshd_quote", "--sshd", filepath.Join(root, "openssh", "\"sshd.exe")},
		{"zero_controller", "--controller", "0"},
		{"negative_controller", "--controller", "-1"},
		{"overflow_controller", "--controller", "4294967296"},
		{"missing_controller_start", "--controller-start", "0"},
		{"future_controller_start", "--controller-start", strconv.FormatInt(now.Add(time.Second).UnixMilli(), 10)},
		{"invalid_expiry", "--expires", "later"},
		{"expired", "--expires", now.Add(-time.Second).Format(time.RFC3339)},
		{"exactly_expired", "--expires", now.Format(time.RFC3339)},
		{"expiry_extended", "--expires", now.Add(sshPlanTTL + time.Second).Format(time.RFC3339)},
		{"unknown_flag", "--password", "must-not-be-accepted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSSHHostOptions(changeSSHHostArgument(args, test.flag, test.value), now); err == nil {
				t.Fatal("accepted invalid service arguments")
			}
		})
	}
	if _, err := parseSSHHostOptions(append(args, "extra"), now); err == nil {
		t.Fatal("accepted positional arguments")
	}
	if _, err := parseSSHHostOptions(changeSSHHostArgument(args, "--expires", now.Add(sshPlanTTL).Format(time.RFC3339)), now); err != nil {
		t.Fatalf("rejected exact lifetime cap: %v", err)
	}
}

func TestSSHHostStatusCannotReenterRunningOrNotifyStoppedTwice(t *testing.T) {
	var state sshHostServiceStatus
	if _, changed := nextSSHHostStatus(state, sshHostRunning, 0); changed {
		t.Fatal("reported ready before initialization")
	}
	var changed bool
	state, changed = nextSSHHostStatus(state, sshHostStartPending, 0)
	if !changed || state.controlsAccepted != 0 || state.checkPoint == 0 || state.waitHint == 0 {
		t.Fatalf("invalid starting status: %#v", state)
	}
	state, changed = nextSSHHostStatus(state, sshHostRunning, 0)
	if !changed || state.controlsAccepted != sshHostAcceptStop|sshHostAcceptShutdown || state.checkPoint != 0 || state.waitHint != 0 {
		t.Fatalf("invalid running status: %#v", state)
	}
	state, changed = nextSSHHostStatus(state, sshHostStopPending, 0)
	if !changed || state.controlsAccepted != 0 {
		t.Fatalf("invalid stopping status: %#v", state)
	}
	if _, changed := nextSSHHostStatus(state, sshHostRunning, 0); changed {
		t.Fatal("service returned to Running after stop began")
	}
	state, changed = nextSSHHostStatus(state, sshHostStopped, sshHostChildError)
	if !changed || state.win32ExitCode != sshHostSpecificError || state.specificExitCode != sshHostChildError || state.checkPoint != 0 || state.waitHint != 0 || state.controlsAccepted != 0 {
		t.Fatalf("invalid failure status: %#v", state)
	}
	for _, next := range []uint32{sshHostStopped, sshHostStartPending, sshHostRunning, sshHostStopPending} {
		if _, changed := nextSSHHostStatus(state, next, 0); changed {
			t.Fatalf("allowed status %d after final STOPPED", next)
		}
	}
}

func TestSSHHostControlCancelsWithoutStartingOrReporting(t *testing.T) {
	for _, control := range []uintptr{sshHostControlStop, sshHostControlShutdown} {
		ctx, cancel := context.WithCancel(context.Background())
		host := &sshServiceHost{ctx: ctx, cancel: cancel}
		if result := host.control(control, 0, 0, 0); result != 0 || ctx.Err() == nil || host.statusHandle != 0 || host.status.currentState != 0 {
			t.Fatal("control did not cancel without changing native status")
		}
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := &sshServiceHost{ctx: ctx, cancel: cancel}
	if host.control(sshHostControlQuery, 0, 0, 0) != 0 || ctx.Err() != nil {
		t.Fatal("interrogate cancelled service")
	}
	if host.control(99, 0, 0, 0) != sshHostNotImplemented || ctx.Err() != nil {
		t.Fatal("unknown control was accepted or cancelled service")
	}
}

func TestSSHHostControllerCreationBindingReadOnly(t *testing.T) {
	created, err := sshControllerStartMillis(os.Getpid())
	if err != nil || created <= 0 || created > time.Now().UnixMilli() {
		t.Fatalf("reading current process creation: %d %v", created, err)
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	if !matchesSSHHostController(process, created) {
		t.Fatal("held process handle did not match its creation time")
	}
	if matchesSSHHostController(process, created+1) || matchesSSHHostController(process, 0) {
		t.Fatal("held handle accepted another process creation time")
	}
	if handle, err := openSSHHostController(uint32(os.Getpid()), created); err == nil || handle != 0 {
		t.Fatal("service accepted itself as the controller")
	}
	if handle, err := openSSHHostController(^uint32(0), created); err == nil || handle != 0 {
		t.Fatal("service accepted a nonexistent controller")
	}
}

func TestSSHHostInvalidInvocationCannotDispatchOrLaunch(t *testing.T) {
	if result := runSSHServiceHost(nil); result != 2 {
		t.Fatalf("missing arguments returned %d", result)
	}
	// The test executable is outside the protected instance copy. This must fail
	// read-only validation before StartServiceCtrlDispatcher is ever called.
	if result := runSSHServiceHost(sshHostTestArguments(time.Now())); result != 2 {
		t.Fatalf("unprotected executable invocation returned %d", result)
	}
}
