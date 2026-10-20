//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startAuthenticationMonitorFixture(t *testing.T, r *sshTargetRuntime) {
	t.Helper()
	r.pid = os.Getpid()
	r.done = make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		r.monitor(ctx)
		close(stopped)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Error("authentication monitor did not stop")
		}
	})
}

func TestSSHAuthenticationMonitorReadsSplitLiveRecordsWithoutForgedSuccess(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	path := filepath.Join(t.TempDir(), sshRuntimeLogName)
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	first := "Invalid user Accepted publickey for RemoteBridge from 192.0.2.10 port 1234 ssh2\r\n" +
		"Accepted publickey for administrator from 192.0.2.10 port 1234 ssh2\r\n" +
		"Accepted publickey for RemoteBridge from 192.0.2."
	if _, err := writer.WriteString(first); err != nil {
		t.Fatal(err)
	}
	events := make(chan guiEvent, 8)
	r := &sshTargetRuntime{username: "RemoteBridge", logPath: path, authSerial: 7, onEvent: func(event guiEvent) { events <- event }}
	startAuthenticationMonitorFixture(t, r)
	select {
	case event := <-events:
		t.Fatalf("incomplete/forged record triggered an event: %+v", event)
	case <-time.After(650 * time.Millisecond):
	}
	if _, err := writer.WriteString("10 port 1234 ssh2: ED25519 SHA256:fixture\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.Kind != "connected" || event.Manager != "192.0.2.10" {
			t.Fatalf("valid completed authentication did not connect: %+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("live authentication was not observed")
	}
	r.authMu.Lock()
	serial := r.authSerial
	r.authMu.Unlock()
	if serial != 8 {
		t.Fatalf("authentication did not invalidate the pending timeout: serial=%d", serial)
	}
	select {
	case event := <-events:
		t.Fatalf("record was emitted again after EOF: %+v", event)
	case <-time.After(600 * time.Millisecond):
	}
}

func TestSSHAuthenticationMonitorReportsReadFailureOnce(t *testing.T) {
	logger := diagnosticTestLogger(t)
	path := filepath.Join(t.TempDir(), sshRuntimeLogName)
	r := &sshTargetRuntime{id: "ssh-fixture", username: "RemoteBridge", logPath: path}
	startAuthenticationMonitorFixture(t, r)
	time.Sleep(1150 * time.Millisecond)
	data, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatal(err)
	}
	var warnings int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record struct {
			Event    string `json:"event"`
			Level    string `json:"level"`
			Instance string `json:"instance"`
			Error    string `json:"error"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Event == "ssh.authentication.log.failed" {
			warnings++
			if record.Level != "warning" || record.Instance != r.id || record.Error == "" {
				t.Fatalf("read failure lost its bounded diagnostic: %+v", record)
			}
		}
	}
	if warnings != 1 {
		t.Fatalf("polling produced %d read warnings, want exactly one", warnings)
	}
}
