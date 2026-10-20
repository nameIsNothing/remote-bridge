package winrmlease

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/platform/windows"
)

type fixtureRunner struct{ calls int }

func (r *fixtureRunner) Run(context.Context, windows.Command) (windows.Result, error) {
	r.calls++
	return windows.Result{Stdout: `{"start":"123456789"}`}, nil
}

func TestLeaseAcceptsThreeHoursAndRejectsLongerDeadline(t *testing.T) {
	if MaxLifetime != 3*time.Hour {
		t.Fatal("managed WinRM lifetime must be three hours")
	}
	root := t.TempDir()
	lease := Lease{InstanceID: "ssh-0123456789ab", SID: "S-1-5-21-1000", Username: `TEST\user`, Hostname: "TEST", ControllerPID: 123, ExpiresAt: time.Now().Add(3 * time.Hour)}
	dir := filepath.Join(root, RootName, lease.InstanceID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	runner := &fixtureRunner{}
	runtime, err := Prepare(context.Background(), runner, root, lease)
	if err != nil || runtime == nil || !runtime.Lease.ExpiresAt.Equal(lease.ExpiresAt.UTC().Truncate(time.Second)) {
		t.Fatalf("three-hour lease rejected or changed: %+v %v", runtime, err)
	}
	lease.ExpiresAt = time.Now().Add(3*time.Hour + time.Second)
	if _, err := Prepare(context.Background(), runner, root, lease); err == nil || runner.calls != 1 {
		t.Fatal("overlong lease reached system configuration")
	}
}
func TestLeasePreparationValidationAndRevocation(t *testing.T) {
	root := t.TempDir()
	lease := Lease{InstanceID: "ssh-0123456789ab", SID: "S-1-5-21-1000", Username: `TEST\张三`, Hostname: "TEST", ControllerPID: 123, ExpiresAt: time.Now().Add(time.Minute)}
	runner := &fixtureRunner{}
	if _, err := Prepare(context.Background(), runner, root, Lease{}); err == nil || runner.calls != 0 {
		t.Fatal("invalid lease reached system runner")
	}
	// The fake runner makes no system/ACL changes. Only temp metadata is written.
	dir := filepath.Join(root, RootName, lease.InstanceID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	runtime, err := Prepare(context.Background(), runner, root, lease)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.Lease.Active || runtime.Lease.ControllerStart != "123456789" {
		t.Fatalf("%+v", runtime.Lease)
	}
	if err := RevokeFile(runtime.Path, "ssh-ffffffffffff"); err == nil {
		t.Fatal("foreign instance revoked")
	}
	if err := RevokeFile(runtime.Path, lease.InstanceID); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(runtime.Path)
	if err != nil {
		t.Fatal(err)
	}
	var revoked Lease
	if err := json.Unmarshal(data, &revoked); err != nil || revoked.Active {
		t.Fatalf("revocation not saved: %s %v", data, err)
	}
	if err := RevokeFile(runtime.Path, lease.InstanceID); err != nil {
		t.Fatal("repeated revoke:", err)
	}
}
func TestFeedbackRejectsWrongIdentityAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feedback.json")
	runtime := &Runtime{Lease: Lease{InstanceID: "ssh-0123456789ab", SID: "S-1-5-21-1000", Username: `TEST\张三`}, SignalPath: path}
	good := Feedback{InstanceID: runtime.Lease.InstanceID, SID: runtime.Lease.SID, Username: runtime.Lease.Username, State: "connected", SessionID: "rb-0123456789abcdef01234567"}
	for _, field := range []string{"valid", "sid", "instance", "username", "session", "state", "oversize"} {
		t.Run(field, func(t *testing.T) {
			got := good
			switch field {
			case "sid":
				got.SID = "S-1-5-21-2000"
			case "instance":
				got.InstanceID = "ssh-ffffffffffff"
			case "username":
				got.Username = "other"
			case "session":
				got.SessionID = "../../bad"
			case "state":
				got.State = "ready"
			}
			data, _ := json.Marshal(got)
			if field == "oversize" {
				data = []byte(strings.Repeat("x", 8193))
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			_, err := runtime.Feedback()
			if (field == "valid") != (err == nil) {
				t.Fatalf("field=%s error=%v", field, err)
			}
		})
	}
}

func TestTargetHeartbeatStopsAfterCloseAndReportsWriteFailure(t *testing.T) {
	root := t.TempDir()
	original := time.Now().UTC().Add(-2 * time.Second)
	runtime := &Runtime{Lease: Lease{Version: 2, InstanceID: "ssh-0123456789ab", Active: true, HeartbeatAt: original, ExpiresAt: time.Now().Add(time.Minute)}, Path: filepath.Join(root, "lease.json")}
	if err := runtime.save(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runtime.Maintain(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(runtime.Path)
		if err != nil {
			t.Fatal(err)
		}
		var lease Lease
		if err := json.Unmarshal(data, &lease); err != nil {
			t.Fatal(err)
		}
		if lease.HeartbeatAt.After(original) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("target did not publish heartbeat")
		}
		time.Sleep(30 * time.Millisecond)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closed target kept publishing")
	}
	data, _ := os.ReadFile(runtime.Path)
	var closed Lease
	if err := json.Unmarshal(data, &closed); err != nil || closed.Active {
		t.Fatalf("close state lost: %s %v", data, err)
	}
	broken := &Runtime{Lease: Lease{Active: true, ExpiresAt: time.Now().Add(time.Minute)}, Path: filepath.Join(root, "missing", "lease.json")}
	if err := broken.Maintain(ctx); err == nil {
		t.Fatal("heartbeat write failure was hidden")
	}
}
