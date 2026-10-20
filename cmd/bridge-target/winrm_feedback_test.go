package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"remote-bridge/internal/winrmlease"
)

func TestWinRMTargetFeedbackUsesVerifiedAccount(t *testing.T) {
	root := t.TempDir()
	lease := &winrmlease.Runtime{Lease: winrmlease.Lease{InstanceID: "ssh-0123456789ab", SID: "S-1-5-21-1000", Username: `TEST\张三`}, SignalPath: filepath.Join(root, "feedback.json")}
	feedback := winrmlease.Feedback{InstanceID: lease.Lease.InstanceID, SID: lease.Lease.SID, Username: lease.Lease.Username, SessionID: "rb-0123456789abcdef01234567", State: "connected"}
	save := func() {
		t.Helper()
		data, _ := json.Marshal(feedback)
		temp := lease.SignalPath + ".tmp"
		if err := os.WriteFile(temp, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(temp, lease.SignalPath); err != nil {
			t.Fatal(err)
		}
	}
	save()
	session := &winrmDesktopSession{lease: lease, monitorDone: make(chan struct{})}
	events := make(chan guiEvent, 4)
	go session.monitorFeedback(func(event guiEvent) { events <- event })
	defer close(session.monitorDone)
	wait := func(state string) {
		t.Helper()
		select {
		case event := <-events:
			if event.Kind != state || event.Manager != feedback.SessionID {
				t.Fatalf("unexpected feedback: %+v", event)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("feedback timed out")
		}
	}
	wait("connected")
	feedback.State = "disconnected"
	save()
	wait("disconnected")
	feedback.SID = "S-1-5-21-2000"
	feedback.State = "connected"
	save()
	select {
	case event := <-events:
		t.Fatalf("forged account accepted: %+v", event)
	case <-time.After(650 * time.Millisecond):
	}
}
