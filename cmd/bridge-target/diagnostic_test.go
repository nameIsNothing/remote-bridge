package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"remote-bridge/internal/diagnostic"
)

func diagnosticTestLogger(t *testing.T) *diagnostic.Logger {
	t.Helper()
	logger, err := diagnostic.New(diagnostic.Options{Directory: t.TempDir(), Filename: "bridge-target.jsonl", Version: version, Mode: "gui"})
	if err != nil {
		t.Fatal(err)
	}
	targetDiagnostics.Lock()
	previous, previousErr := targetDiagnostics.logger, targetDiagnostics.err
	targetDiagnostics.logger, targetDiagnostics.err = logger, nil
	targetDiagnostics.Unlock()
	t.Cleanup(func() {
		targetDiagnostics.Lock()
		targetDiagnostics.logger, targetDiagnostics.err = previous, previousErr
		targetDiagnostics.Unlock()
	})
	return logger
}

func TestGUIConfigurationFailureKeepsReadableRedactedLog(t *testing.T) {
	logger := diagnosticTestLogger(t)
	const secret = "temporary-secret-from-account-creation"
	logger.AddSecret(secret)
	backend := &guiFakeBackend{start: func(context.Context, func(guiEvent)) (guiSession, error) {
		return nil, errors.New("回收旧配置失败：file locked; " + secret)
	}}
	controller, wait := guiTestController(t, backend)
	controller.Check()
	wait(func(state guiSnapshot) bool { return state.CanStart })
	controller.Start()
	state := wait(func(state guiSnapshot) bool { return state.Phase == "error" && !state.Busy })
	if state.LogPath != logger.Path() || strings.Contains(state.Diagnostics(), secret) {
		t.Fatalf("visible diagnostic path/secret filter failed: %q", state.Diagnostics())
	}
	data, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatal("raw account secret persisted")
	}
	found := false
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["event"] == "configuration.failed" {
			found = true
			if record["level"] != "error" || !strings.Contains(record["error"].(string), "file locked") {
				t.Fatalf("failure reason missing: %#v", record)
			}
		}
	}
	if !found {
		t.Fatal("terminal configuration failure not persisted")
	}
}

func TestHostDiagnosticCaptureIgnoresOutputAndPreservesFailure(t *testing.T) {
	logger := diagnosticTestLogger(t)
	input := `{"level":"info","event":"service.started"}
{"level":"error","event":"service.job.failed","error":"AssignProcessToJobObject: Access is denied.","stdout":"DO-NOT-LOG-REMOTE-COMMAND-OUTPUT","command":"DO-NOT-LOG-COMMAND"}
invalid-json
`
	captureDiagnosticRecords(strings.NewReader(input), "ssh-test")
	data, err := os.ReadFile(logger.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "DO-NOT-LOG") || strings.Contains(string(data), "service.started") {
		t.Fatal("non-diagnostic content was copied")
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["event"] != "host.service.job.failed" || record["instance"] != "ssh-test" || !strings.Contains(record["error"].(string), "Access is denied") {
		t.Fatalf("host failure lost: %#v", record)
	}
}
