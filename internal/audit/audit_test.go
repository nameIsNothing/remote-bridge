package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"remote-bridge/internal/model"
)

func TestAppendWritesJSONLWithoutCommandText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	command := "Get-Item secret-password.txt"
	if err := Append(path, model.AuditEvent{Type: "remote.exec", Success: true, Metadata: map[string]string{"command_hash": Digest(command)}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), command) || !strings.Contains(string(data), Digest(command)) {
		t.Fatalf("audit content is not redacted: %s", data)
	}
}
