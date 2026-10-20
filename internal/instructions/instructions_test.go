package instructions

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRequest(dir string) Request {
	return Request{
		OutputDir:    dir,
		PlanID:       "rb-test-1",
		Hostname:     "TARGET-PC",
		Address:      "192.168.1.30",
		Addresses:    []string{"192.168.1.30", "10.0.0.7"},
		Port:         5985,
		Transport:    "http",
		Username:     `TARGET-PC\RB-test-1`,
		StatePath:    `C:\Users\target\AppData\Local\RemoteBridge\bridge-plan.json`,
		TargetBinary: `E:\Remote Bridge\bridge-target.exe`,
		CLIPath:      `E:\Remote Bridge\bridge-cli.exe`,
		ExpiresAt:    time.Now().UTC().Add(time.Hour),
	}
}

func TestExportWritesReadableNonSecretDocuments(t *testing.T) {
	dir := t.TempDir()
	result, err := Export(testRequest(dir))
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if result.MarkdownPath != filepath.Join(dir, MarkdownFileName) || result.JSONPath != filepath.Join(dir, JSONFileName) {
		t.Fatalf("unexpected output paths: %#v", result)
	}

	jsonData, err := os.ReadFile(result.JSONPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc Document
	if err := json.Unmarshal(jsonData, &doc); err != nil {
		t.Fatalf("JSON is not readable: %v", err)
	}
	if doc.Version != SchemaVersion || doc.PlanID != "rb-test-1" || doc.Address != "192.168.1.30" {
		t.Fatalf("unexpected document: %#v", doc)
	}
	if len(doc.Addresses) != 2 || doc.Addresses[0] != doc.Address {
		t.Fatalf("addresses = %#v", doc.Addresses)
	}
	if doc.TargetBinary != `.\bridge-target.exe` || doc.CLIPath != `.\bridge-cli.exe` {
		t.Fatalf("portable executable names = %q, %q", doc.TargetBinary, doc.CLIPath)
	}
	if strings.Contains(string(jsonData), `E:\Remote Bridge`) {
		t.Fatal("absolute removable-drive path leaked into JSON")
	}
	if strings.Contains(strings.ToLower(string(jsonData)), "password") {
		t.Fatal("password-looking JSON field leaked")
	}

	markdownData, err := os.ReadFile(result.MarkdownPath)
	if err != nil {
		t.Fatal(err)
	}
	markdown := string(markdownData)
	if strings.Contains(markdown, "````") || strings.Count(markdown, "```") != 6 {
		t.Fatalf("markdown fences are malformed: %q", markdown)
	}
	if !strings.Contains(markdown, "'.\\bridge-cli.exe' trust '192.168.1.30'") || !strings.Contains(markdown, "'.\\bridge-cli.exe' exec") || !strings.Contains(markdown, "'.\\bridge-target.exe' revoke") {
		t.Fatalf("markdown does not contain portable commands: %s", markdown)
	}
	if doc.TrustCommand != `'.\bridge-cli.exe' trust '192.168.1.30'` {
		t.Fatalf("trust command = %q", doc.TrustCommand)
	}
	if strings.Contains(markdown, "SuperSecret") || strings.Contains(markdown, "pairing-code-value") {
		t.Fatal("secret marker leaked into markdown")
	}
}

func TestExportCanReplaceBothFilesAtomically(t *testing.T) {
	dir := t.TempDir()
	first := testRequest(dir)
	if _, err := Export(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.PlanID = "rb-test-2"
	second.ExpiresAt = time.Now().UTC().Add(2 * time.Hour)
	if _, err := Export(second); err != nil {
		t.Fatalf("second Export() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, JSONFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"plan_id": "rb-test-2"`) {
		t.Fatalf("old JSON remained after replacement: %s", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file was not cleaned up: %s", entry.Name())
		}
	}
}

func TestExportRejectsSecretLookingOverrideAndInvalidInput(t *testing.T) {
	req := testRequest(t.TempDir())
	req.RevokeCommand = `bridge-target revoke --password hunter2`
	if _, err := Export(req); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Fatalf("secret-looking command error = %v", err)
	}

	req = testRequest(t.TempDir())
	req.ExpiresAt = time.Time{}
	if _, err := Export(req); err == nil || !strings.Contains(err.Error(), "expiry") {
		t.Fatalf("missing expiry error = %v", err)
	}

	if _, err := Export(Request{}); err == nil || !strings.Contains(err.Error(), "output directory") {
		t.Fatalf("missing output directory error = %v", err)
	}
}
