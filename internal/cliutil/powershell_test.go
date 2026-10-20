package cliutil

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEncodePowerShellUsesUTF16LEBase64(t *testing.T) {
	encoded, err := EncodePowerShell("Get-Date")
	if err != nil {
		t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString([]byte{'G', 0, 'e', 0, 't', 0, '-', 0, 'D', 0, 'a', 0, 't', 0, 'e', 0})
	if encoded != want {
		t.Fatalf("encoded script = %q, want %q", encoded, want)
	}
}

func TestEncodePowerShellRejectsNULAndUnsupportedRune(t *testing.T) {
	if _, err := EncodePowerShell("a\x00b"); err == nil {
		t.Fatal("expected NUL to be rejected")
	}
	if _, err := EncodePowerShell("😀"); err == nil {
		t.Fatal("expected non-BMP rune to be rejected")
	}
}

func TestWithEnvironmentValueReplacesExistingValue(t *testing.T) {
	result := withEnvironmentValue([]string{"A=1", "REMOTE_BRIDGE_TEMP_PASSWORD=old", "B=2"}, "REMOTE_BRIDGE_TEMP_PASSWORD", "new")
	joined := strings.Join(result, "\x00")
	if strings.Contains(joined, "old") || !strings.Contains(joined, "REMOTE_BRIDGE_TEMP_PASSWORD=new") {
		t.Fatalf("environment replacement failed: %v", result)
	}
}
