package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHCleanupRefusesDirectoryOutsideItsInstance(t *testing.T) {
	root := t.TempDir()
	sentinel := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &sshTargetRuntime{id: "ssh-test", username: "RemoteBridge", root: root, statePath: defaultSSHStatePath()}
	err := r.Cleanup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "所有权") {
		t.Fatalf("unowned cleanup must be refused: %v", err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatalf("unowned file was changed: %q, %v", data, err)
	}
}
