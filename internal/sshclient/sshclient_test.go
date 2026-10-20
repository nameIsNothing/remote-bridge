package sshclient

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateKeyPairUsesEphemeralEd25519Key(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed on the test machine")
	}
	pair, err := GenerateKeyPair(context.Background(), t.TempDir(), "manager")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pair.PrivatePath)
	defer os.Remove(pair.PrivatePath + ".pub")
	if err := ValidatePublicKey(pair.PublicKey); err != nil {
		t.Fatalf("generated public key is invalid: %v", err)
	}
	if _, err := os.Stat(pair.PrivatePath); err != nil {
		t.Fatalf("generated private key missing: %v", err)
	}
}

func TestValidatePublicKey(t *testing.T) {
	good := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm remote-bridge"
	if err := ValidatePublicKey(good); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for _, value := range []string{"", "ssh-ed25519", "ssh-ed25519 !!!", "ssh-ed25519 AAAA\ncommand=bad"} {
		if err := ValidatePublicKey(value); err == nil {
			t.Fatalf("invalid key accepted: %q", value)
		}
	}
}

func TestFormatAndWriteKnownHost(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm comment"
	line, err := FormatKnownHost("192.168.100.27", 22022, key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "[192.168.100.27]:22022 ssh-ed25519 ") || strings.Contains(line, "comment") {
		t.Fatalf("known host line = %q", line)
	}
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := WriteKnownHosts(path, line); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != line+"\n" {
		t.Fatalf("known_hosts = %q, err=%v", data, err)
	}
}

func TestWriteKnownHostsRejectsNewline(t *testing.T) {
	if err := WriteKnownHosts(filepath.Join(t.TempDir(), "known"), "bad\nkey"); err == nil {
		t.Fatal("newline key accepted")
	}
}
