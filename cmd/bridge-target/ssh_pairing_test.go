package main

import (
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/discovery"
)

func sshPairTestRuntime(t *testing.T) (*sshTargetRuntime, discovery.PairRequest) {
	t.Helper()
	t.Setenv("LOCALAPPDATA", t.TempDir())
	key := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(make([]byte, 48))
	r := &sshTargetRuntime{id: "ssh-test", username: "RemoteBridge", port: 2222, keyPath: filepath.Join(t.TempDir(), "authorized_keys"), hostKey: key, expiresAt: time.Now().Add(time.Minute), approved: make(map[string]string)}
	request := discovery.PairRequest{V: 1, Type: discovery.PairRequestType, InstanceID: r.id, PublicKey: key + " comment", ManagerHostname: "管理机", ConfirmUntil: time.Now().Add(time.Minute)}
	return r, request
}

func TestSSHPairReusesOnlySameKeyAndSource(t *testing.T) {
	r, request := sshPairTestRuntime(t)
	confirmations := 0
	r.confirm = func(context.Context, string) bool { confirmations++; return true }
	address := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	for i := 0; i < 2; i++ {
		if response := r.Pair(context.Background(), request, address); !response.Accepted {
			t.Fatal(response.Reason)
		}
	}
	request.PublicKey = strings.Replace(request.PublicKey, "comment", "another-comment", 1)
	if !r.Pair(context.Background(), request, address).Accepted || confirmations != 1 {
		t.Fatal("key comment/UDP source port required repeated approval")
	}
	address.IP = net.ParseIP("192.0.2.11")
	if !r.Pair(context.Background(), request, address).Accepted || confirmations != 2 {
		t.Fatal("new source bypassed approval")
	}
	data, err := os.ReadFile(r.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "from=") != 2 || !strings.Contains(string(data), `from="192.0.2.10"`) || !strings.Contains(string(data), `from="192.0.2.11"`) {
		t.Fatal("SSH authorization does not enforce source binding")
	}
}

func TestSSHPairLateConsentNeverInstallsKey(t *testing.T) {
	r, request := sshPairTestRuntime(t)
	request.ConfirmUntil = time.Now().Add(10 * time.Millisecond)
	r.confirm = func(ctx context.Context, _ string) bool { <-ctx.Done(); return true }
	response := r.Pair(context.Background(), request, &net.UDPAddr{IP: net.ParseIP("192.0.2.10")})
	if response.Accepted {
		t.Fatal("late consent authorized SSH")
	}
	if _, err := os.Stat(r.keyPath); !os.IsNotExist(err) {
		t.Fatal("expired consent installed a key")
	}
}

func TestSSHPairNewKeyAndRejection(t *testing.T) {
	r, request := sshPairTestRuntime(t)
	r.confirm = func(context.Context, string) bool { return false }
	if r.Pair(context.Background(), request, &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}).Accepted {
		t.Fatal("rejected request authorized")
	}
	request.ConfirmUntil = time.Now().Add(-time.Second)
	r.confirm = func(context.Context, string) bool { t.Fatal("expired request displayed a dialog"); return true }
	if r.Pair(context.Background(), request, &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}).Accepted {
		t.Fatal("expired request authorized")
	}
}

func TestSSHAuthenticationLogCannotForgeSuccess(t *testing.T) {
	for _, test := range []struct {
		line     string
		accepted bool
	}{
		{"Accepted publickey for remotebridge from 192.0.2.10 port 1234 ssh2: ED25519 SHA256:test", true},
		{"1234 2026-10-08 16:00:00.100 Accepted publickey for RemoteBridge from 192.0.2.10 port 1234 ssh2: ED25519 SHA256:test\r", true},
		{"sshd-session: Accepted publickey for remotebridge from ::1 port 1234 ssh2: ED25519 SHA256:test", true},
		{"Invalid user Accepted publickey for fake from 192.0.2.10 port 1234", false},
		{"Failed publickey for invalid user Accepted publickey for remotebridge from 192.0.2.10 port 1234 ssh2", false},
		{"Accepted publickey for administrator from 192.0.2.10 port 1234 ssh2", false},
		{"Accepted publickey for remotebridge from 999.999.1.1 port 1234 ssh2", false},
	} {
		_, accepted := acceptedSSHLogin(test.line, "RemoteBridge")
		if accepted != test.accepted {
			t.Errorf("auth parsing %q: %v", test.line, accepted)
		}
	}
}
