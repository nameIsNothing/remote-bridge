package main

import (
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"remote-bridge/internal/managedsession"
	"remote-bridge/internal/model"
	"remote-bridge/internal/sshclient"
)

func managedSSHFixtureInfo() managedsession.Info {
	return managedsession.Info{ID: "rb-0123456789abcdef01234567", InstanceID: "ssh-0123456789ab", Target: "192.0.2.10", Hostname: "fixture.local",
		Username: "fixture", UID: "501", Transport: "ssh", Shell: "posix", Port: 2222, ExpiresAt: time.Now().Add(time.Minute).UTC()}
}

func TestManagedSSHIdentityRejectsAmbiguousOrChangedAccounts(t *testing.T) {
	info := managedSSHFixtureInfo()
	valid := "__REMOTE_BRIDGE_IDENTITY_V1__\nfixture.local\nfixture\n501\n"
	if got, err := parseManagedSSHIdentity(valid, info); err != nil || got.UID != "501" {
		t.Fatalf("valid identity rejected: %+v %v", got, err)
	}
	first := info
	first.UID = ""
	if got, err := parseManagedSSHIdentity(valid, first); err != nil || got.UID != "501" {
		t.Fatalf("initial identity rejected: %+v %v", got, err)
	}
	for _, output := range []string{
		strings.Replace(valid, "fixture\n", "Fixture\n", 1),
		strings.Replace(valid, "fixture.local", "other.local", 1),
		strings.Replace(valid, "501", "0", 1),
		strings.Replace(valid, "501", "502", 1),
		strings.Replace(valid, "501", "0501", 1),
		"login banner\n" + valid, valid + "extra\n", "", strings.Replace(valid, "V1", "V2", 1),
	} {
		if _, err := parseManagedSSHIdentity(output, info); err == nil {
			t.Fatalf("invalid identity accepted: %q", output)
		}
	}
}

func TestManagedSSHIdentityFailurePreservesUsefulSSHError(t *testing.T) {
	_, err := probeManagedSSH(context.Background(), func(context.Context, string) (sshclient.Result, error) {
		return sshclient.Result{ExitCode: 255, Stderr: "mangqilai23@192.0.2.10: Permission denied (publickey).\n"}, errors.New("exit status 255")
	}, managedSSHFixtureInfo(), nil)
	if err == nil || !strings.Contains(err.Error(), "Permission denied (publickey)") || !strings.Contains(err.Error(), "255") {
		t.Fatalf("SSH diagnostic lost: %v", err)
	}
}

func TestManagedSSHProbesRequireAuditBeforeConnecting(t *testing.T) {
	called := false
	runner := func(context.Context, string) (sshclient.Result, error) {
		called = true
		return sshclient.Result{}, nil
	}
	_, err := probeManagedSSH(context.Background(), runner, managedSSHFixtureInfo(), func(string, string, int, bool) error { return errors.New("disk full") })
	if err == nil || called {
		t.Fatalf("unaudited SSH probe was executed: called=%v err=%v", called, err)
	}
}

func newManagedSSHFixtureServer(t *testing.T, audit managedsession.AuditFunc) *managedsession.Server {
	t.Helper()
	server, err := managedsession.NewServer(managedSSHFixtureInfo(), audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Shutdown)
	if err := server.Ready(server.Info()); err != nil {
		t.Fatal(err)
	}
	return server
}

func TestManagedSSHWorkerReusesCLIAndMCPIdentityAndExitCode(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("catalog fixture needs an isolated user cache; Darwin uses the login home")
	}
	cache := t.TempDir()
	t.Setenv("LOCALAPPDATA", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	var mu sync.Mutex
	var commands, events []string
	auditFunc := func(kind, command string, code int, success bool) error {
		mu.Lock()
		events = append(events, kind)
		mu.Unlock()
		return nil
	}
	server := newManagedSSHFixtureServer(t, auditFunc)
	root, err := managedsession.DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := managedsession.PrepareDirectory(root, server.Info().ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := managedsession.WriteRecord(directory, server.Record()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := func(ctx context.Context, command string) (sshclient.Result, error) {
		mu.Lock()
		commands = append(commands, command)
		mu.Unlock()
		if _, ok := ctx.Deadline(); !ok {
			t.Error("command has no timeout")
		}
		return sshclient.Result{Stdout: "中文结果\n", Stderr: "fixture error\n", ExitCode: 7, Truncated: true}, errors.New("exit status 7")
	}
	go serveManagedSSH(ctx, server, runner, server.Info(), auditFunc, time.Hour)
	if code := runSession([]string{"exec", "--id", server.Info().ID, "--command", "printf 'CLI中文'; exit 7", "--timeout", "11", "--json"}); code != int(model.ExitRemoteCommand) {
		t.Fatalf("CLI lost nonzero remote exit: %d", code)
	}
	initialized := true
	request := mcpRequest{JSONRPC: "2.0", Method: "tools/call", Params: json.RawMessage(`{"name":"bridge_execute","arguments":{"session_id":"` + server.Info().ID + `","command":"printf 'MCP中文'; exit 7","timeout_seconds":13}}`)}
	value, rpcErr := handleMCP(request, &initialized)
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	data, _ := json.Marshal(value)
	if !strings.Contains(string(data), `"isError":true`) || !strings.Contains(string(data), `\"exit_code\":7`) || !strings.Contains(string(data), "中文结果") {
		t.Fatalf("MCP lost SSH result: %s", data)
	}
	info := server.Info()
	if info.Transport != "ssh" || info.UID != "501" || info.State != "connected" {
		t.Fatalf("CLI/MCP changed session binding: %+v", info)
	}
	mu.Lock()
	if len(commands) != 2 || len(events) != 4 {
		t.Errorf("commands=%v audit=%v", commands, events)
	}
	mu.Unlock()
	server.BeginClose("fixture close")
	cancel()
	select {
	case <-server.Done():
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after close")
	}
	if _, err := managedsession.Call(context.Background(), server.Record(), managedsession.Request{Operation: "exec", Command: "id"}); err == nil {
		t.Fatal("command accepted after SSH worker closed")
	}
}

func TestManagedSSHWorkerTimeoutCancelsRunnerAndCloses(t *testing.T) {
	server := newManagedSSHFixtureServer(t, nil)
	stopped := make(chan struct{})
	runner := func(ctx context.Context, command string) (sshclient.Result, error) {
		<-ctx.Done()
		close(stopped)
		return sshclient.Result{ExitCode: -1}, ctx.Err()
	}
	go serveManagedSSH(context.Background(), server, runner, server.Info(), nil, time.Hour)
	_, err := managedsession.Call(context.Background(), server.Record(), managedsession.Request{Operation: "exec", Command: "sleep 30", Timeout: 1})
	if err == nil {
		t.Fatal("timed out command succeeded")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout did not cancel runner")
	}
	select {
	case <-server.Done():
	case <-time.After(time.Second):
		t.Fatal("timeout left SSH manager active")
	}
}

func TestManagedSSHWorkerDetectsTargetExit(t *testing.T) {
	server := newManagedSSHFixtureServer(t, nil)
	runner := func(context.Context, string) (sshclient.Result, error) {
		return sshclient.Result{ExitCode: 255}, errors.New("connection refused")
	}
	go serveManagedSSH(context.Background(), server, runner, server.Info(), nil, 10*time.Millisecond)
	select {
	case <-server.Done():
		if !strings.Contains(server.Info().Reason, "目标 SSH") {
			t.Fatalf("target exit reason missing: %+v", server.Info())
		}
	case <-time.After(time.Second):
		t.Fatal("target exit left SSH manager active")
	}
}
