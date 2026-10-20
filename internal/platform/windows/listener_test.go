package windows

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type listenerTestRunner struct {
	result Result
	err    error
	seen   Command
}

func (r *listenerTestRunner) Run(_ context.Context, command Command) (Result, error) {
	r.seen = command
	return r.result, r.err
}

func TestDetectWinRMNormalizesListenerState(t *testing.T) {
	runner := &listenerTestRunner{result: Result{ExitCode: 0, Stdout: `{"service_present":true,"service_running":true,"listener_checked":true,"listener_present":true,"listener_ports":[5986,5985,5985],"listener_protocols":["HTTPS","HTTP","HTTP"]}`}}
	status, err := DetectWinRM(context.Background(), runner)
	if err != nil {
		t.Fatalf("DetectWinRM() error = %v", err)
	}
	if !status.Known || !status.ServiceRunning || !status.ListenerPresent || !status.HTTPListener || !status.HTTPSListener {
		t.Fatalf("unexpected status: %#v", status)
	}
	if len(status.ListenerPorts) != 2 || status.ListenerPorts[0] != 5985 || status.ListenerPorts[1] != 5986 {
		t.Fatalf("listener ports = %#v", status.ListenerPorts)
	}
	if !runner.seen.ReadOnly || !strings.Contains(strings.Join(runner.seen.Args, " "), "Get-WSManInstance") {
		t.Fatalf("detection command was not read-only: %#v", runner.seen)
	}
}

func TestDetectWinRMUnknownDoesNotMeanAbsent(t *testing.T) {
	runner := &listenerTestRunner{result: Result{ExitCode: 0, Stdout: `{"service_present":true,"service_running":true,"listener_checked":false,"listener_error":"Access is denied","listener_present":false}`}}
	status, err := DetectWinRM(context.Background(), runner)
	if err == nil || !strings.Contains(err.Error(), "Access is denied") {
		t.Fatalf("expected listener access error, got %v", err)
	}
	if status.Known || status.ListenerPresent || status.Error == "" {
		t.Fatalf("unknown state was treated as absent: %#v", status)
	}
}

func TestDetectWinRMPropagatesRunnerFailure(t *testing.T) {
	want := errors.New("runner failed")
	status, err := DetectWinRM(context.Background(), &listenerTestRunner{err: want})
	if !errors.Is(err, want) || status.Known || status.Error == "" {
		t.Fatalf("error = %v, status = %#v", err, status)
	}
}
