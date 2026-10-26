//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const startupConsoleFixtureEnv = "REMOTE_BRIDGE_STARTUP_CONSOLE_FIXTURE"

// Every child exits here without running CLI discovery, authentication or any
// system configuration. New consoles remain hidden throughout native tests.
func init() {
	mode := os.Getenv(startupConsoleFixtureEnv)
	if mode == "" {
		return
	}
	if mode == "shared" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child := startupConsoleFixture(ctx, "pause", 0)
		input, err := child.StdinPipe()
		if err != nil {
			os.Exit(12)
		}
		defer input.Close()
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		// This process keeps the console alive while its child checks that
		// association. The input pipe stays open and receives no newline.
		if err := child.Run(); err != nil {
			os.Exit(13)
		}
		os.Exit(0)
	}
	if mode != "pause" {
		os.Exit(11)
	}
	fmt.Fprintln(os.Stdout, "startup-fixture-before")
	pauseManagerOnStartupError()
	fmt.Fprintln(os.Stdout, "startup-fixture-after")
	os.Exit(0)
}

func startupConsoleFixture(ctx context.Context, mode string, flags uint32) *exec.Cmd {
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	for _, value := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(value), startupConsoleFixtureEnv+"=") {
			command.Env = append(command.Env, value)
		}
	}
	command.Env = append(command.Env, startupConsoleFixtureEnv+"="+mode)
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
	return command
}

func TestStartupErrorPausesOnlyPrivateConsole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := startupConsoleFixture(ctx, "pause", 0x00000010) // CREATE_NEW_CONSOLE
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = command.Wait(); close(exited) }()
	defer func() { _ = command.Process.Kill(); <-exited }()
	prompt := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stderr).ReadString('\n')
		prompt <- line
	}()
	select {
	case line := <-prompt:
		if !strings.Contains(line, "按回车关闭窗口") {
			t.Fatalf("startup error prompt missing: %q", line)
		}
	case <-ctx.Done():
		t.Fatal("private console did not show its error prompt")
	}
	select {
	case <-exited:
		t.Fatalf("private console closed before a newline: %v", waitErr)
	case <-time.After(150 * time.Millisecond):
	}
	if _, err := io.WriteString(input, "\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
		if waitErr != nil || !strings.Contains(stdout.String(), "startup-fixture-after") {
			t.Fatalf("newline did not release private console: %v, %q", waitErr, stdout.String())
		}
	case <-ctx.Done():
		t.Fatal("private console remained paused after a newline")
	}
}

func TestStartupErrorDoesNotPauseSharedOrMissingConsole(t *testing.T) {
	for _, scenario := range []struct {
		name  string
		mode  string
		flags uint32
	}{
		{"shared", "shared", 0x00000010},    // hidden owner creates the shared console
		{"no-console", "pause", 0x08000000}, // CREATE_NO_WINDOW
		{"detached", "pause", 0x00000008},   // DETACHED_PROCESS
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := startupConsoleFixture(ctx, scenario.mode, scenario.flags)
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("fixture waited for input or failed: %v, stdout=%q stderr=%q", err, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 || !strings.Contains(stdout.String(), "startup-fixture-after") {
				t.Fatalf("shared/background console unexpectedly paused: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
