package sshclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestShellCommandPreservesPOSIXScriptAndWindowsCompatibility(t *testing.T) {
	script := "printf '%s\\n' '中文 $HOME `literal`'\nvalue=\"a'b\"\nprintf '%s' \"$value\"\nexit 7"
	remote, input, err := shellCommand("posix", script, false)
	if err != nil || !reflect.DeepEqual(remote, []string{"sh", "-s"}) {
		t.Fatalf("posix remote=%q err=%v", remote, err)
	}
	data, err := io.ReadAll(input)
	if err != nil || string(data) != script+"\n" {
		t.Fatalf("posix script changed: %q, err=%v", data, err)
	}
	remote, input, err = shellCommand("posix", "", true)
	if err != nil || len(remote) != 0 || input != nil {
		t.Fatalf("posix interactive must use the login shell: %q, %v", remote, err)
	}
	remote, input, err = shellCommand("", "Write-Output '中文'", false)
	if err != nil || len(remote) != 6 || remote[0] != "powershell.exe" || remote[4] != "-EncodedCommand" || input == nil {
		t.Fatalf("Windows command changed: %q, err=%v", remote, err)
	}
	data, _ = io.ReadAll(input)
	if len(data) != 0 {
		t.Fatal("Windows command must receive EOF on stdin")
	}
	if _, _, err := shellCommand("bash -c evil", "echo ignored", false); err == nil {
		t.Fatal("unknown shell accepted")
	}
}

// This child only reads its inherited pipe and emits synthetic output; it
// never starts SSH or contacts a network endpoint.
func TestSSHProcessHelper(t *testing.T) {
	mode := os.Getenv("REMOTE_BRIDGE_SSH_PROCESS_FIXTURE")
	if mode == "" {
		return
	}
	switch mode {
	case "input":
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(9)
		}
		_ = json.NewEncoder(os.Stdout).Encode(string(data))
		fmt.Fprint(os.Stderr, "错误流 中文")
		os.Exit(7)
	case "large":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("o", MaxOutput+8192))
		_, _ = io.WriteString(os.Stderr, strings.Repeat("e", MaxOutput+8192))
		os.Exit(0)
	case "sleep":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	default:
		os.Exit(8)
	}
}

func sshProcessFixture(ctx context.Context, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSSHProcessHelper$")
	cmd.Env = append(os.Environ(), "REMOTE_BRIDGE_SSH_PROCESS_FIXTURE="+mode)
	return cmd
}

func TestCapturedSSHProcessPreservesInputExitAndEmptyEOF(t *testing.T) {
	for _, script := range []string{"", "printf '%s' '中文'\nexit 7\n"} {
		t.Run(fmt.Sprintf("bytes-%d", len(script)), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := sshProcessFixture(ctx, "input")
			if script != "" {
				cmd.Stdin = strings.NewReader(script)
			}
			result, err := runProcess(cmd, false)
			var received string
			if jsonErr := json.Unmarshal([]byte(result.Stdout), &received); jsonErr != nil || received != script {
				t.Fatalf("received=%q raw=%q jsonErr=%v", received, result.Stdout, jsonErr)
			}
			if err == nil || result.ExitCode != 7 || result.Stderr != "错误流 中文" || result.Truncated {
				t.Fatalf("result=%#v err=%v", result, err)
			}
		})
	}
}

func TestCapturedSSHProcessBoundsAndDrainsBothStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := runProcess(sshProcessFixture(ctx, "large"), false)
	if err != nil || result.ExitCode != 0 || !result.Truncated || len(result.Stdout) != MaxOutput || len(result.Stderr) != MaxOutput {
		t.Fatalf("stdout=%d stderr=%d truncated=%v code=%d err=%v", len(result.Stdout), len(result.Stderr), result.Truncated, result.ExitCode, err)
	}
}

func TestCapturedSSHProcessHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := runProcess(sshProcessFixture(ctx, "sleep"), false)
	if err == nil || ctx.Err() == nil || time.Since(started) > 3*time.Second {
		t.Fatalf("cancellation err=%v context=%v duration=%s", err, ctx.Err(), time.Since(started))
	}
}

func TestCapturedOutputRemainsValidUTF8WithinByteLimit(t *testing.T) {
	var output boundedOutput
	_, _ = output.Write([]byte(strings.Repeat("a", MaxOutput-1) + "中"))
	value := output.String()
	if !output.truncated || len(value) > MaxOutput || !utf8.ValidString(value) {
		t.Fatalf("bytes=%d valid=%v truncated=%v", len(value), utf8.ValidString(value), output.truncated)
	}
	output = boundedOutput{}
	_, _ = output.Write([]byte(strings.Repeat("\xffa", MaxOutput/2)))
	value = output.String()
	if !output.truncated || len(value) > MaxOutput || !utf8.ValidString(value) {
		t.Fatalf("invalid-byte conversion bytes=%d valid=%v truncated=%v", len(value), utf8.ValidString(value), output.truncated)
	}
}
