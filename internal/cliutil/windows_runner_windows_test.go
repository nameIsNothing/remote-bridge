//go:build windows

package cliutil

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/platform/windows"
)

func TestPasswordRunnerEmptyInputWithoutNullDevice(t *testing.T) {
	t.Setenv("REMOTE_BRIDGE_STDIN_TEST_SECRET", "parent-fixture")
	if os.Getenv("REMOTE_BRIDGE_TEST_UNAVAILABLE_NULL") == "1" {
		if file, err := os.Open(os.DevNull); err == nil {
			file.Close()
			t.Fatal("fault-injection run did not make the null device unavailable")
		}
	}
	for _, exitCode := range []int{0, 7} {
		t.Run(fmt.Sprintf("exit-%d", exitCode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// Only a synthetic value is supplied. Check its child environment
			// remains available while stdin terminates without the null device.
			runner := NewPasswordRunner("fixture-only", "REMOTE_BRIDGE_STDIN_TEST_SECRET")
			script := fmt.Sprintf(`$ErrorActionPreference='Stop'; if($env:REMOTE_BRIDGE_STDIN_TEST_SECRET -cne 'fixture-only') { throw 'fixture environment missing' }; $content=[Console]::In.ReadToEnd(); if($content.Length -ne 0) { throw 'expected empty stdin' }; Write-Output 'stdin-eof'; exit %d`, exitCode)
			command := windows.PowerShellCommand(script, true)
			result, err := runner.Run(ctx, command)
			if result.ExitCode != exitCode || strings.TrimSpace(result.Stdout) != "stdin-eof" || (err != nil) != (exitCode != 0) {
				t.Fatalf("child input/output/exit contract failed: result=%+v error=%v", result, err)
			}
			if strings.Contains(result.Stdout+result.Stderr, "fixture-only") || os.Getenv("REMOTE_BRIDGE_STDIN_TEST_SECRET") != "parent-fixture" {
				t.Fatal("fixture value escaped its child environment")
			}
		})
	}
}
