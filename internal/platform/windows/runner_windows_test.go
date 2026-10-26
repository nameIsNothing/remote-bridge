//go:build windows

package windows

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The overlay run points os.DevNull at a missing path without changing the
// Windows NUL driver or the installed toolchain. The same production runner
// must still supply EOF, capture output and preserve the child exit code.
func TestSystemRunnerEmptyInputWithoutNullDevice(t *testing.T) {
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
			script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $content=[Console]::In.ReadToEnd(); if($content.Length -ne 0) { throw 'expected empty stdin' }; Write-Output 'stdin-eof'; exit %d`, exitCode)
			result, err := NewRunner().Run(ctx, PowerShellCommand(script, true))
			if result.ExitCode != exitCode || strings.TrimSpace(result.Stdout) != "stdin-eof" || (err != nil) != (exitCode != 0) {
				t.Fatalf("child input/output/exit contract failed: result=%+v error=%v", result, err)
			}
		})
	}
}
