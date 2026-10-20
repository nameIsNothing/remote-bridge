//go:build windows

package windows

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SystemRunner executes the exact PowerShell command described by Command.
// It does not add credentials, persist output, or perform an operation on its
// own; callers must explicitly pass it to Inspect, Apply, Revoke, or Rollback.
type SystemRunner struct{}

// NewRunner returns the Windows PowerShell runner used by the CLI.
func NewRunner() Runner { return SystemRunner{} }

func (SystemRunner) Run(ctx context.Context, command Command) (Result, error) {
	started := time.Now()
	result := Result{ExitCode: -1}
	program := strings.ToLower(filepath.Base(command.Program))
	if program != "powershell.exe" && program != "powershell" {
		result.Duration = time.Since(started)
		return result, ErrInvalidOptions
	}
	if len(command.Args) == 0 {
		result.Duration = time.Since(started)
		return result, ErrInvalidOptions
	}
	process := exec.CommandContext(ctx, command.Program, command.Args...)
	// Captured helpers must not spawn console windows over the desktop UI.
	process.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stdout, stderr bytes.Buffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Duration = time.Since(started)
	if process.ProcessState != nil {
		result.ExitCode = process.ProcessState.ExitCode()
	}
	return result, err
}
