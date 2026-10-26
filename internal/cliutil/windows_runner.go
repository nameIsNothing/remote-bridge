package cliutil

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"remote-bridge/internal/platform/windows"
)

// PasswordRunner is the narrow adapter used by bridge-target apply.  It
// passes the generated account password to the child PowerShell process only
// for the duration of one command.  The plan and command arguments never
// contain the password.
type PasswordRunner struct {
	Password string
	EnvName  string
}

// NewPasswordRunner returns a Windows runner that injects password into the
// named environment variable for each child process.  The returned value is
// safe to use only for the short apply operation; callers should discard it
// immediately afterwards.
func NewPasswordRunner(password, envName string) windows.Runner {
	return PasswordRunner{Password: password, EnvName: envName}
}

func (r PasswordRunner) Run(ctx context.Context, command windows.Command) (windows.Result, error) {
	if runtime.GOOS != "windows" {
		return windows.Result{ExitCode: -1}, windows.ErrUnsupported
	}
	if strings.TrimSpace(command.Program) == "" || len(command.Args) == 0 {
		return windows.Result{ExitCode: -1}, windows.ErrInvalidOptions
	}
	started := time.Now()
	process := exec.CommandContext(ctx, command.Program, command.Args...)
	// This captured, non-interactive helper needs EOF, not a NUL device.
	process.Stdin = strings.NewReader("")
	configurePasswordHelper(process)
	process.Env = withEnvironmentValue(os.Environ(), r.EnvName, r.Password)
	var stdout, stderr bytes.Buffer
	process.Stdout = &stdout
	process.Stderr = &stderr
	err := process.Run()
	result := windows.Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Duration: time.Since(started)}
	if process.ProcessState != nil {
		result.ExitCode = process.ProcessState.ExitCode()
	}
	return result, err
}

func withEnvironmentValue(environment []string, name, value string) []string {
	if strings.TrimSpace(name) == "" {
		return environment
	}
	prefix := name + "="
	filtered := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if strings.HasPrefix(item, prefix) {
			continue
		}
		filtered = append(filtered, item)
	}
	return append(filtered, prefix+value)
}

var _ windows.Runner = PasswordRunner{}
