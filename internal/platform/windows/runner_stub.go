//go:build !windows

package windows

import "context"

// SystemRunner is present on non-Windows builds so callers can compile the
// same CLI, but it never attempts to execute PowerShell on another platform.
type SystemRunner struct{}

// NewRunner returns a stub runner outside Windows. Use BuildPlan and command
// builders for dry-run inspection, or run the resulting binary on Windows for
// actual system checks and changes.
func NewRunner() Runner { return SystemRunner{} }

func (SystemRunner) Run(context.Context, Command) (Result, error) {
	return Result{ExitCode: -1}, ErrUnsupported
}
