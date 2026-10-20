//go:build windows

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHJobClosesOwnedChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30; Write-Output 'survived'")
	var output strings.Builder
	cmd.Stdout = &output
	hideTargetHelper(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	job, err := assignSSHJob(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	closeSSHJob(job)
	started := time.Now()
	_ = cmd.Wait()
	if strings.Contains(output.String(), "survived") || time.Since(started) > 2*time.Second {
		t.Fatal("child survived a kill-on-close job")
	}
}

func TestSSHOwnedPathsRejectRelativePaths(t *testing.T) {
	if validateSSHOwnedPath("RemoteBridge/ssh/unsafe") == nil {
		t.Fatal("relative cleanup path accepted")
	}
	if err := validateSSHOwnedPath(filepath.Join(t.TempDir(), "not-created", "plan")); err != nil {
		t.Fatal(err)
	}
}

func TestSSHProgramDataDoesNotTrustEnvironment(t *testing.T) {
	original := sshProgramDataDirectory()
	t.Setenv("ProgramData", t.TempDir())
	if sshProgramDataDirectory() != original || original == "" {
		t.Fatal("system runtime directory was redirected by environment")
	}
}
