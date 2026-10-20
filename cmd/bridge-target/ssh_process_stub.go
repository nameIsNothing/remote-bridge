//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

func hideTargetHelper(cmd *exec.Cmd)         {}
func validateSSHOwnedPath(path string) error { return nil }
func sshProgramDataDirectory() string        { return os.TempDir() }
func acquireTargetLock() (func(), error)     { return func() {}, nil }
func installedSSHCandidates() []string       { return nil }
func trustedInstalledSSHD(path string) bool  { return false }
func nativeTargetIsAdministrator() bool      { return false }
func sshProcessAlive(pid int) bool           { return false }
func assignSSHJob(pid int) (uintptr, error)  { return 0, errors.New("Windows only") }
func closeSSHJob(job uintptr)                {}
