//go:build !windows

package sshclient

import (
	"fmt"
	"os"
)

func protectPrivateKey(path string) error { return os.Chmod(path, 0o600) }

// ProtectDirectory restricts a manager session directory and all newly
// created private-key files to the current user on Unix platforms.
func ProtectDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SSH directory is not a regular directory")
	}
	return os.Chmod(path, 0o700)
}
