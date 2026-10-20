//go:build !windows

package main

import "errors"

type nativeSSHRecoveryOperations struct{}

func (nativeSSHRecoveryOperations) Candidates() ([]sshRecoveryCandidate, error) {
	return nil, errors.New("Windows only")
}
func (nativeSSHRecoveryOperations) Open(uint32, bool) (sshRecoveryProcess, error) {
	return nil, errors.New("Windows only")
}
