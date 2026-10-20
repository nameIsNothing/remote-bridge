//go:build !windows

package main

import "errors"

func launchElevated(_ string, _ []string) (int, error) {
	return -1, errors.New("UAC elevation is supported only on Windows")
}
