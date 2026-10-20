package main

import (
	"errors"
	"fmt"
	"os"
)

// errElevationCancelled is returned when the operator dismisses the Windows
// UAC consent dialog. It is mapped to the stable unauthorized exit code by
// runTrust; no system setting is changed in that case.
var errElevationCancelled = errors.New("Windows UAC authorization was cancelled")

// elevateTrust starts this same executable with the narrow internal child
// marker. The platform launcher owns the UAC interaction and waits for the
// child exit code; the target has already passed validTrustedHost before this
// function is called.
func elevateTrust(target string) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return -1, fmt.Errorf("locate bridge-cli executable: %w", err)
	}
	return launchElevated(executable, []string{"trust", "--target", target, "--uac-child"})
}
