//go:build !windows

package main

func managedWindowsAvailable() bool   { return false }
func managedShowError(message string) {}
