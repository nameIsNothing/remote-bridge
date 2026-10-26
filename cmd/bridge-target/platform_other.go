//go:build !darwin && !linux

package main

func runPlatformTarget(_ []string) (int, bool) { return 0, false }
