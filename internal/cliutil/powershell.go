// Package cliutil contains small helpers shared by the portable command-line
// programs.  It intentionally keeps secrets on stdin instead of putting them
// in process arguments or environment variables.
package cliutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// Result is the captured result of a PowerShell process.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// PowerShellAvailable reports whether the current host can run Windows
// PowerShell.  The target/manager commands remain buildable on other systems,
// but their Windows operations return a clear error at runtime.
func PowerShellAvailable() bool {
	return runtime.GOOS == "windows"
}

// RunPowerShell runs a UTF-16LE encoded PowerShell script.  Encoding the
// script avoids shell quoting bugs when a remote command contains quotes,
// dollar signs, pipes or redirection operators.
func RunPowerShell(script string, stdin []byte) (Result, error) {
	if runtime.GOOS != "windows" {
		return Result{}, errors.New("PowerShell operations are supported only on Windows")
	}
	encoded, err := EncodePowerShell(utf8OutputPrefix + script)
	if err != nil {
		return Result{}, err
	}
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, fmt.Errorf("PowerShell exited with code %d: %w", result.ExitCode, err)
	}
	return result, err
}

// RunPowerShellInteractive starts PowerShell with the caller's console
// attached.  It is used for commands that deliberately prompt for a
// credential with Read-Host -AsSecureString.  The password therefore never
// appears in argv, an environment variable, or a captured output buffer.
func RunPowerShellInteractive(script string) (int, error) {
	if runtime.GOOS != "windows" {
		return -1, errors.New("PowerShell operations are supported only on Windows")
	}
	encoded, err := EncodePowerShell(utf8OutputPrefix + script)
	if err != nil {
		return -1, err
	}
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-EncodedCommand", encoded)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), fmt.Errorf("PowerShell exited with code %d: %w", exitErr.ExitCode(), err)
		}
		return -1, err
	}
	return 0, nil
}

const utf8OutputPrefix = "$OutputEncoding = [Text.Encoding]::UTF8; [Console]::OutputEncoding = [Text.Encoding]::UTF8; "

// EncodePowerShell converts a Go string into the format expected by
// powershell.exe -EncodedCommand: base64 of UTF-16LE text.
func EncodePowerShell(script string) (string, error) {
	if strings.IndexByte(script, 0) >= 0 {
		return "", errors.New("PowerShell script contains a NUL byte")
	}
	runes := []rune(script)
	buf := make([]byte, 2*len(runes))
	for i, r := range runes {
		if r > 0xffff {
			return "", fmt.Errorf("PowerShell script contains unsupported code point U+%X", r)
		}
		binary.LittleEndian.PutUint16(buf[i*2:], uint16(r))
	}
	return encodeBase64(buf), nil
}

func encodeBase64(src []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(src); i += 3 {
		var n uint32
		remaining := len(src) - i
		n |= uint32(src[i]) << 16
		if remaining > 1 {
			n |= uint32(src[i+1]) << 8
		}
		if remaining > 2 {
			n |= uint32(src[i+2])
		}
		out.WriteByte(alphabet[(n>>18)&0x3f])
		out.WriteByte(alphabet[(n>>12)&0x3f])
		if remaining > 1 {
			out.WriteByte(alphabet[(n>>6)&0x3f])
		} else {
			out.WriteByte('=')
		}
		if remaining > 2 {
			out.WriteByte(alphabet[n&0x3f])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}
