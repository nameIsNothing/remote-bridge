package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"remote-bridge/internal/diagnostic"
)

const (
	sshStartupLogReadLimit   = 64 << 10
	sshStartupTotalReadLimit = 128 << 10
	sshStartupLineLimit      = 2 << 10
	sshStartupLineCount      = 8
	sshStartupErrorLimit     = 8 << 10
)

// captureSSHStartupFailure copies only recognizable startup error lines from
// the private sshd log into the controller's structured diagnostics. It must
// be called only on a startup-failure path, before cleanup removes the root.
func captureSSHStartupFailure(r *sshTargetRuntime) {
	if r == nil || !validSSHPlanID(r.id) || !samePath(r.root, sshRuntimeDirectory(r.id)) {
		return
	}
	sshdLogPath := filepath.Join(r.root, sshRuntimeLogName)
	if !filepath.IsAbs(r.root) || !filepath.IsAbs(r.logPath) || !samePath(r.logPath, sshdLogPath) {
		return
	}
	if err := validateSSHOwnedPath(r.root); err != nil {
		return
	}
	logs, err := readSSHStartupDiagnosticLogs(r.root)
	if err != nil {
		return
	}
	filtered := filterSSHStartupErrorLines(bytes.Join(logs, []byte{'\n'}))
	if filtered == "" {
		return
	}
	targetDiagnostic(diagnostic.Event{
		Level:    "error",
		Event:    "ssh.startup.failed",
		Instance: r.id,
		Error:    filtered,
	})
}

func readSSHStartupLog(reader io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(reader, sshStartupLogReadLimit))
}

// readSSHStartupDiagnosticLogs reads only the two documented per-instance
// startup logs, including the older -E destination. Both each-file and
// aggregate input are bounded; either file may be absent.
func readSSHStartupDiagnosticLogs(root string) ([][]byte, error) {
	if !filepath.IsAbs(root) {
		return nil, os.ErrInvalid
	}
	var logs [][]byte
	var total int64
	for _, name := range []string{sshRuntimeLogName, "sshd.log"} {
		path := filepath.Join(root, name)
		if err := validateSSHOwnedPath(path); err != nil {
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			_ = file.Close()
			continue
		}
		remaining := int64(sshStartupTotalReadLimit) - total
		if remaining <= 0 {
			_ = file.Close()
			break
		}
		limit := int64(sshStartupLogReadLimit)
		if remaining < limit {
			limit = remaining
		}
		data, readErr := io.ReadAll(io.LimitReader(file, limit))
		_ = file.Close()
		if readErr != nil {
			continue
		}
		logs = append(logs, data)
		total += int64(len(data))
	}
	return logs, nil
}

// filterSSHStartupErrorLines deliberately rejects authentication/session and
// debug records before selecting a small set of startup-failure signatures.
// OpenSSH's log also contains live session metadata, so it must never be copied
// wholesale into the general diagnostic log.
func filterSSHStartupErrorLines(data []byte) string {
	if len(data) > sshStartupTotalReadLimit {
		data = data[:sshStartupTotalReadLimit]
	}
	var selected []string
	used := 0
	for _, raw := range bytes.Split(data, []byte{'\n'}) {
		if len(selected) >= sshStartupLineCount {
			break
		}
		if len(raw) > sshStartupLineLimit || !utf8.Valid(raw) {
			continue
		}
		line := strings.TrimSpace(strings.TrimSuffix(string(raw), "\r"))
		if line == "" || hasSSHStartupExcludedContent(line) || !isSSHStartupErrorLine(line) {
			continue
		}
		line = safeTargetDiagnosticText(line)
		line = strings.ReplaceAll(strings.ReplaceAll(line, "\r", " "), "\n", " ")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		remaining := sshStartupErrorLimit - used
		if remaining <= 0 {
			break
		}
		if len(line) > remaining {
			line = truncateSSHStartupUTF8(line, remaining)
		}
		if line == "" {
			break
		}
		selected = append(selected, line)
		used += len(line) + 1
	}
	return strings.Join(selected, "\n")
}

func hasSSHStartupExcludedContent(line string) bool {
	lower := strings.ToLower(line)
	missingSessionBinary := strings.Contains(lower, "sshd-session.exe does not exist or is not executable")
	for _, marker := range []string{
		"authentication", "accepted publickey", "failed publickey", "failed password",
		"userauth", "command", "disconnect", "debug",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Contains(lower, "session") && !missingSessionBinary
}

func isSSHStartupErrorLine(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{
		"fatal", "error", "host key", "hostkey", "no host keys", "bind",
		"permission", "config", "initializ", "init failed", "service failed",
		"failed to start", "could not start", "unable to start",
		"couldn't open logfile", "could not open logfile", "unable to open logfile",
		"does not exist or is not executable",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func truncateSSHStartupUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) && len(value) > 0 {
		value = value[:len(value)-1]
	}
	return value
}
