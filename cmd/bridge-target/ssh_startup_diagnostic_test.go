package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilterSSHStartupErrorLinesKeepsConcreteErrorsAndRedactsSecrets(t *testing.T) {
	input := strings.Join([]string{
		"debug1: server startup details",
		"sshd: error: Unable to load host key: C:/ProgramData/RemoteBridge/ssh/key password=fixture-secret",
		"fatal: Cannot bind any address.",
		"sshd: error: Bad configuration option: fixture_option",
	}, "\n")

	got := filterSSHStartupErrorLines([]byte(input))
	for _, expected := range []string{"Unable to load host key", "Cannot bind any address", "Bad configuration option"} {
		if !strings.Contains(got, expected) {
			t.Errorf("filtered startup error is missing %q: %q", expected, got)
		}
	}
	if strings.Contains(got, "fixture-secret") {
		t.Fatalf("diagnostic secret was not redacted: %q", got)
	}
	if strings.Contains(got, "debug1") {
		t.Fatalf("debug line was copied: %q", got)
	}
}

func TestFilterSSHStartupErrorLinesKeepsLogfileAndMissingSessionBinaryErrors(t *testing.T) {
	input := strings.Join([]string{
		"sshd: Couldn't open logfile C:/ProgramData/RemoteBridge/ssh/sshd.log: Permission denied",
		"sshd: could not open logfile C:/ProgramData/RemoteBridge/ssh/sshd.log: No such file or directory",
		"sshd: sshd-session.exe does not exist or is not executable",
		"sshd: session opened for user RemoteBridge",
	}, "\n")

	got := filterSSHStartupErrorLines([]byte(input))
	if !strings.Contains(got, "Couldn't open logfile") || !strings.Contains(got, "Permission denied") {
		t.Fatalf("logfile open error was lost: %q", got)
	}
	if !strings.Contains(got, "No such file or directory") {
		t.Fatalf("logfile ENOENT error was lost: %q", got)
	}
	if !strings.Contains(got, "sshd-session.exe does not exist or is not executable") {
		t.Fatalf("missing SSH session binary error was filtered: %q", got)
	}
	if strings.Contains(got, "session opened for user") {
		t.Fatalf("ordinary session event was copied: %q", got)
	}
}

func TestFilterSSHStartupErrorLinesExcludesSessionAndOrdinaryLog(t *testing.T) {
	input := strings.Join([]string{
		"Accepted publickey for RemoteBridge from 192.0.2.20 port 41000 ssh2",
		"Failed publickey for RemoteBridge from 192.0.2.20 port 41001 ssh2",
		"Authentication refused: bad ownership or modes for file",
		"Starting session: command for RemoteBridge",
		"Disconnected from user RemoteBridge 192.0.2.20 port 41000",
		"Server listening on 0.0.0.0 port 2222.",
		"Connection from 192.0.2.20 port 41000",
		"debug1: sshd startup error details",
	}, "\n")

	if got := filterSSHStartupErrorLines([]byte(input)); got != "" {
		t.Fatalf("non-startup/session lines should not be copied: %q", got)
	}
}

func TestFilterSSHStartupErrorLinesBoundsCountAndTotalBytes(t *testing.T) {
	var shortLines []string
	for i := 0; i < sshStartupLineCount+4; i++ {
		shortLines = append(shortLines, "fatal: startup error")
	}
	got := filterSSHStartupErrorLines([]byte(strings.Join(shortLines, "\n")))
	if count := strings.Count(got, "fatal:"); count != sshStartupLineCount {
		t.Fatalf("expected at most %d selected lines, got %d", sshStartupLineCount, count)
	}

	longLine := "fatal: " + strings.Repeat("x", 1800)
	var longLines []string
	for i := 0; i < sshStartupLineCount; i++ {
		longLines = append(longLines, longLine)
	}
	got = filterSSHStartupErrorLines([]byte(strings.Join(longLines, "\n")))
	if len(got) > sshStartupErrorLimit {
		t.Fatalf("filtered output exceeded %d bytes: %d", sshStartupErrorLimit, len(got))
	}
}

func TestReadSSHStartupLogStopsAtHeadLimit(t *testing.T) {
	input := append(bytes.Repeat([]byte("ordinary startup text\n"), 4000), []byte("fatal: error beyond head limit\n")...)
	got, err := readSSHStartupLog(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != sshStartupLogReadLimit {
		t.Fatalf("read %d bytes, want capped head of %d", len(got), sshStartupLogReadLimit)
	}
	if strings.Contains(string(got), "beyond head limit") {
		t.Fatal("read continued beyond the bounded log head")
	}
}

func TestReadSSHStartupDiagnosticLogsReadsOnlyTwoBoundedInstanceFiles(t *testing.T) {
	root := t.TempDir()
	content := bytes.Repeat([]byte("startup error\n"), 12000)
	for _, name := range []string{"sshd-startup.log", "sshd.log"} {
		if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "other.log"), []byte("fatal: should not be read"), 0600); err != nil {
		t.Fatal(err)
	}

	logs, err := readSSHStartupDiagnosticLogs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("read %d logs, want exactly the two owned startup logs", len(logs))
	}
	total := 0
	for _, log := range logs {
		if len(log) > sshStartupLogReadLimit {
			t.Fatalf("one log exceeded %d bytes: %d", sshStartupLogReadLimit, len(log))
		}
		total += len(log)
	}
	if total > sshStartupTotalReadLimit {
		t.Fatalf("combined logs exceeded %d bytes: %d", sshStartupTotalReadLimit, total)
	}
}

func TestFilterSSHStartupErrorLinesKeepsSecondFileErrorsAfterFirstFileLimit(t *testing.T) {
	first := bytes.Repeat([]byte("ordinary startup information\n"), 5000)
	first = first[:sshStartupLogReadLimit]
	second := []byte("sshd: fatal: startup failure from stderr\n")
	if len(first) != sshStartupLogReadLimit {
		t.Fatalf("test fixture first log is %d bytes, want %d", len(first), sshStartupLogReadLimit)
	}
	got := filterSSHStartupErrorLines(bytes.Join([][]byte{first, second}, []byte{'\n'}))
	if !strings.Contains(got, "startup failure from stderr") {
		t.Fatalf("second-file error was lost after a full first file: %q", got)
	}
}

func TestFilterSSHStartupErrorLinesIgnoresMalformedAndOverlongLines(t *testing.T) {
	input := append([]byte("fatal: "), 0xff)
	input = append(input, []byte("\n")...)
	input = append(input, []byte("fatal: "+strings.Repeat("x", sshStartupLineLimit))...)
	input = append(input, []byte("\nfatal: usable startup error\n")...)

	got := filterSSHStartupErrorLines(input)
	if strings.Contains(got, "\ufffd") || strings.Contains(got, strings.Repeat("x", 100)) {
		t.Fatalf("malformed or overlong line was copied: %q", got)
	}
	if !strings.Contains(got, "usable startup error") {
		t.Fatalf("valid later error line was lost: %q", got)
	}
}
