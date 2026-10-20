package diagnostic

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func testLogger(t *testing.T, dir string, maxBytes int64) *Logger {
	t.Helper()
	l, err := New(Options{
		Directory: dir,
		Filename:  "bridge-target-20261009.jsonl",
		Version:   "0.2.1-test",
		Mode:      "ssh",
		MaxBytes:  maxBytes,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return l
}

func readRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q: %v", path, err)
	}
	defer f.Close()

	var records []map[string]any
	s := bufio.NewScanner(f)
	for s.Scan() {
		var record map[string]any
		if err := json.Unmarshal(s.Bytes(), &record); err != nil {
			t.Fatalf("invalid JSON record in %q: %v; line=%q", path, err, s.Text())
		}
		records = append(records, record)
	}
	if err := s.Err(); err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return records
}

func TestLogJSONUnicodeAndMetadata(t *testing.T) {
	l := testLogger(t, t.TempDir(), 0)
	err := l.Log(Event{
		Level:      "INFO",
		Event:      "ssh_pairing_approved",
		Step:       "\u8fde\u63a5\u786e\u8ba4",
		Phase:      "target",
		Instance:   "\u76ee\u6807-\u4e00",
		Message:    "\u5df2\u5141\u8bb8\u8fde\u63a5 \U0001f9ed",
		DurationMS: 17,
		ExitCode:   intPointer(0),
	})
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}
	records := readRecords(t, l.Path())
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	r := records[0]
	for key, want := range map[string]string{
		"version":  "0.2.1-test",
		"mode":     "ssh",
		"level":    "INFO",
		"event":    "ssh_pairing_approved",
		"step":     "\u8fde\u63a5\u786e\u8ba4",
		"phase":    "target",
		"instance": "\u76ee\u6807-\u4e00",
		"message":  "\u5df2\u5141\u8bb8\u8fde\u63a5 \U0001f9ed",
	} {
		if got, ok := r[key].(string); !ok || got != want {
			t.Errorf("field %q = %#v, want %q", key, r[key], want)
		}
	}
	if got, ok := r["time"].(string); !ok || got == "" {
		t.Fatalf("time metadata missing or not a string: %#v", r["time"])
	} else if _, err := time.Parse(time.RFC3339Nano, got); err != nil {
		t.Errorf("time %q is not RFC3339: %v", got, err)
	}
	if got, ok := r["pid"].(float64); !ok || int(got) != os.Getpid() {
		t.Errorf("pid metadata = %#v, want %d", r["pid"], os.Getpid())
	}
	if got, ok := r["duration_ms"].(float64); !ok || got != 17 {
		t.Errorf("duration_ms = %#v, want 17", r["duration_ms"])
	}
	if got, ok := r["exit_code"].(float64); !ok || got != 0 {
		t.Errorf("exit_code = %#v, want 0", r["exit_code"])
	}
}

func TestLogAppendsWithoutTruncatingExistingRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bridge-target-20261009.jsonl")
	previous := `{"time":"2026-10-09T00:00:00Z","event":"previous"}` + "\n"
	if err := os.WriteFile(path, []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	l := testLogger(t, dir, 0)
	if err := l.Log(Event{Event: "current"}); err != nil {
		t.Fatalf("Log() error = %v", err)
	}
	records := readRecords(t, path)
	if len(records) != 2 || records[0]["event"] != "previous" || records[1]["event"] != "current" {
		t.Fatalf("append did not preserve both records: %#v", records)
	}
}

func TestLogSanitizesRegisteredLiteralAndCommonSecrets(t *testing.T) {
	l := testLogger(t, t.TempDir(), 0)
	registered := "pairing-code-plain-literal-5192"
	l.AddSecret(registered)
	input := strings.Join([]string{
		"literal=" + registered,
		"password=hunter2",
		"api_token: tok_test_123456789",
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-material\n-----END OPENSSH PRIVATE KEY-----",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEexample user@host",
		"powershell.exe -EncodedCommand SQBFAFgA",
	}, " | ")
	if err := l.Log(Event{Event: "sanitization", Message: input, Error: input}); err != nil {
		t.Fatalf("Log() error = %v", err)
	}
	r := readRecords(t, l.Path())[0]
	for _, key := range []string{"message", "error"} {
		got, ok := r[key].(string)
		if !ok {
			t.Fatalf("%s missing/string expected: %#v", key, r[key])
		}
		for _, secret := range []string{
			registered, "hunter2", "tok_test_123456789", "eyJhbGciOiJIUzI1NiJ9.payload.signature",
			"private-material", "AAAAC3NzaC1lZDI1NTE5AAAAIEexample", "SQBFAFgA",
		} {
			if strings.Contains(got, secret) {
				t.Errorf("%s contains secret %q: %s", key, secret, got)
			}
		}
	}
	if strings.Contains(Sanitize("password=sample-secret"), "sample-secret") {
		t.Error("Sanitize did not redact a password key/value")
	}
}

func TestSanitizeDecodesPowerShellCLIXMLErrorStream(t *testing.T) {
	input := "#< CLIXML\n<Objs Version=\"1.1.0.1\"><S S=\"Progress\">progress should be ignored</S><S S=\"Error\">\u9519\u8bef_x000D__x000A_\u7b2c\u4e8c\u884c</S></Objs>"
	got := Sanitize(input)
	want := "\u9519\u8bef\r\n\u7b2c\u4e8c\u884c"
	if got != want {
		t.Fatalf("Sanitize(CLIXML) = %q, want %q", got, want)
	}
	if strings.Contains(got, "progress") || strings.Contains(got, "CLIXML") {
		t.Fatalf("non-error CLIXML content was retained: %q", got)
	}
}

func TestConcurrentLogProducesParseableRecords(t *testing.T) {
	l := testLogger(t, t.TempDir(), 0)
	const workers = 12
	const each = 30
	var wg sync.WaitGroup
	errCh := make(chan error, workers*each)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := l.Log(Event{Event: "concurrent", Instance: fmt.Sprintf("%d-%d", worker, i)}); err != nil {
					errCh <- err
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent Log() error: %v", err)
	}
	records := readRecords(t, l.Path())
	if got, want := len(records), workers*each; got != want {
		t.Fatalf("got %d parseable records, want %d", got, want)
	}
}

func TestRotationKeepsOnePreviousFileAndRecords(t *testing.T) {
	dir := t.TempDir()
	l := testLogger(t, dir, 320)
	for i := 0; i < 2; i++ {
		if err := l.Log(Event{Event: "rotation", Message: fmt.Sprintf("record-%d-%s", i, strings.Repeat("x", 90))}); err != nil {
			t.Fatalf("Log(%d) error = %v", i, err)
		}
	}
	backup := readRecords(t, l.Path()+".1")
	if len(backup) == 0 || !strings.HasPrefix(backup[0]["message"].(string), "record-0-") {
		t.Fatalf("first record was not preserved in first backup: %#v", backup)
	}
	for i := 2; i < 8; i++ {
		if err := l.Log(Event{Event: "rotation", Message: fmt.Sprintf("record-%d-%s", i, strings.Repeat("x", 90))}); err != nil {
			t.Fatalf("Log(%d) error = %v", i, err)
		}
	}
	current := readRecords(t, l.Path())
	backup = readRecords(t, l.Path()+".1")
	if len(current) == 0 || len(backup) == 0 {
		t.Fatalf("expected records in current and backup files; current=%d backup=%d", len(current), len(backup))
	}
	if _, err := os.Stat(l.Path() + ".2"); !os.IsNotExist(err) {
		t.Errorf("unexpected second backup (stat error %v)", err)
	}
}

func TestNewRejectsUnsafeFilenameAndDirectoryAsLog(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(Options{Directory: dir, Filename: "../escape.jsonl"}); err == nil {
		t.Error("New accepted a filename containing a parent path")
	}
	logDir := filepath.Join(dir, "bridge-target-20261009.jsonl")
	if err := os.Mkdir(logDir, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Directory: dir, Filename: filepath.Base(logDir)}); err == nil {
		t.Error("New accepted a directory at the log path")
	}
}

func TestNewRejectsSymlinkAtLogPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-log.jsonl")
	if err := os.WriteFile(target, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "bridge-target-20261009.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := New(Options{Directory: dir, Filename: filepath.Base(link)}); err == nil {
		t.Fatal("New accepted a symbolic link at the log path")
	}
}

func TestSanitizeBoundsUTF8AndPreservesValidity(t *testing.T) {
	input := strings.Repeat("\u754c\U0001f9ea", 5000)
	got := Sanitize(input)
	if !utf8.ValidString(got) {
		t.Fatal("Sanitize returned invalid UTF-8")
	}
	if n := len(got); n > 8192 {
		t.Errorf("Sanitize returned %d bytes, want at most 8192", n)
	}
}

func intPointer(n int) *int { return &n }
