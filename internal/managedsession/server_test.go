package managedsession

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func testInfo() Info {
	return Info{ID: "rb-0123456789abcdef01234567", InstanceID: "ssh-0123456789ab", Target: "192.0.2.10", Hostname: "TEST", Username: `TEST\张三`, Port: 5985, ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Second)}
}

func TestManagedSessionAcceptsThreeHoursAndRejectsLongerDeadline(t *testing.T) {
	if MaxLifetime != 3*time.Hour {
		t.Fatal("managed session lifetime must be three hours")
	}
	info := testInfo()
	info.ExpiresAt = time.Now().Add(3 * time.Hour)
	s, err := NewServer(info, nil)
	if err != nil {
		t.Fatal("three-hour target deadline rejected:", err)
	}
	defer s.Shutdown()
	if !s.Info().ExpiresAt.Equal(info.ExpiresAt) {
		t.Fatal("manager changed the target-issued deadline")
	}
	info.ExpiresAt = time.Now().Add(3*time.Hour + time.Second)
	if other, err := NewServer(info, nil); err == nil {
		other.Shutdown()
		t.Fatal("overlong target deadline accepted")
	}
}
func testServer(t *testing.T, audit AuditFunc) *Server {
	t.Helper()
	s, err := NewServer(testInfo(), audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	info := s.Info()
	info.SID = "S-1-5-21-1000-2000-3000-1001"
	workerPost(t, s, WorkerMessage{Operation: "ready", Info: &info}, 200)
	return s
}
func workerPost(t *testing.T, s *Server, message WorkerMessage, wantStatus int) Work {
	t.Helper()
	data, _ := json.Marshal(message)
	req, _ := http.NewRequest("POST", s.Endpoint()+"/v1/worker", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+s.WorkerToken())
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != wantStatus {
		t.Fatalf("worker status=%d, want %d", res.StatusCode, wantStatus)
	}
	var work Work
	if wantStatus == 200 {
		if err := json.NewDecoder(res.Body).Decode(&work); err != nil {
			t.Fatal(err)
		}
	}
	return work
}
func TestServerReusesSessionSerializesCommandsAndCloses(t *testing.T) {
	var mu sync.Mutex
	var events []string
	s := testServer(t, func(kind, command string, code int, ok bool) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, kind)
		return nil
	})
	for _, text := range []string{"Get-Date", "Write-Output '中文'"} {
		type callResult struct {
			response Response
			err      error
		}
		reply := make(chan callResult, 1)
		go func() {
			r, e := Call(context.Background(), s.Record(), Request{Operation: "exec", Command: text})
			reply <- callResult{r, e}
		}()
		work := workerPost(t, s, WorkerMessage{Operation: "next"}, 200)
		if work.Operation != "exec" || work.Command != text {
			t.Fatalf("bad dispatch: %+v", work)
		}
		if _, err := Call(context.Background(), s.Record(), Request{Operation: "exec", Command: "second"}); err == nil || err.Error() != ErrBusy.Error() {
			t.Fatalf("concurrent command accepted: %v", err)
		}
		workerPost(t, s, WorkerMessage{Operation: "result", ID: work.ID, Result: &Result{Stdout: "中文", ExitCode: 21}}, 200)
		got := <-reply
		if got.err != nil || got.response.Result == nil || got.response.Result.ExitCode != 21 || got.response.Info.ID != s.Info().ID {
			t.Fatalf("bad result: %+v", got)
		}
	}
	mu.Lock()
	count := len(events)
	mu.Unlock()
	if count != 4 {
		t.Fatalf("missing command start/finish audit: %v", events)
	}
	s.BeginClose("target ended")
	if _, err := Call(context.Background(), s.Record(), Request{Operation: "exec", Command: "Get-Date"}); err == nil {
		t.Fatal("command accepted after close")
	}
	if work := workerPost(t, s, WorkerMessage{Operation: "next"}, 200); work.Operation != "close" {
		t.Fatal("worker not told to stop")
	}
	workerPost(t, s, WorkerMessage{Operation: "closed"}, 200)
	select {
	case <-s.Done():
	case <-time.After(time.Second):
		t.Fatal("host did not end")
	}
}
func TestServerAuthenticationPinningAndBinding(t *testing.T) {
	s := testServer(t, nil)
	wrong := s.Record()
	wrong.Token = strings.Repeat("0", 64)
	if _, err := Call(context.Background(), wrong, Request{Operation: "status"}); err == nil {
		t.Fatal("wrong token accepted")
	}
	wrong = s.Record()
	wrong.Fingerprint = strings.Repeat("0", 64)
	if _, err := Call(context.Background(), wrong, Request{Operation: "status"}); err == nil {
		t.Fatal("wrong certificate accepted")
	}
	wrong = s.Record()
	wrong.Endpoint = "https://example.com"
	if _, err := Call(context.Background(), wrong, Request{Operation: "status"}); err == nil {
		t.Fatal("external endpoint accepted")
	}
	wrong = s.Record()
	wrong.Token = s.WorkerToken()
	if _, err := Call(context.Background(), wrong, Request{Operation: "status"}); err == nil {
		t.Fatal("worker credential accepted as client")
	}
	second, err := NewServer(testInfo(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown()
	info := second.Info()
	info.Hostname = "OTHER"
	info.SID = "S-1-5-21-1"
	workerPost(t, second, WorkerMessage{Operation: "ready", Info: &info}, 409)
	if second.Info().State != "closing" {
		t.Fatal("mismatched authentication did not close session")
	}
}
func TestServerAuditFailureAndCancellationFailClosed(t *testing.T) {
	s := testServer(t, func(string, string, int, bool) error { return errors.New("disk unavailable") })
	if _, err := Call(context.Background(), s.Record(), Request{Operation: "exec", Command: "Get-Date"}); err == nil || !strings.Contains(err.Error(), "未执行") {
		t.Fatalf("audit failure ignored: %v", err)
	}
	select {
	case <-s.work:
		t.Fatal("unaudited command dispatched")
	default:
	}
	other := testServer(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	reply := make(chan error, 1)
	go func() {
		_, err := Call(ctx, other.Record(), Request{Operation: "exec", Command: "Get-Date"})
		reply <- err
	}()
	work := workerPost(t, other, WorkerMessage{Operation: "next"}, 200)
	if work.Operation != "exec" {
		t.Fatal("no command")
	}
	cancel()
	<-reply
	select {
	case <-other.Closing():
	case <-time.After(2 * time.Second):
		t.Fatal("canceled call left session usable")
	}
}
func TestServerExpiryStopsDispatch(t *testing.T) {
	info := testInfo()
	info.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	s, err := NewServer(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	select {
	case <-s.Closing():
	case <-time.After(time.Second):
		t.Fatal("expiry not enforced")
	}
}
func TestRegistryIsProtectedAndNeverExposesToken(t *testing.T) {
	s := testServer(t, nil)
	root := t.TempDir()
	directory, err := PrepareDirectory(root, s.Info().ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRecord(directory, s.Record()); err != nil {
		t.Fatal(err)
	}
	record, err := LoadRecord(root, s.Info().ID)
	if err != nil {
		t.Fatal(err)
	}
	if record.Token != s.Record().Token {
		t.Fatal("record lost private authorization")
	}
	items, err := List(context.Background(), root)
	if err != nil || len(items) != 1 {
		t.Fatalf("list=%+v err=%v", items, err)
	}
	visible, _ := json.Marshal(items)
	if strings.Contains(string(visible), record.Token) || strings.Contains(Handoff(items[0], "bridge-cli.exe"), record.Token) {
		t.Fatal("token leaked into public data")
	}
	record = Record{Info: s.Info()}
	record.Info.State = "closed"
	if err := WriteRecord(directory, record); err != nil {
		t.Fatal(err)
	}
	items, err = List(context.Background(), root)
	if err != nil || len(items) != 0 {
		t.Fatal("closed record listed as active")
	}
	loaded, err := LoadRecord(root, s.Info().ID)
	if err != nil || loaded.Token != "" {
		t.Fatal("closed record kept credentials")
	}
	if _, err := LoadRecord(root, "../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatal(err)
	}
}
