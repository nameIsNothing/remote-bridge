package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/discovery"
	"remote-bridge/internal/sshclient"
)

type sshSessionFixture struct {
	cache         *sshSessionCache
	now           time.Time
	announcement  discovery.Announcement
	endpoint      *net.UDPAddr
	generated     int
	pairRequests  []discovery.PairRequest
	approvedKeys  map[string]bool
	approvals     int
	hostKey       string
	responseUntil time.Time
}

func newSSHSessionFixture(t *testing.T) *sshSessionFixture {
	t.Helper()
	cache, err := newSSHSessionCache(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	f := &sshSessionFixture{
		cache: cache, now: now, endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.27"), Port: discovery.DefaultPort},
		hostKey: sshTestPublicKey(1), approvedKeys: make(map[string]bool), responseUntil: now.Add(30 * time.Minute),
		announcement: discovery.Announcement{V: discovery.Version, Type: discovery.AnnouncementType, InstanceID: "ssh-fixture", Hostname: "fixture-target", Addresses: []string{"192.0.2.27"}, Port: 2222, Transport: "ssh", Username: "RemoteBridge", ExpiresAt: now.Add(30 * time.Minute)},
	}
	cache.now = func() time.Time { return f.now }
	return f
}

// Synthetic public test material; no real user or target key is inspected.
func sshTestPublicKey(seed byte) string {
	data := make([]byte, 40)
	for i := range data {
		data[i] = seed
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(data)
}

func (f *sshSessionFixture) keygen(_ context.Context, directory, name string) (sshclient.KeyPair, error) {
	f.generated++
	key := sshTestPublicKey(byte(10 + f.generated))
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte("synthetic test fixture"), 0o600); err != nil {
		return sshclient.KeyPair{}, err
	}
	if err := os.WriteFile(path+".pub", []byte(key+" fixture\n"), 0o600); err != nil {
		return sshclient.KeyPair{}, err
	}
	return sshclient.KeyPair{PrivatePath: path, PublicKey: key + " fixture"}, nil
}

func (f *sshSessionFixture) pair(_ context.Context, request discovery.PairRequest) (discovery.PairResponse, error) {
	f.pairRequests = append(f.pairRequests, request)
	if !f.approvedKeys[request.PublicKey] {
		f.approvedKeys[request.PublicKey] = true
		f.approvals++
	}
	return discovery.PairResponse{V: discovery.Version, Type: discovery.PairResponseType, InstanceID: request.InstanceID, RequestNonce: request.RequestNonce, Accepted: true, Hostname: "fixture-target", Port: f.announcement.Port, Username: f.announcement.Username, Shell: f.announcement.Shell, ExpiresAt: f.responseUntil, HostKey: f.hostKey}, nil
}

func (f *sshSessionFixture) open(t *testing.T) *lockedSSHSession {
	t.Helper()
	session, err := f.cache.open(context.Background(), f.announcement.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.close)
	return session
}

func (f *sshSessionFixture) authorize(t *testing.T, session *lockedSSHSession) sshSessionRecord {
	t.Helper()
	record, _, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestSSHSessionReusesApprovalAfterSSHFailure(t *testing.T) {
	f := newSSHSessionFixture(t)
	first := f.open(t)
	original := f.authorize(t, first)
	// A canceled context prevents starting ssh.exe or contacting any endpoint.
	// The approved record must survive a real adapter failure before retry.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sshclient.Run(ctx, original.Address, original.Port, original.Username, first.privatePath(), first.knownHostsPath(), "hostname"); err == nil {
		t.Fatal("canceled SSH call unexpectedly succeeded")
	}
	first.close()
	f.now = f.now.Add(time.Minute)
	second := f.open(t)
	record, reused, err := second.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen)
	if err != nil || !reused {
		t.Fatalf("retry reused=%v, err=%v", reused, err)
	}
	if f.generated != 1 || f.approvals != 1 || len(f.pairRequests) != 2 {
		t.Fatalf("generated=%d approvals=%d pairs=%d", f.generated, f.approvals, len(f.pairRequests))
	}
	if record.PublicKey != original.PublicKey || record.ManagerID != original.ManagerID || record.HostKey != original.HostKey || !record.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("reused session changed its identity, host key or lifetime")
	}
	if f.pairRequests[0].RequestNonce == f.pairRequests[1].RequestNonce {
		t.Fatal("retry did not use a fresh request nonce")
	}
}

func TestSSHSessionRejectsChangedBindingWithoutPairing(t *testing.T) {
	tests := []struct {
		name   string
		change func(*discovery.Announcement, *net.UDPAddr, *string)
	}{
		{"instance", func(a *discovery.Announcement, _ *net.UDPAddr, _ *string) { a.InstanceID = "different-instance" }},
		{"IP", func(_ *discovery.Announcement, e *net.UDPAddr, _ *string) { e.IP = net.ParseIP("192.0.2.28") }},
		{"SSH port", func(a *discovery.Announcement, _ *net.UDPAddr, _ *string) { a.Port = 22 }},
		{"discovery port", func(_ *discovery.Announcement, e *net.UDPAddr, _ *string) { e.Port++ }},
		{"announced username", func(a *discovery.Announcement, _ *net.UDPAddr, _ *string) { a.Username = "Administrator" }},
		{"username override", func(_ *discovery.Announcement, _ *net.UDPAddr, user *string) { *user = "Administrator" }},
		{"shell", func(a *discovery.Announcement, _ *net.UDPAddr, _ *string) { a.Shell = "posix" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			session := f.open(t)
			f.authorize(t, session)
			selected := f.announcement
			endpoint := *f.endpoint
			username := ""
			test.change(&selected, &endpoint, &username)
			_, _, err := session.authorize(context.Background(), selected, &endpoint, username, f.pair, f.keygen)
			if err == nil || len(f.pairRequests) != 1 || f.generated != 1 {
				t.Fatalf("err=%v pairs=%d generated=%d", err, len(f.pairRequests), f.generated)
			}
		})
	}
}

func TestSSHSessionRejectsHostKeyReplacementAndKeepsOriginalPin(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	original := f.authorize(t, session)
	f.hostKey = sshTestPublicKey(2)
	_, reused, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen)
	if err == nil || !reused || !strings.Contains(err.Error(), "主机密钥") {
		t.Fatalf("reused=%v err=%v", reused, err)
	}
	stored, err := session.readRecord()
	if err != nil || stored.HostKey != original.HostKey {
		t.Fatal("failed response replaced the stored host key")
	}
	if err := session.validateBinding(stored, f.announcement, f.endpoint, ""); err != nil {
		t.Fatalf("failed response damaged the original known_hosts: %v", err)
	}
	f.hostKey = original.HostKey + " changed-comment"
	if _, reused, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen); err != nil || !reused {
		t.Fatalf("same canonical host key with a new comment: reused=%v err=%v", reused, err)
	}
}

func TestSSHSessionExpiryIsCappedAndNeverRenewed(t *testing.T) {
	tests := []struct {
		name         string
		announcement time.Duration
		response     time.Duration
		want         time.Duration
	}{
		{"30 minute cap", time.Hour, time.Hour, 30 * time.Minute},
		{"announcement cap", 10 * time.Minute, time.Hour, 10 * time.Minute},
		{"response cap", time.Hour, 5 * time.Minute, 5 * time.Minute},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			start := f.now
			f.announcement.ExpiresAt = start.Add(test.announcement)
			f.responseUntil = start.Add(test.response)
			session := f.open(t)
			first := f.authorize(t, session)
			if !first.ExpiresAt.Equal(start.Add(test.want)) {
				t.Fatalf("expiry=%s want=%s", first.ExpiresAt, start.Add(test.want))
			}
			f.now = start.Add(time.Minute)
			f.announcement.ExpiresAt = start.Add(2 * time.Hour)
			f.responseUntil = start.Add(2 * time.Hour)
			second := f.authorize(t, session)
			if !second.ExpiresAt.Equal(first.ExpiresAt) {
				t.Fatal("a later UDP response extended an existing approval")
			}
			f.now = first.ExpiresAt
			if _, err := session.readRecord(); !errors.Is(err, errSSHSessionExpired) {
				t.Fatalf("expired record err=%v", err)
			}
		})
	}
}

func TestSSHSessionLifetimeUsesBoundShellAndNeverRenews(t *testing.T) {
	for _, test := range []struct {
		name, shell                  string
		announcement, response, want time.Duration
	}{
		{"Unix exact three hours", "posix", 3 * time.Hour, 3 * time.Hour, 3 * time.Hour},
		{"Unix upper cap", "posix", 4 * time.Hour, 4 * time.Hour, 3 * time.Hour},
		{"Unix short announcement", "posix", 30 * time.Minute, 3 * time.Hour, 30 * time.Minute},
		{"Unix short response", "posix", 3 * time.Hour, 30 * time.Minute, 30 * time.Minute},
		{"Windows remains thirty minutes", "", 3 * time.Hour, 3 * time.Hour, 30 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			start := f.now
			f.announcement.Shell = test.shell
			f.announcement.ExpiresAt = start.Add(test.announcement)
			f.responseUntil = start.Add(test.response)
			session := f.open(t)
			first := f.authorize(t, session)
			if !first.ExpiresAt.Equal(start.Add(test.want)) {
				t.Fatalf("expiry=%s want=%s", first.ExpiresAt, start.Add(test.want))
			}
			// A two-hour point proves Unix records survive the old 30-minute
			// validator, while shorter/legacy approvals stay readable before expiry.
			advance := 10 * time.Minute
			if test.want == 3*time.Hour {
				advance = 2 * time.Hour
			}
			f.now = start.Add(advance)
			stored, err := session.readRecord()
			if err != nil || !stored.ExpiresAt.Equal(first.ExpiresAt) {
				t.Fatalf("read existing record: %v", err)
			}
			f.announcement.ExpiresAt = start.Add(4 * time.Hour)
			f.responseUntil = start.Add(4 * time.Hour)
			second, reused, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen)
			if err != nil || !reused || !second.ExpiresAt.Equal(first.ExpiresAt) || f.generated != 1 || f.approvals != 1 {
				t.Fatalf("reuse changed deadline or approval: reused=%v err=%v generated=%d approvals=%d", reused, err, f.generated, f.approvals)
			}
			f.now = first.ExpiresAt
			if _, err := session.readRecord(); !errors.Is(err, errSSHSessionExpired) {
				t.Fatalf("exact expiry accepted: %v", err)
			}
		})
	}
}

func TestSSHSessionCacheRejectsLifetimeBeyondShellLimit(t *testing.T) {
	for _, test := range []struct {
		name, shell string
		limit       time.Duration
	}{
		{"Unix three hours", "posix", 3 * time.Hour},
		{"Windows thirty minutes", "", 30 * time.Minute},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			f.announcement.Shell = test.shell
			session := f.open(t)
			record := f.authorize(t, session)
			record.ExpiresAt = record.CreatedAt.Add(test.limit)
			if err := session.save(record); err != nil {
				t.Fatal(err)
			}
			if _, err := session.readRecord(); err != nil {
				t.Fatalf("exact shell limit rejected: %v", err)
			}
			record.ExpiresAt = record.ExpiresAt.Add(time.Nanosecond)
			if err := session.save(record); err != nil {
				t.Fatal(err)
			}
			if _, err := session.readRecord(); err == nil {
				t.Fatal("record beyond shell limit accepted")
			}
		})
	}
}

func TestSSHSessionThreeHourUnixKeepsIdentityBindings(t *testing.T) {
	for _, change := range []string{"host key", "account", "Shell"} {
		t.Run(change, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			f.announcement.Shell, f.announcement.Username = "posix", "macuser"
			f.announcement.ExpiresAt = f.now.Add(3 * time.Hour)
			f.responseUntil = f.announcement.ExpiresAt
			session := f.open(t)
			original := f.authorize(t, session)
			f.now = f.now.Add(time.Hour)
			selected := f.announcement
			wantPairs := 1
			switch change {
			case "host key":
				f.hostKey = sshTestPublicKey(3)
				wantPairs = 2
			case "account":
				selected.Username = "MacUser"
			case "Shell":
				selected.Shell = ""
			}
			if _, _, err := session.authorize(context.Background(), selected, f.endpoint, "", f.pair, f.keygen); err == nil {
				t.Fatal("changed Unix identity accepted")
			}
			stored, err := session.readRecord()
			if err != nil || stored.HostKey != original.HostKey || stored.Username != original.Username || stored.Shell != original.Shell || !stored.ExpiresAt.Equal(original.ExpiresAt) || f.generated != 1 || len(f.pairRequests) != wantPairs {
				t.Fatalf("failed binding check changed cached approval: err=%v generated=%d pairs=%d", err, f.generated, len(f.pairRequests))
			}
		})
	}
}

func TestSSHSessionUncommittedStagingStillExpiresAtThirtyMinutes(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	if _, err := f.keygen(context.Background(), session.directory, "manager"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(session.directory, f.now, f.now); err != nil {
		t.Fatal(err)
	}
	session.close()
	start := f.now
	f.now = start.Add(29 * time.Minute)
	if err := f.cache.pruneExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.privatePath()); err != nil {
		t.Fatal("staging removed before its original deadline")
	}
	f.now = start.Add(30 * time.Minute)
	if err := f.cache.pruneExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unapproved staging retained beyond thirty minutes: %v", err)
	}
}

func TestSSHSessionGarbageCollectionSkipsBusySessionsAndOtherDirectories(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	original := f.authorize(t, session)
	unrelated := filepath.Join(f.cache.root, "unrelated")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatal(err)
	}
	f.now = original.ExpiresAt
	if err := f.cache.pruneExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.privatePath()); err != nil {
		t.Fatal("garbage collection removed a key still held by an SSH command")
	}
	session.close()
	if err := f.cache.pruneExpired(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired directory remains, err=%v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatal("garbage collection touched an unrelated directory")
	}
}

func TestSSHSessionLockHasBoundedWaitAndPreventsForgetDuringCommand(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	f.authorize(t, session)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := f.cache.forget(ctx, f.announcement.InstanceID); !errors.Is(err, errSSHSessionBusy) {
		t.Fatalf("concurrent forget err=%v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("lock did not honor the caller's shorter deadline")
	}
	if _, err := os.Stat(session.privatePath()); err != nil {
		t.Fatal("concurrent forget removed a key in use")
	}
	session.close()
	if err := f.cache.forget(context.Background(), f.announcement.InstanceID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forgotten directory remains, err=%v", err)
	}
}

func TestSSHSessionFailedOrRejectedPairLeavesNoKey(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "rejection"}[reject], func(t *testing.T) {
			f := newSSHSessionFixture(t)
			session := f.open(t)
			pair := func(_ context.Context, request discovery.PairRequest) (discovery.PairResponse, error) {
				if !reject {
					return discovery.PairResponse{}, context.DeadlineExceeded
				}
				return discovery.PairResponse{V: discovery.Version, Type: discovery.PairResponseType, InstanceID: request.InstanceID, RequestNonce: request.RequestNonce, Accepted: false, Reason: "declined"}, nil
			}
			if _, _, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", pair, f.keygen); err == nil {
				t.Fatal("unsuccessful pairing was accepted")
			}
			if _, err := os.Stat(session.directory); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed pair left cache directory, err=%v", err)
			}
		})
	}
}

func TestSSHSessionDamagedCacheFailsWithoutSilentlyGeneratingNewKey(t *testing.T) {
	for _, file := range []string{"manager.pub", "known_hosts", "session.json"} {
		t.Run(file, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			session := f.open(t)
			f.authorize(t, session)
			if err := os.WriteFile(filepath.Join(session.directory, file), []byte("damaged"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", f.pair, f.keygen); err == nil {
				t.Fatal("damaged cache was accepted")
			}
			if f.generated != 1 || len(f.pairRequests) != 1 {
				t.Fatal("cache damage silently discarded authorization and asked to pair again")
			}
		})
	}
}

func TestSSHSessionClearNeverRecursivelyDeletesUnexpectedFiles(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	f.authorize(t, session)
	unexpected := filepath.Join(session.directory, "unrelated")
	if err := os.WriteFile(unexpected, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := session.clear(); err == nil {
		t.Fatal("unexpected file did not cause a reported cleanup failure")
	}
	if data, err := os.ReadFile(unexpected); err != nil || string(data) != "preserve" {
		t.Fatal("cleanup deleted an unexpected file")
	}
}

func TestSSHSessionNameCannotEscapeCacheRoot(t *testing.T) {
	name, err := sshSessionName("../../untrusted/instance")
	if err != nil || !sshSessionNamePattern.MatchString(name) {
		t.Fatalf("name=%q err=%v", name, err)
	}
	for _, instance := range []string{"", "\r\n", "invalid\x00instance", strings.Repeat("x", 129)} {
		if _, err := sshSessionName(instance); err == nil {
			t.Fatalf("invalid instance accepted: %q", instance)
		}
	}
}

func TestSSHSessionPassesExactPairDeadlineToTarget(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	deadline := time.Now().Add(120 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if _, _, err := session.authorize(ctx, f.announcement, f.endpoint, "", f.pair, f.keygen); err != nil {
		t.Fatal(err)
	}
	if !f.pairRequests[0].ConfirmUntil.Equal(deadline) {
		t.Fatalf("target confirmation deadline=%s want=%s", f.pairRequests[0].ConfirmUntil, deadline)
	}
}

func TestSSHSessionPOSIXShellAndCaseSensitiveUsername(t *testing.T) {
	f := newSSHSessionFixture(t)
	f.announcement.Shell, f.announcement.Username = "posix", "macuser"
	session := f.open(t)
	first := f.authorize(t, session)
	if first.Shell != "posix" || first.Username != "macuser" {
		t.Fatalf("POSIX binding missing: %#v", first)
	}
	stored, err := session.readRecord()
	if err != nil || stored.Shell != "posix" {
		t.Fatalf("POSIX cache round trip: shell=%q err=%v", stored.Shell, err)
	}
	for _, mutation := range []string{"announcement casing", "override casing", "shell downgrade"} {
		t.Run(mutation, func(t *testing.T) {
			selected, override := f.announcement, ""
			switch mutation {
			case "announcement casing":
				selected.Username = "MacUser"
			case "override casing":
				override = "MacUser"
			case "shell downgrade":
				selected.Shell = ""
			}
			_, _, err := session.authorize(context.Background(), selected, f.endpoint, override, f.pair, f.keygen)
			if err == nil || len(f.pairRequests) != 1 {
				t.Fatalf("changed binding err=%v pair count=%d", err, len(f.pairRequests))
			}
		})
	}
	_, reused, err := session.authorize(context.Background(), f.announcement, f.endpoint, "macuser", f.pair, f.keygen)
	if err != nil || !reused || f.generated != 1 || f.approvals != 1 {
		t.Fatalf("POSIX reuse=%v err=%v generated=%d approvals=%d", reused, err, f.generated, f.approvals)
	}
}

func TestSSHSessionFirstPOSIXPairRejectsMismatchedResponse(t *testing.T) {
	for _, mutation := range []string{"shell", "username casing"} {
		t.Run(mutation, func(t *testing.T) {
			f := newSSHSessionFixture(t)
			f.announcement.Shell, f.announcement.Username = "posix", "macuser"
			session := f.open(t)
			pair := func(ctx context.Context, request discovery.PairRequest) (discovery.PairResponse, error) {
				response, err := f.pair(ctx, request)
				if mutation == "shell" {
					response.Shell = ""
				} else {
					response.Username = "MacUser"
				}
				return response, err
			}
			if _, _, err := session.authorize(context.Background(), f.announcement, f.endpoint, "", pair, f.keygen); err == nil {
				t.Fatal("mismatched POSIX response accepted")
			}
			if _, err := os.Stat(session.privatePath()); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed POSIX pairing retained a key: %v", err)
			}
		})
	}
}

func TestSSHSessionLegacyWindowsCacheOmitsShellAndKeepsCaseInsensitiveUser(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	record, _, err := session.authorize(context.Background(), f.announcement, f.endpoint, "remotebridge", f.pair, f.keygen)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(record)
	if err != nil || strings.Contains(string(data), `"shell"`) {
		t.Fatalf("legacy cache changed: %s err=%v", data, err)
	}
}

func TestSSHManageConflictingFlagsAreRejectedBeforeDiscovery(t *testing.T) {
	for _, options := range [][]string{
		{"--manage", "--command", "hostname"},
		{"--manage", "--command", ""},
		{"--manage", "--json"},
		{"--manage", "--forget-session"},
	} {
		if code := runSSH(options); code != 2 {
			t.Fatalf("options=%q code=%d", options, code)
		}
	}
}

func TestSSHSessionFinishRemovesFilesAfterRunningCommandExpires(t *testing.T) {
	f := newSSHSessionFixture(t)
	session := f.open(t)
	record := f.authorize(t, session)
	f.now = record.ExpiresAt
	if err := session.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(session.directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired command left local key files, err=%v", err)
	}
}
