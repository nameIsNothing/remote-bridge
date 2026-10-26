package managedsession

import (
	"strings"
	"testing"
	"time"
)

func sshTestInfo() Info {
	return Info{ID: "rb-0123456789abcdef01234567", InstanceID: "ssh-0123456789ab", Target: "192.0.2.10", Hostname: "fixture.local",
		Username: "fixture", UID: "501", Transport: "ssh", Shell: "posix", Port: 2222, ExpiresAt: time.Now().Add(time.Minute).UTC()}
}

func TestSSHTransportRejectsRootUnknownShellAndExtendedLifetime(t *testing.T) {
	for name, change := range map[string]func(*Info){
		"root":              func(i *Info) { i.UID = "0" },
		"missing uid":       func(i *Info) { i.UID = "" },
		"uid with zeros":    func(i *Info) { i.UID = "0501" },
		"uid injection":     func(i *Info) { i.UID = "501\nroot" },
		"uid overflow":      func(i *Info) { i.UID = "4294967296" },
		"Windows SID":       func(i *Info) { i.SID = "S-1-5-21-1" },
		"missing shell":     func(i *Info) { i.Shell = "" },
		"other shell":       func(i *Info) { i.Shell = "zsh -c" },
		"unknown transport": func(i *Info) { i.Transport = "other" },
		"expired":           func(i *Info) { i.ExpiresAt = time.Now().Add(-time.Second) },
		"long lifetime":     func(i *Info) { i.ExpiresAt = time.Now().Add(MaxSSHLifetime + time.Second) },
		"bad port":          func(i *Info) { i.Port = 0 },
		"large port":        func(i *Info) { i.Port = 65536 },
	} {
		t.Run(name, func(t *testing.T) {
			info := sshTestInfo()
			change(&info)
			if server, err := NewServer(info, nil); err == nil {
				server.Shutdown()
				t.Fatal("invalid SSH binding accepted")
			}
		})
	}
	info := sshTestInfo()
	info.ExpiresAt = time.Now().Add(MaxSSHLifetime)
	server, err := NewServer(info, nil)
	if err != nil {
		t.Fatal("maximum Unix SSH deadline rejected:", err)
	}
	server.Shutdown()
	legacy := testInfo()
	legacy.UID = "501"
	if server, err := NewServer(legacy, nil); err == nil {
		server.Shutdown()
		t.Fatal("Unix identity accepted as a WinRM binding")
	}
}

func TestSSHThreeHourLimitAndExistingShortDeadline(t *testing.T) {
	now := time.Now()
	info := sshTestInfo()
	info.ExpiresAt = now.Add(3 * time.Hour)
	if !validTransport(info, now) {
		t.Fatal("exact three-hour SSH lifetime rejected")
	}
	info.ExpiresAt = info.ExpiresAt.Add(time.Nanosecond)
	if validTransport(info, now) {
		t.Fatal("SSH lifetime beyond three hours accepted")
	}
	// NewServer independently verifies the public constructor's boundary.
	info.ExpiresAt = time.Now().Add(3 * time.Hour)
	server, err := NewServer(info, nil)
	if err != nil {
		t.Fatal("three-hour server rejected:", err)
	}
	if !server.Info().ExpiresAt.Equal(info.ExpiresAt) {
		t.Fatal("server changed the target's absolute deadline")
	}
	server.Shutdown()
	info.ExpiresAt = time.Now().Add(3*time.Hour + time.Minute)
	if server, err := NewServer(info, nil); err == nil {
		server.Shutdown()
		t.Fatal("overlong SSH server accepted")
	}
	// An old thirty-minute entry remains thirty minutes after upgrading the
	// manager. A worker cannot replace it with the new maximum at Ready.
	info.ExpiresAt = time.Now().Add(30 * time.Minute)
	server, err = NewServer(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	extended := server.Info()
	extended.ExpiresAt = time.Now().Add(3 * time.Hour)
	if err := server.Ready(extended); err == nil || !server.Info().ExpiresAt.Equal(info.ExpiresAt) {
		t.Fatal("upgraded manager renewed an existing short entry")
	}
}

func TestSSHReadyBindsEveryAuthenticatedField(t *testing.T) {
	for name, change := range map[string]func(*Info){
		"hostname":          func(i *Info) { i.Hostname = "other.local" },
		"username case":     func(i *Info) { i.Username = "Fixture" },
		"uid":               func(i *Info) { i.UID = "502" },
		"root":              func(i *Info) { i.UID = "0" },
		"Windows SID":       func(i *Info) { i.SID = "S-1-5-21-1" },
		"missing transport": func(i *Info) { i.Transport = "" },
		"missing shell":     func(i *Info) { i.Shell = "" },
		"instance":          func(i *Info) { i.InstanceID = "other" },
		"session":           func(i *Info) { i.ID = "rb-fedcba987654321001234567" },
		"target":            func(i *Info) { i.Target = "192.0.2.11" },
		"port":              func(i *Info) { i.Port = 2223 },
		"expiry":            func(i *Info) { i.ExpiresAt = i.ExpiresAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			server, err := NewServer(sshTestInfo(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Shutdown()
			changed := server.Info()
			change(&changed)
			if err := server.Ready(changed); err == nil || server.Info().State != "closing" {
				t.Fatalf("binding mismatch accepted: %+v err=%v", server.Info(), err)
			}
		})
	}
	server, err := NewServer(sshTestInfo(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	if err := server.Ready(server.Info()); err != nil || server.Info().State != "connected" {
		t.Fatalf("valid SSH worker rejected: %v", err)
	}
	if text := Handoff(server.Info(), "bridge-cli.exe"); !strings.Contains(text, "POSIX sh") || strings.Contains(text, "另建 WinRM") {
		t.Fatalf("wrong SSH handoff: %s", text)
	}
}

func TestWinRMReadyRetainsLegacyProjectedIdentity(t *testing.T) {
	info := testInfo()
	server, err := NewServer(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	projected := Info{InstanceID: info.InstanceID, Hostname: info.Hostname, Username: info.Username, SID: "S-1-5-21-1", ExpiresAt: info.ExpiresAt}
	workerPost(t, server, WorkerMessage{Operation: "ready", Info: &projected}, 200)
	if server.Info().State != "connected" || server.Info().SID != projected.SID || server.Info().Target != info.Target {
		t.Fatal("legacy WinRM worker projection no longer accepted")
	}
}
