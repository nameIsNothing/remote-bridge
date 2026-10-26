package unixssh

import (
	"net"
	"strings"
	"testing"
	"time"
)

func testLease() Lease {
	now := time.Now().UTC()
	return Lease{Version: 1, Instance: "usb-0123456789abcdef01234567", Username: "testuser", UID: 501, GID: 20, Shell: "/bin/zsh", Addresses: []string{"192.168.100.132"}, Subnets: []string{"192.168.100.0/24"}, Port: 2222, CreatedAt: now, ExpiresAt: now.Add(MaxLifetime), UpdatedAt: now, Active: true}
}

func TestUnixSSHThreeHourLimit(t *testing.T) {
	if MaxLifetime != 3*time.Hour {
		t.Fatalf("Unix SSH limit=%s", MaxLifetime)
	}
	l := testLease()
	l.ExpiresAt = l.CreatedAt.Add(3 * time.Hour)
	if err := l.Validate(); err != nil {
		t.Fatalf("3h rejected: %v", err)
	}
	l.ExpiresAt = l.ExpiresAt.Add(time.Nanosecond)
	if err := l.Validate(); err == nil {
		t.Fatal("over 3h accepted")
	}
	l.ExpiresAt = l.CreatedAt.Add(30 * time.Minute)
	if err := l.Validate(); err != nil {
		t.Fatalf("existing short lease rejected: %v", err)
	}
}
func TestLeaseBoundaries(t *testing.T) {
	good := testLease()
	if e := good.Check(good.UpdatedAt, 501); e != nil {
		t.Fatal(e)
	}
	cases := map[string]func(*Lease){"root": func(l *Lease) { l.UID = 0 }, "public": func(l *Lease) { l.Addresses = []string{"8.8.8.8"} }, "wide_subnet": func(l *Lease) { l.Subnets = []string{"0.0.0.0/0"} }, "expired": func(l *Lease) { l.ExpiresAt = l.CreatedAt }, "extended": func(l *Lease) { l.ExpiresAt = l.ExpiresAt.Add(time.Second) }, "stale": func(l *Lease) { l.UpdatedAt = l.CreatedAt.Add(-6 * time.Second) }, "future": func(l *Lease) { l.UpdatedAt = l.CreatedAt.Add(3 * time.Second) }, "revoked": func(l *Lease) { l.Active = false }, "username_options": func(l *Lease) { l.Username = "x *" }}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			l := good
			modify(&l)
			if l.Check(good.CreatedAt, 501) == nil {
				t.Fatal("accepted invalid lease")
			}
		})
	}
	if good.Check(good.CreatedAt, 502) == nil {
		t.Fatal("wrong uid accepted")
	}
	if good.Check(good.ExpiresAt, 501) == nil {
		t.Fatal("expiry accepted")
	}
	if !good.Allows(net.ParseIP("192.168.100.66")) || good.Allows(net.ParseIP("192.168.101.66")) || good.Allows(net.ParseIP("8.8.8.8")) {
		t.Fatal("source restriction failed")
	}
}
func TestIsolatedConfig(t *testing.T) {
	l := testLease()
	dir := "/private/var/RemoteBridge-" + l.Instance
	config, e := Config(l, dir)
	if e != nil {
		t.Fatal(e)
	}
	for _, part := range []string{"ListenAddress 192.168.100.132", "AllowUsers testuser@192.168.100.0/24", "AuthorizedKeysFile " + dir + "/authorized_keys", "ForceCommand " + dir + "/bridge-target ssh-unix-session " + dir, "PasswordAuthentication no", "PermitRootLogin no", "DisableForwarding yes", "PermitUserRC no", "UsePAM yes"} {
		if !strings.Contains(config, part+"\n") {
			t.Errorf("missing %s", part)
		}
	}
	for _, bad := range []string{"0.0.0.0", "Include ", "/etc/ssh/", ".ssh/authorized_keys"} {
		if strings.Contains(config, bad) {
			t.Errorf("global config dependency: %s", bad)
		}
	}
	for _, bad := range []string{"/tmp/wrong", "/private/var/tmp/RemoteBridge-" + l.Instance + "\nInclude x", "relative/RemoteBridge-" + l.Instance} {
		if _, e := Config(l, bad); e == nil {
			t.Fatal("unsafe dir accepted")
		}
	}
}
