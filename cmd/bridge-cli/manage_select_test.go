package main

import (
	"reflect"
	"testing"
	"time"

	"remote-bridge/internal/discovery"
)

func TestManagedStartupSelectsUnixAndPreservesWindowsPriority(t *testing.T) {
	now := time.Now()
	unix := discovery.Announcement{InstanceID: "usb-unix", Hostname: "mac.local", Addresses: []string{"192.0.2.11"}, Port: 2222, Username: "unixuser", Shell: "posix", Transport: "ssh", ExpiresAt: now.Add(time.Minute)}
	windows := discovery.Announcement{InstanceID: "ssh-windows", Hostname: "windows", Addresses: []string{"192.0.2.12"}, Port: 5985, Username: `WINDOWS\User`, Transport: "winrm-http", ExpiresAt: now.Add(time.Minute)}
	for _, tc := range []struct {
		name         string
		items        []discovery.Announcement
		target, want string
		fail         bool
	}{
		{name: "Unix only", items: []discovery.Announcement{unix}, want: unix.InstanceID},
		{name: "Windows first", items: []discovery.Announcement{unix, windows}, want: windows.InstanceID},
		{name: "Explicit Unix IP", items: []discovery.Announcement{windows, unix}, target: "192.0.2.11", want: unix.InstanceID},
		{name: "Explicit Unix hostname", items: []discovery.Announcement{windows, unix}, target: "MAC.LOCAL", want: unix.InstanceID},
		{name: "Explicit Windows", items: []discovery.Announcement{unix, windows}, target: "192.0.2.12", want: windows.InstanceID},
		{name: "Unknown target", items: []discovery.Announcement{unix, windows}, target: "192.0.2.99", fail: true},
		{name: "Nothing advertised", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectManagedAnnouncement(tc.items, tc.target)
			if (err != nil) != tc.fail || (!tc.fail && got.InstanceID != tc.want) {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	legacy := unix
	legacy.Shell = ""
	if _, err := selectManagedAnnouncement([]discovery.Announcement{legacy}, ""); err == nil {
		t.Fatal("legacy Windows SSH incorrectly routed into Unix managed mode")
	}
	other := unix
	other.InstanceID = "usb-other"
	other.Hostname = "other.local"
	other.Addresses = []string{"192.0.2.13"}
	if _, err := selectManagedAnnouncement([]discovery.Announcement{unix, other}, ""); err == nil {
		t.Fatal("silently chose between two Unix targets")
	}
	secondWindows := windows
	secondWindows.InstanceID = "ssh-second"
	secondWindows.Addresses = []string{"192.0.2.14"}
	if _, err := selectManagedAnnouncement([]discovery.Announcement{windows, secondWindows, unix}, ""); err == nil {
		t.Fatal("WinRM ambiguity incorrectly fell back to Unix")
	}
	expired := unix
	expired.ExpiresAt = now.Add(-time.Second)
	if _, err := selectManagedAnnouncement([]discovery.Announcement{expired}, ""); err == nil {
		t.Fatal("expired target selected")
	}
}

func TestManagedStartupSSHRetainsSelectedInstanceAndNetworkOptions(t *testing.T) {
	item := discovery.Announcement{InstanceID: "usb-selected"}
	got := managedSSHStartupArguments(item, "192.0.2.11", "192.0.2.255", 3*time.Second, 37021)
	want := []string{"--target", "192.0.2.11", "--instance", "usb-selected", "--manage", "--broadcast", "192.0.2.255", "--timeout", "3s", "--discovery-port", "37021", "--pair-timeout", "300s"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("selected target/options changed: %q", got)
	}
}
