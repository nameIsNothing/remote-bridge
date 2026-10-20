package main

import (
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/discovery"
)

func TestRemoteExecScriptEncodesNestedCommand(t *testing.T) {
	command := `Get-ChildItem C:\ | Where-Object Name -like 'USB*'`
	script := remoteExecScript("192.0.2.10", "EDY", command, 5985)
	if !strings.Contains(script, "-EncodedCommand $encodedBridgeCommand") {
		t.Fatal("remote exec script does not encode the nested PowerShell command")
	}
	if strings.Contains(script, "-Command $bridgeCommand") {
		t.Fatal("remote exec script still passes the nested command as a native argument")
	}
	if !strings.Contains(script, encodeValue(command)) {
		t.Fatal("remote exec script lost the encoded requested command")
	}
}

func TestSelectWinRMAnnouncementFiltersTransportAndTarget(t *testing.T) {
	items := []discovery.Announcement{
		{V: discovery.Version, Type: discovery.AnnouncementType, InstanceID: "ssh", Hostname: "target", Addresses: []string{"192.0.2.10"}, Port: 2222, Transport: "ssh", Username: "RemoteBridge", ExpiresAt: time.Now().Add(time.Minute)},
		{V: discovery.Version, Type: discovery.AnnouncementType, InstanceID: "winrm", Hostname: "target", Addresses: []string{"192.0.2.10"}, Port: 5985, Transport: "winrm", Username: `TARGET\EDY`, ExpiresAt: time.Now().Add(time.Minute)},
	}
	selected, err := selectWinRMAnnouncement(items, "192.0.2.10")
	if err != nil || selected.Transport != "winrm" || selected.Port != 5985 {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
}

func TestVerifiedWinRMScriptChecksIdentityAndKeepsPasswordSecure(t *testing.T) {
	script := verifiedRemoteExecScript("192.0.2.10", `TARGET\EDY`, "Get-Date", 5985)
	for _, want := range []string{"Read-Host", "-AsSecureString", "whoami", "New-PSSession", "Remove-PSSession", "exit $bridgeExitCode"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	for _, forbidden := range []string{"-Password", "$password", "cmdkey", "ConvertFrom-SecureString"} {
		if strings.Contains(strings.ToLower(script), strings.ToLower(forbidden)) {
			t.Fatalf("script contains forbidden credential handling %q", forbidden)
		}
	}
}

func TestWinRMResultCodesDoNotConfuseRemoteFailureWithIdentityFailure(t *testing.T) {
	for _, tc := range []struct{ input, want int }{
		{0, 0}, {11, 11}, {20, 20}, {21, 21}, {1, 20}, {-1, 20},
	} {
		if got := winRMResultCode(tc.input); got != tc.want {
			t.Errorf("winRMResultCode(%d) = %d, want %d", tc.input, got, tc.want)
		}
	}
}
