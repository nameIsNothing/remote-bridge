package main

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"remote-bridge/internal/discovery"
	"remote-bridge/internal/platform/windows"
)

func TestChooseTargetAddress(t *testing.T) {
	addresses := []localAddress{
		{Interface: "Ethernet", Address: "192.168.1.30"},
		{Interface: "Wi-Fi", Address: "10.0.0.5"},
	}

	selected, ok := chooseTargetAddress(bufio.NewReader(strings.NewReader("2\n")), addresses)
	if !ok || selected != "10.0.0.5" {
		t.Fatalf("selected = %q, ok = %t", selected, ok)
	}

	selected, ok = chooseTargetAddress(bufio.NewReader(strings.NewReader("\n")), addresses)
	if !ok || selected != "192.168.1.30" {
		t.Fatalf("default selected = %q, ok = %t", selected, ok)
	}

	if selected, ok = chooseTargetAddress(bufio.NewReader(strings.NewReader("3\n")), addresses); ok || selected != "" {
		t.Fatalf("invalid selection = %q, ok = %t", selected, ok)
	}
}

func TestChooseTargetAddressSingleOrEmpty(t *testing.T) {
	selected, ok := chooseTargetAddress(bufio.NewReader(strings.NewReader("")), []localAddress{{Address: "192.168.1.30"}})
	if !ok || selected != "192.168.1.30" {
		t.Fatalf("single selected = %q, ok = %t", selected, ok)
	}
	selected, ok = chooseTargetAddress(bufio.NewReader(strings.NewReader("")), nil)
	if !ok || selected != "" {
		t.Fatalf("empty selected = %q, ok = %t", selected, ok)
	}
}

func TestFirstAddressPrefersPhysicalLAN(t *testing.T) {
	addresses := []localAddress{
		{Interface: "VMware Network Adapter VMnet8", Address: "192.168.77.1"},
		{Interface: "Ethernet", Address: "192.168.100.27"},
		{Interface: "vEthernet (WSL)", Address: "172.17.208.1"},
	}
	if got := firstAddress(addresses); got != "192.168.100.27" {
		t.Fatalf("firstAddress() = %q, want physical Ethernet address", got)
	}
}

func TestListenerPreparationDecision(t *testing.T) {
	configure, warning := listenerPreparationDecision(windows.WinRMStatus{Known: true}, nil)
	if !configure || warning != "" {
		t.Fatalf("missing listener decision = configure %t, warning %q", configure, warning)
	}

	configure, warning = listenerPreparationDecision(windows.WinRMStatus{
		Known:           true,
		ListenerPresent: true,
		HTTPListener:    true,
	}, nil)
	if configure || warning != "" {
		t.Fatalf("HTTP listener decision = configure %t, warning %q", configure, warning)
	}

	configure, warning = listenerPreparationDecision(windows.WinRMStatus{
		Known:             true,
		ListenerPresent:   true,
		ListenerProtocols: []string{"HTTPS"},
		ListenerPorts:     []int{5986},
	}, nil)
	if configure || !strings.Contains(warning, "5986") {
		t.Fatalf("mismatched listener decision = configure %t, warning %q", configure, warning)
	}

	configure, warning = listenerPreparationDecision(windows.WinRMStatus{Error: "Access is denied"}, errors.New("probe failed"))
	if !configure || !strings.Contains(warning, "Access is denied") {
		t.Fatalf("unknown listener decision = configure %t, warning %q", configure, warning)
	}
}

func TestInteractiveApplyConfirmed(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "empty line", input: "\n", want: true},
		{name: "Windows empty line", input: "\r\n", want: true},
		{name: "whitespace", input: "  \t\n", want: true},
		{name: "Windows whitespace", input: "  \t\r\n", want: true},
		{name: "empty stdin EOF", input: "", want: false},
		{name: "whitespace EOF", input: "  \t", want: false},
		{name: "incomplete Windows line", input: "\r", want: false},
		{name: "non-empty token", input: "APPLY\n", want: false},
		{name: "non-empty lowercase token", input: "apply\n", want: false},
		{name: "cancel", input: "no\n", want: false},
		{name: "non-empty EOF", input: "no", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := interactiveApplyConfirmed(bufio.NewReader(strings.NewReader(test.input))); got != test.want {
				t.Fatalf("interactiveApplyConfirmed(%q) = %t, want %t", test.input, got, test.want)
			}
		})
	}
}

func TestInteractiveApplyReadErrorCancels(t *testing.T) {
	readErr := errors.New("confirmation input failed")
	tests := []struct {
		name   string
		reader io.Reader
	}{
		{name: "immediate error", reader: iotest.ErrReader(readErr)},
		{name: "error after whitespace", reader: io.MultiReader(strings.NewReader("  \t"), iotest.ErrReader(readErr))},
		{name: "error during Windows newline", reader: io.MultiReader(strings.NewReader("\r"), iotest.ErrReader(readErr))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if interactiveApplyConfirmed(bufio.NewReader(test.reader)) {
				t.Fatal("read error must cancel configuration")
			}
		})
	}
}

func TestSSHAccountMarkerFitsWindowsDescriptionLimit(t *testing.T) {
	planID := strings.Repeat("x", 32)
	marker := sshAccountMarker(planID)
	if len(marker) > 48 {
		t.Fatalf("SSH account marker length = %d, want <= 48: %q", len(marker), marker)
	}
	if !strings.HasPrefix(marker, sshAccountMarkerPrefix) {
		t.Fatalf("SSH account marker = %q, want prefix %q", marker, sshAccountMarkerPrefix)
	}
	if got := legacySSHAccountMarker(planID); !strings.HasPrefix(got, legacySSHAccountMarkerPrefix) {
		t.Fatalf("legacy SSH account marker = %q, want prefix %q", got, legacySSHAccountMarkerPrefix)
	}
	script := buildSSHAccountScript(windows.DefaultTemporaryUser, planID, 1800)
	if !strings.Contains(script, "$marker = '"+marker+"'") {
		t.Fatalf("account script does not use the short marker: %q", script)
	}
	if !strings.Contains(script, "StartsWith('"+legacySSHAccountMarkerPrefix+"'") {
		t.Fatalf("account script does not accept the legacy marker")
	}
}

func TestStateFilePresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bridge-plan.json")
	present, err := stateFilePresent(path)
	if err != nil || present {
		t.Fatalf("missing state = present %t, err %v", present, err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	present, err = stateFilePresent(path)
	if err != nil || !present {
		t.Fatalf("existing state = present %t, err %v", present, err)
	}
	present, err = stateFilePresent(dir)
	if err == nil || !present || !strings.Contains(err.Error(), "目录") {
		t.Fatalf("directory state = present %t, err %v", present, err)
	}
}

func TestBuildDiscoveryAnnouncementContainsNoSecret(t *testing.T) {
	plan, err := windows.BuildPlan(windows.PlanOptions{
		ID:                "discover-test",
		ManagementAddress: windows.LocalSubnet,
		AllowHTTP:         true,
		AccountTTL:        10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 24, 1, 2, 3, 0, time.UTC)
	announcement := buildDiscoveryAnnouncement(plan, "192.168.100.27", []localAddress{{Address: "192.168.100.27"}}, now)
	if announcement.InstanceID != plan.ID || announcement.Username != plan.Options.TemporaryUser {
		t.Fatalf("announcement identity = %#v", announcement)
	}
	if announcement.Port != windows.DefaultHTTPPort || announcement.Transport != string(windows.TransportHTTP) {
		t.Fatalf("announcement endpoint = %#v", announcement)
	}
	if !announcement.ExpiresAt.Equal(now.Add(plan.Options.AccountTTL)) {
		t.Fatalf("expiry = %s", announcement.ExpiresAt)
	}
	if announcement.RequestNonce != "" {
		t.Fatal("target announcement must not contain a request nonce before responding")
	}
}

func TestTargetDiscoveryResponderStops(t *testing.T) {
	announcement := discovery.Announcement{
		V:          discovery.Version,
		Type:       discovery.AnnouncementType,
		InstanceID: "stop-test",
		Hostname:   "target",
		Addresses:  []string{"192.168.100.27"},
		Port:       windows.DefaultHTTPPort,
		Transport:  string(windows.TransportHTTP),
		Username:   windows.DefaultTemporaryUser,
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	statePath := filepath.Join(t.TempDir(), "bridge-plan.json")
	responder, err := startTargetDiscoveryResponder(announcement, statePath)
	if err != nil {
		t.Skipf("UDP discovery port unavailable: %v", err)
	}
	query, err := discovery.NewQuery()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := discovery.MarshalQuery(query)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		responder.Stop()
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP(payload, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: discovery.DefaultPort}); err != nil {
		responder.Stop()
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, discovery.MaxPacketSize)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		responder.Stop()
		t.Fatal(err)
	}
	got, err := discovery.UnmarshalAnnouncement(buf[:n])
	if err != nil {
		responder.Stop()
		t.Fatal(err)
	}
	if got.RequestNonce != query.RequestNonce || got.InstanceID != announcement.InstanceID {
		responder.Stop()
		t.Fatalf("response = %#v", got)
	}
	if err := os.WriteFile(discoveryRevocationMarker(statePath), []byte("revoked\n"), 0600); err != nil {
		responder.Stop()
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	responder.Stop()
	responder.Stop() // Stop is intentionally idempotent for the wizard cleanup path.
}
