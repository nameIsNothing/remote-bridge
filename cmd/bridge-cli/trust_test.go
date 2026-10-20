package main

import (
	"strings"
	"testing"
)

func TestParseTrustTargetAcceptsPositionAndFlag(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "position", args: []string{"192.168.100.27"}, want: "192.168.100.27"},
		{name: "flag", args: []string{"--target", "WIN-TEST"}, want: "WIN-TEST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseTrustTarget(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("target = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustTargetRejectsInjectionAndAmbiguousForms(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"192.168.100.27", "192.168.100.28"},
		{"--target", "192.168.100.27", "192.168.100.28"},
		{"--target", "192.168.100.27,10.0.0.1"},
		{"--target", "192.168.100.27;Write-Error pwned"},
		{"--target", "*"},
		{"--target", ".."},
	} {
		if _, err := parseTrustTarget(args); err == nil {
			t.Fatalf("parseTrustTarget(%q) unexpectedly succeeded", args)
		}
	}
}

func TestParseTrustOptionsKeepsUACMarkerInternal(t *testing.T) {
	options, err := parseTrustOptions([]string{"--target", "192.168.100.27", "--uac-child"})
	if err != nil {
		t.Fatal(err)
	}
	if options.target != "192.168.100.27" || !options.uacChild {
		t.Fatalf("options = %#v", options)
	}
	target, err := parseTrustTarget([]string{"--target", "192.168.100.27", "--uac-child"})
	if err != nil || target != "192.168.100.27" {
		t.Fatalf("parseTrustTarget with internal marker = %q, %v", target, err)
	}
}

func TestValidTrustedHost(t *testing.T) {
	valid := []string{"192.168.100.27", "::1", "WIN-TEST", "host.example.local", "lab_01"}
	for _, value := range valid {
		if !validTrustedHost(value) {
			t.Errorf("validTrustedHost(%q) = false", value)
		}
	}
	invalid := []string{"", " 192.168.100.27", "192.168.100.27 ", "10.0.0.1,10.0.0.2", "host/name", "host;command", "*", "-host", "host-"}
	for _, value := range invalid {
		if validTrustedHost(value) {
			t.Errorf("validTrustedHost(%q) = true", value)
		}
	}
}

func TestTrustScriptDoesNotInterpolateTarget(t *testing.T) {
	script := trustScript("192.168.100.27")
	if strings.Contains(script, "192.168.100.27'") {
		t.Fatal("trust script appears to interpolate the raw target")
	}
	if !strings.Contains(script, "FromBase64String") {
		t.Fatal("trust script should decode target at runtime")
	}
}
