package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type openSSHTestRunner struct {
	result Result
	err    error
	seen   Command
}

func (r *openSSHTestRunner) Run(_ context.Context, command Command) (Result, error) {
	r.seen = command
	return r.result, r.err
}

func TestDetectOpenSSHNormalizesProbe(t *testing.T) {
	runner := &openSSHTestRunner{result: Result{ExitCode: 0, Stdout: `{"known":true,"capability_name":"OpenSSH.Server~~~~0.0.1.0","capability_checked":true,"capability_state":"Installed","service_present":true,"service_running":true,"service_start_type":"Automatic","executable_path":"C:\\Program Files\\OpenSSH\\sshd.exe","firewall_rule_present":true,"port_listening":true,"os_caption":"Microsoft Windows 11","os_version":"10.0.26100","os_build":"26100","os_architecture":"64-bit"}`}}
	status, err := DetectOpenSSH(context.Background(), runner)
	if err != nil {
		t.Fatalf("DetectOpenSSH() error = %v", err)
	}
	if !status.Known || !status.CapabilityChecked || status.CapabilityState != "Installed" || !status.ServicePresent || !status.ServiceRunning || !status.FirewallRulePresent || !status.PortListening {
		t.Fatalf("unexpected status: %#v", status)
	}
	if status.CapabilityName != OpenSSHCapabilityName || status.OSArchitecture != "64-bit" {
		t.Fatalf("normalized metadata = %#v", status)
	}
	if !runner.seen.ReadOnly || !strings.Contains(strings.Join(runner.seen.Args, " "), "Get-WindowsCapability") {
		t.Fatalf("detection command was not read-only: %#v", runner.seen)
	}
}

func TestDetectOpenSSHCapabilityFailureCanStillDescribeService(t *testing.T) {
	runner := &openSSHTestRunner{result: Result{ExitCode: 0, Stdout: `{"known":true,"capability_name":"OpenSSH.Server~~~~0.0.1.0","capability_checked":false,"capability_error":"Get-WindowsCapability is not recognized","service_present":true,"service_running":false,"executable_path":"C:\\Program Files\\OpenSSH\\sshd.exe"}`}}
	status, err := DetectOpenSSH(context.Background(), runner)
	if err != nil {
		t.Fatalf("DetectOpenSSH() error = %v", err)
	}
	if !status.Known || status.CapabilityChecked || status.CapabilityError == "" || !status.ServicePresent || status.ServiceRunning {
		t.Fatalf("unexpected fallback status: %#v", status)
	}
}

func TestDetectOpenSSHRejectsUnknownProbe(t *testing.T) {
	runner := &openSSHTestRunner{result: Result{ExitCode: 0, Stdout: `{"known":false,"error":"access denied"}`}}
	status, err := DetectOpenSSH(context.Background(), runner)
	if err == nil || !strings.Contains(err.Error(), "access denied") || status.Known {
		t.Fatalf("status = %#v, error = %v", status, err)
	}
}

func TestDetectOpenSSHPropagatesRunnerFailure(t *testing.T) {
	want := errors.New("runner failed")
	status, err := DetectOpenSSH(context.Background(), &openSSHTestRunner{err: want})
	if !errors.Is(err, want) || status.Known || status.Error == "" {
		t.Fatalf("error = %v, status = %#v", err, status)
	}
}

func TestOpenSSHInstallOptionsValidation(t *testing.T) {
	valid := OpenSSHInstallOptions{
		Source:       OpenSSHSourceUSB,
		PackagePath:  `E:\packages\OpenSSH-Win64.zip`,
		ManifestPath: `E:\packages\manifest.json`,
		InstallRoot:  DefaultOpenSSHInstallRoot,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid options: %v", err)
	}
	invalid := []OpenSSHInstallOptions{
		{Source: OpenSSHSource("powershell")},
		{Source: OpenSSHSourceUSB, ManifestPath: `E:\packages\manifest.json`},
		{Source: OpenSSHSourceUSB, PackagePath: `E:\packages\install.ps1`, ManifestPath: `E:\packages\manifest.json`},
		{Source: OpenSSHSourceAuto, PackagePath: `E:\packages\OpenSSH-Win64.zip`},
		{Source: OpenSSHSourceAuto, ManifestPath: `E:\packages\manifest.json`},
		{Source: OpenSSHSourceUSB, PackagePath: `E:\packages\OpenSSH.zip`, ManifestPath: `E:\packages\manifest:evil.json`},
		{Source: OpenSSHSourceUSB, PackagePath: `E:\packages\OpenSSH.zip`, ManifestPath: `E:\packages\manifest.json`, InstallRoot: `relative\OpenSSH`},
		{Source: OpenSSHSourceOnline, Port: 2222},
	}
	for _, options := range invalid {
		if err := options.Validate(); err == nil {
			t.Fatalf("options unexpectedly valid: %#v", options)
		}
	}
}

func TestOpenSSHArchitectureAcceptsLocalizedWindowsValues(t *testing.T) {
	tests := map[string]string{
		"64 位":   "amd64",
		"64-bit": "amd64",
		"32 位":   "386",
		"ARM64":  "arm64",
	}
	for input, want := range tests {
		got, err := OpenSSHArchitecture(input)
		if err != nil || got != want {
			t.Fatalf("OpenSSHArchitecture(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestValidateOpenSSHPackagePathRejectsCodeAndTraversal(t *testing.T) {
	for _, path := range []string{
		`E:\packages\install.ps1`,
		`E:\packages\OpenSSH.exe`,
		`E:\packages\..\OpenSSH.zip`,
		`E:\packages\OpenSSH.zip;whoami`,
		`E:\packages\OpenSSH.zip'`,
	} {
		if err := ValidateOpenSSHPackagePath(path); err == nil {
			t.Fatalf("unsafe package path accepted: %q", path)
		}
	}
	if err := ValidateOpenSSHPackagePath(`E:\packages\OpenSSH-Win64.zip`); err != nil {
		t.Fatalf("valid package path rejected: %v", err)
	}
}

func TestOpenSSHPackageManifestValidation(t *testing.T) {
	manifest := OpenSSHPackageManifest{
		Version:      "9.8.2.0",
		Architecture: "amd64",
		Archive:      "OpenSSH-Win64.zip",
		SHA256:       strings.Repeat("a", 64),
		MinBuild:     17763,
	}
	if err := manifest.Validate(); err != nil {
		t.Fatalf("valid manifest: %v", err)
	}
	inside, err := OpenSSHBuildInRange("26100", manifest)
	if err != nil || !inside {
		t.Fatalf("build range = %v, %v", inside, err)
	}
	outside, err := OpenSSHBuildInRange("16299", manifest)
	if err != nil || outside {
		t.Fatalf("old build range = %v, %v", outside, err)
	}
	for _, bad := range []OpenSSHPackageManifest{
		{Version: "9.8", Architecture: "amd64", Archive: "OpenSSH.zip", SHA256: "bad"},
		{Version: "9.8", Architecture: "mips", Archive: "OpenSSH.zip", SHA256: strings.Repeat("a", 64)},
		{Version: "9.8", Architecture: "amd64", Archive: "install.ps1", SHA256: strings.Repeat("a", 64)},
		{Version: "9.8", Architecture: "amd64", Archive: "OpenSSH.zip", SHA256: strings.Repeat("a", 64), MinBuild: 30000, MaxBuild: 20000},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("bad manifest accepted: %#v", bad)
		}
	}
}

func TestVerifyOpenSSHPackageDigest(t *testing.T) {
	directory := t.TempDir()
	archive := filepath.Join(directory, "OpenSSH-Win64.zip")
	data := []byte("test archive bytes")
	if err := os.WriteFile(archive, data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	manifest := OpenSSHPackageManifest{
		Version:      "9.8.2.0",
		Architecture: "amd64",
		Archive:      "OpenSSH-Win64.zip",
		SHA256:       hex.EncodeToString(digest[:]),
	}
	if err := VerifyOpenSSHPackageDigest(archive, manifest); err != nil {
		t.Fatalf("valid package rejected: %v", err)
	}
	manifest.SHA256 = strings.Repeat("0", 64)
	if err := VerifyOpenSSHPackageDigest(archive, manifest); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

func TestResolveOpenSSHSource(t *testing.T) {
	packageOptions := OpenSSHInstallOptions{Source: OpenSSHSourceAuto, PackagePath: `E:\packages\OpenSSH-Win64.zip`, ManifestPath: `E:\packages\manifest.json`}
	usbStatus := OpenSSHStatus{Known: true, CapabilityChecked: false}
	decision, err := ResolveOpenSSHSource(usbStatus, packageOptions)
	if err != nil || decision.Source != OpenSSHSourceUSB || decision.PackagePath == "" {
		t.Fatalf("USB decision = %#v, error = %v", decision, err)
	}
	onlineStatus := OpenSSHStatus{Known: true, CapabilityChecked: true, CapabilityState: "NotPresent"}
	decision, err = ResolveOpenSSHSource(onlineStatus, OpenSSHInstallOptions{Source: OpenSSHSourceAuto})
	if err != nil || decision.Source != OpenSSHSourceOnline {
		t.Fatalf("online decision = %#v, error = %v", decision, err)
	}
	existingStatus := OpenSSHStatus{Known: true, ServicePresent: true, ServiceRunning: true}
	decision, err = ResolveOpenSSHSource(existingStatus, OpenSSHInstallOptions{Source: OpenSSHSourceAuto})
	if err != nil || decision.Source != OpenSSHSourceExisting {
		t.Fatalf("existing decision = %#v, error = %v", decision, err)
	}
	if _, err := ResolveOpenSSHSource(existingStatus, OpenSSHInstallOptions{Source: OpenSSHSourceUSB, PackagePath: `E:\packages\OpenSSH.zip`, ManifestPath: `E:\packages\manifest.json`}); err == nil {
		t.Fatal("USB policy replaced an existing sshd service")
	}
	if _, err := ResolveOpenSSHSource(OpenSSHStatus{Known: true}, OpenSSHInstallOptions{Source: OpenSSHSourceAuto}); err == nil {
		t.Fatal("auto policy accepted unknown capability with no package")
	}
}

func TestOpenSSHArchitectureNormalization(t *testing.T) {
	for input, want := range map[string]string{"AMD64": "amd64", "64-bit": "amd64", "x86": "386", "32-bit": "386", "ARM64": "arm64"} {
		got, err := OpenSSHArchitecture(input)
		if err != nil || got != want {
			t.Fatalf("architecture %q = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := OpenSSHArchitecture("mips64"); err == nil {
		t.Fatal("unknown architecture accepted")
	}
}
