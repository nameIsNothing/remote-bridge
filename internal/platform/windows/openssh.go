package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// OpenSSHCapabilityName is the Windows Features-on-Demand identifier used by
// Windows 10 (build 1809 and later), Windows 11, and supported Windows Server
// releases.  Keeping the value in one place prevents the detection and
// installer paths from drifting apart.
const OpenSSHCapabilityName = "OpenSSH.Server~~~~0.0.1.0"

// DefaultSSHPort is the port used by the Windows OpenSSH server unless an
// operator has deliberately configured a different listener outside this
// package.  The first LAN implementation only accepts the standard port.
const DefaultSSHPort = 22

// DefaultOpenSSHServiceName is the service name installed by Win32-OpenSSH
// and by the Windows OpenSSH capability.
const DefaultOpenSSHServiceName = "sshd"

// DefaultOpenSSHInstallRoot is the standard location used by the Win32-
// OpenSSH distribution.  It is a display/default value only; this package
// never executes a path supplied by a plan without validating it first.
const DefaultOpenSSHInstallRoot = `C:\Program Files\OpenSSH`

// OpenSSHSource selects where the OpenSSH server should come from.  Auto is
// intentionally conservative: an already installed service wins, then a
// validated removable-media package, and finally the Windows capability
// source.  The caller still has to explicitly apply the resulting plan.
type OpenSSHSource string

const (
	OpenSSHSourceAuto     OpenSSHSource = "auto"
	OpenSSHSourceExisting OpenSSHSource = "existing"
	OpenSSHSourceUSB      OpenSSHSource = "usb"
	OpenSSHSourceOnline   OpenSSHSource = "online"
)

var (
	// OpenSSH package archives are deliberately limited to ZIP files.  A
	// package is unpacked and checked by a later, platform-specific action;
	// accepting a .ps1/.exe here would turn a portable plan into an arbitrary
	// code execution primitive.
	openSSHArchiveName = regexp.MustCompile(`(?i)^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip$`)
	openSSHVersionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$`)
	openSSHSHA256      = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)
)

// OpenSSHInstallOptions contains non-secret policy and package metadata for
// an OpenSSH preparation.  PackagePath and ManifestPath are deliberately not
// JSON fields: they identify a transient U-disk input and must not become a
// portable state-file dependency.  The state can retain a package digest and
// ownership marker after apply instead.
type OpenSSHInstallOptions struct {
	Source       OpenSSHSource `json:"source,omitempty"`
	PackagePath  string        `json:"-"`
	ManifestPath string        `json:"-"`
	InstallRoot  string        `json:"install_root,omitempty"`
	Port         int           `json:"port,omitempty"`
}

// OpenSSHPackageManifest is the metadata that accompanies a removable-media
// Win32-OpenSSH archive.  It contains no credentials or executable commands.
// A release process should sign this metadata and verify the archive digest
// before invoking any package installation script.
type OpenSSHPackageManifest struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Archive      string `json:"archive"`
	SHA256       string `json:"sha256"`
	MinBuild     int    `json:"min_build,omitempty"`
	MaxBuild     int    `json:"max_build,omitempty"`
}

// OpenSSHSourceDecision records the result of the side-effect-free source
// selection.  PackagePath is runtime-only and intentionally omitted from
// JSON/state serialization.
type OpenSSHSourceDecision struct {
	Source         OpenSSHSource `json:"source"`
	Reason         string        `json:"reason"`
	CapabilityName string        `json:"capability_name"`
	PackagePath    string        `json:"-"`
}

// OpenSSHStatus is a read-only snapshot of the local OpenSSH installation.
// CapabilityError can be non-empty on systems without Features-on-Demand even
// when service detection succeeded; callers may then choose a validated USB
// package instead of treating the machine as unsupported.
type OpenSSHStatus struct {
	Known               bool   `json:"known"`
	CapabilityName      string `json:"capability_name"`
	CapabilityChecked   bool   `json:"capability_checked"`
	CapabilityState     string `json:"capability_state,omitempty"`
	CapabilityError     string `json:"capability_error,omitempty"`
	ServicePresent      bool   `json:"service_present"`
	ServiceRunning      bool   `json:"service_running"`
	ServiceStartType    string `json:"service_start_type,omitempty"`
	ExecutablePath      string `json:"executable_path,omitempty"`
	FirewallRulePresent bool   `json:"firewall_rule_present"`
	PortListening       bool   `json:"port_listening"`
	OSCaption           string `json:"os_caption,omitempty"`
	OSVersion           string `json:"os_version,omitempty"`
	OSBuild             string `json:"os_build,omitempty"`
	OSArchitecture      string `json:"os_architecture,omitempty"`
	Error               string `json:"error,omitempty"`
}

type openSSHProbeResult struct {
	Known               bool   `json:"known"`
	CapabilityName      string `json:"capability_name"`
	CapabilityChecked   bool   `json:"capability_checked"`
	CapabilityState     string `json:"capability_state"`
	CapabilityError     string `json:"capability_error"`
	ServicePresent      bool   `json:"service_present"`
	ServiceRunning      bool   `json:"service_running"`
	ServiceStartType    string `json:"service_start_type"`
	ExecutablePath      string `json:"executable_path"`
	FirewallRulePresent bool   `json:"firewall_rule_present"`
	PortListening       bool   `json:"port_listening"`
	OSCaption           string `json:"os_caption"`
	OSVersion           string `json:"os_version"`
	OSBuild             string `json:"os_build"`
	OSArchitecture      string `json:"os_architecture"`
	Error               string `json:"error"`
}

// DetectOpenSSH performs a read-only PowerShell probe.  It does not install,
// start, stop, or configure OpenSSH.  A missing Get-WindowsCapability or
// Get-NetTCPConnection command is represented in CapabilityError/Error while
// service and executable checks remain useful for Win32-OpenSSH installations.
func DetectOpenSSH(ctx context.Context, runner Runner) (OpenSSHStatus, error) {
	status := OpenSSHStatus{CapabilityName: OpenSSHCapabilityName}
	if runner == nil {
		return status, ErrNoRunner
	}
	result, runErr := runner.Run(ctx, psCommand(openSSHDetectScript(), true))
	if runErr != nil {
		status.Error = runErr.Error()
		return status, runErr
	}
	if result.ExitCode != 0 {
		err := fmt.Errorf("OpenSSH detection exited with code %d", result.ExitCode)
		if strings.TrimSpace(result.Stderr) != "" {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(result.Stderr))
		}
		status.Error = err.Error()
		return status, err
	}
	var probe openSSHProbeResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &probe); err != nil {
		err = fmt.Errorf("parse OpenSSH detection result: %w", err)
		status.Error = err.Error()
		return status, err
	}
	status = normalizeOpenSSHStatus(probe)
	if !status.Known {
		message := strings.TrimSpace(status.Error)
		if message == "" {
			message = "OpenSSH state could not be inspected"
		}
		status.Error = message
		return status, errors.New(message)
	}
	return status, nil
}

func normalizeOpenSSHStatus(probe openSSHProbeResult) OpenSSHStatus {
	name := strings.TrimSpace(probe.CapabilityName)
	if name == "" {
		name = OpenSSHCapabilityName
	}
	return OpenSSHStatus{
		Known:               probe.Known,
		CapabilityName:      name,
		CapabilityChecked:   probe.CapabilityChecked,
		CapabilityState:     strings.TrimSpace(probe.CapabilityState),
		CapabilityError:     strings.TrimSpace(probe.CapabilityError),
		ServicePresent:      probe.ServicePresent,
		ServiceRunning:      probe.ServiceRunning,
		ServiceStartType:    strings.TrimSpace(probe.ServiceStartType),
		ExecutablePath:      strings.TrimSpace(probe.ExecutablePath),
		FirewallRulePresent: probe.FirewallRulePresent,
		PortListening:       probe.PortListening,
		OSCaption:           strings.TrimSpace(probe.OSCaption),
		OSVersion:           strings.TrimSpace(probe.OSVersion),
		OSBuild:             strings.TrimSpace(probe.OSBuild),
		OSArchitecture:      strings.TrimSpace(probe.OSArchitecture),
		Error:               strings.TrimSpace(probe.Error),
	}
}

// OpenSSHInstallOptions.Validate validates policy and package identifiers
// without touching the filesystem or executing a package.  PackagePath is
// required for the usb source and, when present for auto, must still be a
// regular-looking archive path.  The caller should separately verify its
// manifest digest and Authenticode signature before apply.
func (o OpenSSHInstallOptions) Validate() error {
	source := o.Source
	if source == "" {
		source = OpenSSHSourceAuto
	}
	switch source {
	case OpenSSHSourceAuto, OpenSSHSourceExisting, OpenSSHSourceUSB, OpenSSHSourceOnline:
	default:
		return fmt.Errorf("%w: unsupported OpenSSH source %q", ErrInvalidOptions, source)
	}
	port := o.Port
	if port == 0 {
		port = DefaultSSHPort
	}
	if port != DefaultSSHPort {
		return fmt.Errorf("%w: OpenSSH must use port %d", ErrInvalidOptions, DefaultSSHPort)
	}
	if source == OpenSSHSourceUSB && strings.TrimSpace(o.PackagePath) == "" {
		return fmt.Errorf("%w: USB OpenSSH source requires package_path", ErrInvalidOptions)
	}
	if source == OpenSSHSourceUSB && strings.TrimSpace(o.ManifestPath) == "" {
		return fmt.Errorf("%w: USB OpenSSH source requires manifest_path", ErrInvalidOptions)
	}
	// Auto switches to the USB source whenever either removable-media path is
	// present.  Do not defer a missing counterpart until extraction: a plan
	// should be rejected before the operator confirms system changes.
	if source == OpenSSHSourceAuto {
		packagePresent := strings.TrimSpace(o.PackagePath) != ""
		manifestPresent := strings.TrimSpace(o.ManifestPath) != ""
		if packagePresent != manifestPresent {
			return fmt.Errorf("%w: auto USB source requires package_path and manifest_path together", ErrInvalidOptions)
		}
	}
	if strings.TrimSpace(o.PackagePath) != "" {
		if err := ValidateOpenSSHPackagePath(o.PackagePath); err != nil {
			return fmt.Errorf("%w: package_path: %v", ErrInvalidOptions, err)
		}
	}
	if strings.TrimSpace(o.ManifestPath) != "" {
		if err := validateOpenSSHManifestPath(o.ManifestPath); err != nil {
			return fmt.Errorf("%w: manifest_path: %v", ErrInvalidOptions, err)
		}
	}
	if strings.TrimSpace(o.InstallRoot) != "" {
		if err := validateOpenSSHInstallRoot(o.InstallRoot); err != nil {
			return fmt.Errorf("%w: install_root: %v", ErrInvalidOptions, err)
		}
	}
	return nil
}

// ValidateOpenSSHPackagePath checks the shape of a removable-media archive
// path.  It intentionally does not read the archive; callers should perform a
// digest/signature check using a trusted manifest before installation.
func ValidateOpenSSHPackagePath(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("package path is empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return errors.New("package path contains NUL")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("package path contains control characters")
		}
	}
	if strings.ContainsAny(value, `*?;|&<>"'`) {
		return errors.New("package path contains unsupported shell characters")
	}
	if hasParentPathComponent(value) {
		return errors.New("package path cannot contain parent-directory components")
	}
	base := openSSHPathLeaf(value)
	if !openSSHArchiveName.MatchString(base) {
		return errors.New("package path must name a .zip archive")
	}
	return nil
}

func validateOpenSSHManifestPath(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("manifest path is empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return errors.New("manifest path contains NUL")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("manifest path contains control characters")
		}
	}
	if strings.ContainsAny(value, `*?;|&<>"'`) || hasParentPathComponent(value) || hasUnsafeWindowsColon(value) {
		return errors.New("manifest path contains unsupported characters or parent-directory components")
	}
	base := openSSHPathLeaf(value)
	if !strings.EqualFold(filepath.Ext(base), ".json") {
		return errors.New("manifest path must name a .json file")
	}
	return nil
}

func validateOpenSSHInstallRoot(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("install root is empty")
	}
	if strings.IndexByte(value, 0) >= 0 || strings.ContainsAny(value, `*?;|&<>"'`) || hasParentPathComponent(value) || hasUnsafeWindowsColon(value) {
		return errors.New("install root contains unsupported characters or parent-directory components")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("install root contains control characters")
		}
	}
	// Only an absolute Windows path is accepted for installation.  This keeps
	// a package from silently extracting into the process working directory.
	if !isWindowsAbsolutePath(value) {
		return errors.New("install root must be an absolute Windows path")
	}
	return nil
}

func isWindowsAbsolutePath(value string) bool {
	if len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return true
	}
	return strings.HasPrefix(value, `\\`)
}

// hasUnsafeWindowsColon rejects NTFS alternate-data-stream syntax and
// drive-relative paths.  A single colon is permitted only as the second
// character of an absolute drive path such as C:\\foo or C:/foo.
func hasUnsafeWindowsColon(value string) bool {
	for index, r := range value {
		if r != ':' {
			continue
		}
		if index == 1 && len(value) >= 3 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && (value[2] == '\\' || value[2] == '/') {
			continue
		}
		return true
	}
	return false
}

func hasParentPathComponent(value string) bool {
	value = strings.ReplaceAll(value, `\`, "/")
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

// openSSHPathLeaf treats both Windows and POSIX separators as separators so
// manifest validation remains deterministic when a Windows path is inspected
// by a cross-compiled test or tooling process on another host.
func openSSHPathLeaf(value string) string {
	value = strings.TrimRight(value, `/\`)
	if index := strings.LastIndexAny(value, `/\`); index >= 0 {
		return value[index+1:]
	}
	return value
}

// ValidateOpenSSHPackageManifest validates metadata before a caller compares
// it with the selected OS and hashes the archive.  It deliberately does not
// trust the manifest as a signature; release tooling should authenticate it
// separately.
func (m OpenSSHPackageManifest) Validate() error {
	if !openSSHVersionName.MatchString(strings.TrimSpace(m.Version)) {
		return fmt.Errorf("%w: invalid OpenSSH package version", ErrInvalidOptions)
	}
	architecture := strings.ToLower(strings.TrimSpace(m.Architecture))
	switch architecture {
	case "amd64", "x86_64", "x64", "386", "x86", "arm64":
	default:
		return fmt.Errorf("%w: unsupported OpenSSH package architecture %q", ErrInvalidOptions, m.Architecture)
	}
	if err := ValidateOpenSSHPackagePath(m.Archive); err != nil {
		return fmt.Errorf("%w: archive: %v", ErrInvalidOptions, err)
	}
	if openSSHPathLeaf(m.Archive) != strings.TrimSpace(m.Archive) {
		return fmt.Errorf("%w: archive must be a file name, not a path", ErrInvalidOptions)
	}
	if !openSSHSHA256.MatchString(strings.TrimSpace(m.SHA256)) {
		return fmt.Errorf("%w: sha256 must be 64 hexadecimal characters", ErrInvalidOptions)
	}
	if m.MinBuild < 0 || m.MaxBuild < 0 || (m.MinBuild > 0 && m.MaxBuild > 0 && m.MinBuild > m.MaxBuild) {
		return fmt.Errorf("%w: invalid Windows build range", ErrInvalidOptions)
	}
	return nil
}

// ResolveOpenSSHSource selects an installation source without touching the
// system.  It intentionally does not assume that a capability query failure
// means "not installed": an existing Win32-OpenSSH service can still be used.
func ResolveOpenSSHSource(status OpenSSHStatus, options OpenSSHInstallOptions) (OpenSSHSourceDecision, error) {
	if err := options.Validate(); err != nil {
		return OpenSSHSourceDecision{}, err
	}
	source := options.Source
	if source == "" {
		source = OpenSSHSourceAuto
	}
	// A removable package can be independently verified even when the local
	// capability probe is unavailable.  Every decision that relies on existing
	// service/capability state, however, must reject an unknown snapshot rather
	// than treating unknown as absent or present.
	if !status.Known && source != OpenSSHSourceUSB && strings.TrimSpace(options.PackagePath) == "" {
		return OpenSSHSourceDecision{}, fmt.Errorf("%w: OpenSSH state is unknown", ErrInvalidOptions)
	}
	decision := OpenSSHSourceDecision{Source: source, CapabilityName: OpenSSHCapabilityName, PackagePath: strings.TrimSpace(options.PackagePath)}
	if status.ServicePresent {
		if source == OpenSSHSourceUSB || source == OpenSSHSourceOnline {
			return OpenSSHSourceDecision{}, fmt.Errorf("%w: sshd already exists; refusing to replace an existing service", ErrInvalidOptions)
		}
		decision.Source = OpenSSHSourceExisting
		decision.Reason = "existing sshd service"
		return decision, nil
	}
	switch source {
	case OpenSSHSourceExisting:
		return OpenSSHSourceDecision{}, fmt.Errorf("%w: OpenSSH source existing requested but sshd is absent", ErrInvalidOptions)
	case OpenSSHSourceUSB:
		decision.Reason = "validated removable-media archive"
		return decision, nil
	case OpenSSHSourceOnline:
		if !status.CapabilityChecked {
			return OpenSSHSourceDecision{}, fmt.Errorf("%w: Windows OpenSSH capability state is unknown; inspect before online install", ErrInvalidOptions)
		}
		decision.Reason = "Windows Features-on-Demand capability"
		return decision, nil
	case OpenSSHSourceAuto:
		if strings.TrimSpace(options.PackagePath) != "" {
			decision.Source = OpenSSHSourceUSB
			decision.Reason = "validated removable-media archive"
			return decision, nil
		}
		if !status.CapabilityChecked {
			return OpenSSHSourceDecision{}, fmt.Errorf("%w: no existing sshd, USB package, or known Windows capability source", ErrInvalidOptions)
		}
		decision.Source = OpenSSHSourceOnline
		decision.Reason = "Windows Features-on-Demand capability"
		return decision, nil
	default:
		return OpenSSHSourceDecision{}, fmt.Errorf("%w: unsupported OpenSSH source %q", ErrInvalidOptions, source)
	}
}

// OpenSSHArchitecture normalizes common Windows architecture spellings for
// package-manifest matching.  It accepts the OS architecture text returned by
// Win32_OperatingSystem and rejects unknown values instead of guessing.
func OpenSSHArchitecture(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	switch value {
	case "amd64", "x64", "x86_64", "x8664", "64-bit", "64bit", "64位":
		return "amd64", nil
	case "x86", "i386", "i686", "32-bit", "32bit", "32位", "386":
		return "386", nil
	case "arm64", "aarch64", "arm64位":
		return "arm64", nil
	default:
		return "", fmt.Errorf("%w: unsupported Windows architecture %q", ErrInvalidOptions, value)
	}
}

// OpenSSHBuildInRange reports whether a Windows build is covered by a
// manifest.  A zero bound means no bound.  The helper accepts the textual
// build field emitted by Win32_OperatingSystem and avoids locale parsing.
func OpenSSHBuildInRange(build string, manifest OpenSSHPackageManifest) (bool, error) {
	if err := manifest.Validate(); err != nil {
		return false, err
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(build))
	if err != nil || parsed < 0 {
		return false, fmt.Errorf("%w: invalid Windows build %q", ErrInvalidOptions, build)
	}
	if manifest.MinBuild > 0 && parsed < manifest.MinBuild {
		return false, nil
	}
	if manifest.MaxBuild > 0 && parsed > manifest.MaxBuild {
		return false, nil
	}
	return true, nil
}

// ReadOpenSSHPackageManifest reads and validates a metadata file.  It is kept
// separate from source selection so tests and callers can authenticate the
// file/digest with their own trust policy before any installation action.
func ReadOpenSSHPackageManifest(path string) (OpenSSHPackageManifest, error) {
	if err := validateOpenSSHManifestPath(path); err != nil {
		return OpenSSHPackageManifest{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return OpenSSHPackageManifest{}, err
	}
	var manifest OpenSSHPackageManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return OpenSSHPackageManifest{}, fmt.Errorf("parse OpenSSH package manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return OpenSSHPackageManifest{}, err
	}
	return manifest, nil
}

// VerifyOpenSSHPackageDigest verifies a removable-media archive against a
// validated manifest without executing or extracting it.  The archive name is
// matched as well as the digest so a caller cannot accidentally pair a valid
// hash with a different file selected from the U-disk.
func VerifyOpenSSHPackageDigest(path string, manifest OpenSSHPackageManifest) error {
	if err := ValidateOpenSSHPackagePath(path); err != nil {
		return err
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if !strings.EqualFold(openSSHPathLeaf(path), strings.TrimSpace(manifest.Archive)) {
		return fmt.Errorf("%w: package filename does not match manifest archive", ErrInvalidOptions)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: package path is not a regular file", ErrInvalidOptions)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash OpenSSH package: %w", err)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, strings.TrimSpace(manifest.SHA256)) {
		return fmt.Errorf("%w: OpenSSH package SHA-256 mismatch", ErrInvalidOptions)
	}
	return nil
}

// openSSHDetectScript emits a stable, compact JSON object.  Each optional
// Windows probe is isolated in try/catch so a missing capability cmdlet does
// not hide an already installed Win32-OpenSSH service.
func openSSHDetectScript() string {
	return `$ErrorActionPreference = 'Stop'; $capabilityName = 'OpenSSH.Server~~~~0.0.1.0'; $known = $true; $capabilityChecked = $false; $capabilityState = ''; $capabilityError = ''; try { $cap = @(Get-WindowsCapability -Online -Name $capabilityName -ErrorAction Stop); $capabilityChecked = $true; if ($cap.Count -gt 0) { $capabilityState = [string]$cap[0].State } else { $capabilityState = 'NotFound' } } catch { $capabilityError = $_.Exception.Message }; $servicePresent = $false; $serviceRunning = $false; $serviceStartType = ''; try { $service = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue; if ($null -ne $service) { $servicePresent = $true; $serviceRunning = ([string]$service.Status -eq 'Running'); $serviceStartType = [string]$service.StartType } } catch { if ([string]::IsNullOrWhiteSpace($capabilityError)) { $capabilityError = $_.Exception.Message } }; $executablePath = ''; try { $cmd = Get-Command 'sshd.exe' -ErrorAction SilentlyContinue; if ($null -ne $cmd) { $executablePath = [string]$cmd.Source } } catch { }; $firewallPresent = $false; try { $rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue; $firewallPresent = $null -ne $rule } catch { }; $portListening = $false; try { $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction Stop); $portListening = $listeners.Count -gt 0 } catch { }; $osCaption = ''; $osVersion = ''; $osBuild = ''; $osArchitecture = ''; try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $osCaption = [string]$os.Caption; $osVersion = [string]$os.Version; $osBuild = [string]$os.BuildNumber; $osArchitecture = [string]$os.OSArchitecture } catch { if ([string]::IsNullOrWhiteSpace($capabilityError)) { $capabilityError = $_.Exception.Message } }; [pscustomobject]@{ known = $known; capability_name = $capabilityName; capability_checked = $capabilityChecked; capability_state = $capabilityState; capability_error = $capabilityError; service_present = $servicePresent; service_running = $serviceRunning; service_start_type = $serviceStartType; executable_path = $executablePath; firewall_rule_present = $firewallPresent; port_listening = $portListening; os_caption = $osCaption; os_version = $osVersion; os_build = $osBuild; os_architecture = $osArchitecture; error = '' } | ConvertTo-Json -Compress`
}
