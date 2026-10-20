// Package windows contains the Windows-specific pieces of the local-area
// network connector.  The package deliberately separates creating a plan
// from executing it: BuildPlan and the command builders are pure, while
// Apply, Revoke, and Rollback are the only functions that can run mutating
// PowerShell commands.
package windows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultHTTPPort is the standard WinRM HTTP listener port.
	DefaultHTTPPort = 5985
	// DefaultHTTPSPort is the standard WinRM HTTPS listener port.
	DefaultHTTPSPort = 5986
	// DefaultDiscoveryPort is the UDP port used by the short-lived LAN
	// discovery responder. It is deliberately separate from WinRM and is
	// enabled only when a caller opts into discovery for a simple LAN plan.
	// Keep this value in sync with internal/discovery.DefaultPort.
	DefaultDiscoveryPort = 37020
	// LocalSubnet is the explicit Windows Firewall address token for peers on
	// the target machine's local subnet. It is intended for the simple LAN
	// experiment mode; it is deliberately not an alias for Any.
	LocalSubnet = "LocalSubnet"
	// DefaultAccountTTL is the lifetime assigned to a temporary maintenance
	// account when a caller does not select a shorter lifetime.
	DefaultAccountTTL = 30 * time.Minute
	// DefaultPasswordEnv is the name of the environment variable read by the
	// account creation command.  The password itself is never part of a plan.
	DefaultPasswordEnv = "REMOTE_BRIDGE_TEMP_PASSWORD"
	// DefaultTemporaryUser is the stable local account name used when the
	// caller does not provide one.  The password is still rotated on every
	// apply, and the account remains owned by the plan marker in its
	// Description field.  A stable name makes the generated connection
	// instructions easy to reuse while avoiding a password being persisted.
	DefaultTemporaryUser = "RemoteBridge"
	// DefaultFirewallGroup keeps rules created by this package easy to find
	// and remove without changing unrelated firewall rules.
	DefaultFirewallGroup = "Remote Bridge"
)

var (
	// ErrUnsupported is returned by the non-Windows implementation when a
	// caller attempts to inspect or execute the local machine.
	ErrUnsupported = errors.New("windows platform operations are only supported on Windows")
	// ErrInvalidOptions means that a plan cannot be safely constructed from
	// the supplied options.
	ErrInvalidOptions = errors.New("invalid Windows bridge options")
	// ErrNoRunner means that an execution function was called without a
	// command runner.  BuildPlan never needs a runner.
	ErrNoRunner = errors.New("a command runner is required for this operation")
)

var (
	userNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)
	principalPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,127}(?:\\[A-Za-z0-9][A-Za-z0-9._@\\-]{0,127})?$`)
	sidPattern       = regexp.MustCompile(`^S-1-[0-9-]{3,80}$`)
	envNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	planIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
)

// Transport selects the WinRM listener used by a plan.
//
// HTTP is useful for a trusted, isolated LAN and is the only transport that
// can be enabled without first provisioning a certificate. HTTPS should be
// selected when the target has a certificate whose thumbprint can be checked
// by the management side.
type Transport string

const (
	TransportHTTP  Transport = "http"
	TransportHTTPS Transport = "https"
)

// PlanOptions controls inspection and plan construction.  It contains names
// and an environment-variable name, never a password.  The caller must make
// the password available in PasswordEnv only for the duration of Apply.
type PlanOptions struct {
	// ID is a caller-visible identifier.  Empty IDs are filled with a random
	// short identifier by BuildPlan.
	ID string `json:"id,omitempty"`
	// ManagementAddress is the management host's IP or CIDR. Firewall rules are
	// scoped to this value; it must not be empty. The explicit LocalSubnet token
	// is also accepted (case-insensitively) for a simple LAN experiment. It
	// maps to Windows Firewall's LocalSubnet remote-address token and never to
	// the unrestricted Any token.
	ManagementAddress string `json:"management_address"`
	// Transport defaults to HTTP for a local experiment.  HTTPS only changes
	// the listener/port selected by generated commands; certificate handling
	// remains an explicit operator responsibility.
	Transport Transport `json:"transport,omitempty"`
	// Port defaults to the standard port for Transport.  Only 5985 and 5986
	// are accepted to avoid accidentally opening another service.
	Port int `json:"port,omitempty"`
	// FirewallProfile controls the Windows firewall profile on the generated
	// allow rule. "Any" is the portable default because a laptop can mark a
	// trusted LAN as Public; the remote address remains restricted.
	FirewallProfile string `json:"firewall_profile,omitempty"`
	FirewallGroup   string `json:"firewall_group,omitempty"`
	FirewallRule    string `json:"firewall_rule,omitempty"`
	// TemporaryUser defaults to DefaultTemporaryUser when empty.  The account
	// password is rotated on every apply; callers that need parallel bridges
	// can still provide an explicit unique name.
	TemporaryUser string `json:"temporary_user,omitempty"`
	// PasswordEnv names the process environment variable consumed by the
	// account-creation PowerShell command.  Its value is never serialized.
	PasswordEnv string `json:"password_env,omitempty"`
	// AccountTTL controls the temporary account expiration.  Values must be
	// between one minute and twenty-four hours.
	AccountTTL time.Duration `json:"account_ttl,omitempty"`
	// ConfigureListener adds an idempotent listener preparation action.  It is
	// false by default because enabling WinRM can change an existing machine
	// policy; callers can opt in after reviewing the dry-run plan.
	ConfigureListener bool `json:"configure_listener,omitempty"`
	// AllowHTTP explicitly acknowledges that credentials will travel through
	// the LAN's WinRM HTTP protection.  It is recorded in the plan warning and
	// does not weaken firewall scoping.
	AllowHTTP bool `json:"allow_http,omitempty"`
	// EnableDiscovery adds a LocalSubnet-scoped UDP rule for the visible,
	// short-lived target discovery responder. It never carries credentials and
	// should normally be used only by the simple LAN experiment path.
	EnableDiscovery bool `json:"enable_discovery,omitempty"`
	// CurrentUser switches the plan from the legacy temporary-account flow to
	// the interactive Windows account that launched the target wizard. The
	// account is never created, password-reset, or removed by this plan.
	CurrentUser bool `json:"current_user,omitempty"`
	// CurrentUserPrincipal and CurrentUserSID bind a current-user plan to the
	// identity captured on the target before the manager connects. They are
	// metadata only; the password is entered on the manager and never stored.
	CurrentUserPrincipal string `json:"current_user_principal,omitempty"`
	CurrentUserSID       string `json:"current_user_sid,omitempty"`
}

// NormalizedOptions is the validated, concrete set of options embedded in a
// plan. It has no secret material and is safe to marshal in a dry-run JSON
// response.
type NormalizedOptions struct {
	ID                   string        `json:"id"`
	ManagementAddress    string        `json:"management_address"`
	Transport            Transport     `json:"transport"`
	Port                 int           `json:"port"`
	FirewallProfile      string        `json:"firewall_profile"`
	FirewallGroup        string        `json:"firewall_group"`
	FirewallRule         string        `json:"firewall_rule"`
	TemporaryUser        string        `json:"temporary_user"`
	PasswordEnv          string        `json:"password_env"`
	AccountTTL           time.Duration `json:"account_ttl"`
	ConfigureListener    bool          `json:"configure_listener"`
	AllowHTTP            bool          `json:"allow_http"`
	EnableDiscovery      bool          `json:"enable_discovery"`
	CurrentUser          bool          `json:"current_user,omitempty"`
	CurrentUserPrincipal string        `json:"current_user_principal,omitempty"`
	CurrentUserSID       string        `json:"current_user_sid,omitempty"`
}

// Command describes one invocation of PowerShell. Args intentionally contain
// no password; the account command reads PasswordEnv from the process
// environment. ReadOnly is used by Inspect to ensure a plan action cannot be
// accidentally run as a check.
type Command struct {
	Program  string   `json:"program"`
	Args     []string `json:"args"`
	ReadOnly bool     `json:"read_only"`
}

// String returns a useful, non-secret display form for logs and dry-run
// output. PowerShell script text is intentionally left intact because the
// generated scripts contain only validated names and an environment-variable
// name, never the variable's value.
func (c Command) String() string {
	parts := make([]string, 0, len(c.Args)+1)
	parts = append(parts, c.Program)
	for _, arg := range c.Args {
		if strings.IndexAny(arg, " \t\"'") >= 0 {
			parts = append(parts, "\""+strings.ReplaceAll(arg, "\"", "\\\"")+"\"")
		} else {
			parts = append(parts, arg)
		}
	}
	return strings.Join(parts, " ")
}

// Result is the captured result of one command. Output is returned to the
// caller for audit handling; this package does not write it to disk.
type Result struct {
	Stdout   string        `json:"stdout,omitempty"`
	Stderr   string        `json:"stderr,omitempty"`
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration,omitempty"`
}

// Runner is the narrow seam between the planner and the operating system.
// The Windows implementation uses powershell.exe; tests and the CLI can
// inject a recording runner without touching the system.
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// Action is a plan step. Mutating actions have ReadOnly=false and can only be
// reached through Apply, Revoke, or Rollback. Every action is written to be
// idempotent where the underlying Windows cmdlet permits it.
type Action struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Command     Command `json:"command"`
	ReadOnly    bool    `json:"read_only"`
	Idempotent  bool    `json:"idempotent"`
}

// Plan is a side-effect-free description of a complete temporary bridge
// lifecycle. BuildPlan only returns this value; no command is run until the
// caller explicitly invokes Apply, Revoke, or Rollback.
type Plan struct {
	Version     int               `json:"version"`
	ID          string            `json:"id"`
	CreatedAt   time.Time         `json:"created_at"`
	Options     NormalizedOptions `json:"options"`
	Warnings    []string          `json:"warnings,omitempty"`
	Inspect     []Action          `json:"inspect"`
	ApplySteps  []Action          `json:"apply"`
	RevokeSteps []Action          `json:"revoke"`
	Rollback    []Action          `json:"rollback"`
}

// StepResult ties a command result to the action that produced it.
type StepResult struct {
	ActionID    string `json:"action_id"`
	Description string `json:"description"`
	Result      Result `json:"result"`
	Error       string `json:"error,omitempty"`
}

// ExecutionReport is returned by Apply, Revoke, and Rollback. It is suitable
// for an audit event after the caller adds operator/session information.
type ExecutionReport struct {
	PlanID    string       `json:"plan_id"`
	Operation string       `json:"operation"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   time.Time    `json:"ended_at"`
	Steps     []StepResult `json:"steps"`
}

// InspectionReport contains read-only checks. Commands are run independently
// so one unavailable Windows feature does not hide the remaining diagnostics.
type InspectionReport struct {
	PlanID    string       `json:"plan_id,omitempty"`
	StartedAt time.Time    `json:"started_at"`
	EndedAt   time.Time    `json:"ended_at"`
	Supported bool         `json:"supported"`
	Steps     []StepResult `json:"steps"`
	Warnings  []string     `json:"warnings,omitempty"`
}

// Validate validates caller supplied options without touching the system.
func (o PlanOptions) Validate() error {
	if strings.TrimSpace(o.ManagementAddress) == "" {
		return fmt.Errorf("%w: management_address is required", ErrInvalidOptions)
	}
	if err := validateAddress(o.ManagementAddress); err != nil {
		return fmt.Errorf("%w: management_address: %v", ErrInvalidOptions, err)
	}
	transport := o.Transport
	if transport == "" {
		transport = TransportHTTP
	}
	if transport != TransportHTTP && transport != TransportHTTPS {
		return fmt.Errorf("%w: transport must be %q or %q", ErrInvalidOptions, TransportHTTP, TransportHTTPS)
	}
	port := o.Port
	if port == 0 {
		if transport == TransportHTTPS {
			port = DefaultHTTPSPort
		} else {
			port = DefaultHTTPPort
		}
	}
	if (transport == TransportHTTP && port != DefaultHTTPPort) || (transport == TransportHTTPS && port != DefaultHTTPSPort) {
		return fmt.Errorf("%w: %s transport must use port %d", ErrInvalidOptions, transport, map[Transport]int{TransportHTTP: DefaultHTTPPort, TransportHTTPS: DefaultHTTPSPort}[transport])
	}
	if o.ID != "" && !planIDPattern.MatchString(o.ID) {
		return fmt.Errorf("%w: id must contain 1-32 letters, digits, '_' or '-'", ErrInvalidOptions)
	}
	if o.TemporaryUser != "" && !userNamePattern.MatchString(o.TemporaryUser) {
		return fmt.Errorf("%w: temporary_user is not a valid local account name", ErrInvalidOptions)
	}
	if o.CurrentUser {
		if !principalPattern.MatchString(strings.TrimSpace(o.CurrentUserPrincipal)) {
			return fmt.Errorf("%w: current_user_principal is not a valid Windows principal", ErrInvalidOptions)
		}
		if strings.TrimSpace(o.CurrentUserSID) != "" && !sidPattern.MatchString(strings.TrimSpace(o.CurrentUserSID)) {
			return fmt.Errorf("%w: current_user_sid is not a valid SID", ErrInvalidOptions)
		}
	}
	if o.PasswordEnv != "" && !envNamePattern.MatchString(o.PasswordEnv) {
		return fmt.Errorf("%w: password_env is not a valid environment variable name", ErrInvalidOptions)
	}
	if o.FirewallGroup != "" && strings.ContainsAny(o.FirewallGroup, "\r\n") {
		return fmt.Errorf("%w: firewall_group contains a newline", ErrInvalidOptions)
	}
	if o.FirewallRule != "" && strings.ContainsAny(o.FirewallRule, "\r\n") {
		return fmt.Errorf("%w: firewall_rule contains a newline", ErrInvalidOptions)
	}
	if o.FirewallProfile != "" && strings.ContainsAny(o.FirewallProfile, "\r\n") {
		return fmt.Errorf("%w: firewall_profile contains a newline", ErrInvalidOptions)
	}
	if len(o.FirewallGroup) > 255 || len(o.FirewallRule) > 255 {
		return fmt.Errorf("%w: firewall_group and firewall_rule must be at most 255 characters", ErrInvalidOptions)
	}
	if o.FirewallProfile != "" {
		if err := validateFirewallProfile(o.FirewallProfile); err != nil {
			return fmt.Errorf("%w: firewall_profile: %v", ErrInvalidOptions, err)
		}
	}
	if o.AccountTTL < 0 {
		return fmt.Errorf("%w: account_ttl cannot be negative", ErrInvalidOptions)
	}
	if o.AccountTTL != 0 && (o.AccountTTL < time.Minute || o.AccountTTL > 24*time.Hour) {
		return fmt.Errorf("%w: account_ttl must be between 1m and 24h", ErrInvalidOptions)
	}
	return nil
}

func validateFirewallProfile(value string) error {
	parts := strings.Split(value, ",")
	seen := make(map[string]struct{}, len(parts))
	for _, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "" {
			return fmt.Errorf("contains an empty profile")
		}
		canonical := strings.ToLower(part)
		switch canonical {
		case "any", "domain", "private", "public":
		default:
			return fmt.Errorf("unsupported profile %q", part)
		}
		if _, exists := seen[canonical]; exists {
			return fmt.Errorf("profile %q is repeated", part)
		}
		seen[canonical] = struct{}{}
		if canonical == "any" && len(parts) != 1 {
			return fmt.Errorf("Any cannot be combined with another profile")
		}
	}
	return nil
}

func validateAddress(value string) error {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, LocalSubnet) {
		return nil
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("must be a reachable management host address")
		}
		return nil
	}
	_, network, err := net.ParseCIDR(value)
	if err != nil {
		return fmt.Errorf("must be an IP address or CIDR")
	}
	if network.IP.IsUnspecified() || network.IP.IsMulticast() || network.IP.IsLoopback() {
		return fmt.Errorf("must be a reachable management network")
	}
	return nil
}

func normalizeOptions(in PlanOptions) (NormalizedOptions, error) {
	if err := in.Validate(); err != nil {
		return NormalizedOptions{}, err
	}
	id := in.ID
	if id == "" {
		var raw [6]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return NormalizedOptions{}, fmt.Errorf("generate plan id: %w", err)
		}
		id = "rb-" + hex.EncodeToString(raw[:])
	}
	transport := in.Transport
	if transport == "" {
		transport = TransportHTTP
	}
	port := in.Port
	if port == 0 {
		if transport == TransportHTTPS {
			port = DefaultHTTPSPort
		} else {
			port = DefaultHTTPPort
		}
	}
	profile := in.FirewallProfile
	if profile == "" {
		profile = "Any"
	}
	group := in.FirewallGroup
	if group == "" {
		group = DefaultFirewallGroup
	}
	rule := in.FirewallRule
	if rule == "" {
		rule = "RemoteBridge-" + id + "-WinRM"
	}
	user := in.TemporaryUser
	if user == "" {
		user = DefaultTemporaryUser
	}
	env := in.PasswordEnv
	if env == "" {
		env = DefaultPasswordEnv
	}
	ttl := in.AccountTTL
	if ttl == 0 {
		ttl = DefaultAccountTTL
	}
	return NormalizedOptions{
		ID:                   id,
		ManagementAddress:    normalizeManagementAddress(in.ManagementAddress),
		Transport:            transport,
		Port:                 port,
		FirewallProfile:      profile,
		FirewallGroup:        group,
		FirewallRule:         rule,
		TemporaryUser:        user,
		PasswordEnv:          env,
		AccountTTL:           ttl,
		ConfigureListener:    in.ConfigureListener,
		AllowHTTP:            in.AllowHTTP,
		EnableDiscovery:      in.EnableDiscovery,
		CurrentUser:          in.CurrentUser,
		CurrentUserPrincipal: strings.TrimSpace(in.CurrentUserPrincipal),
		CurrentUserSID:       strings.TrimSpace(in.CurrentUserSID),
	}, nil
}

// isLocalSubnetAddress reports whether value names the explicit Windows
// Firewall LocalSubnet token. The comparison is case-insensitive so a CLI or
// generated connection file can use the natural spelling without creating
// multiple semantically identical plans.
func isLocalSubnetAddress(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), LocalSubnet)
}

func normalizeManagementAddress(value string) string {
	value = strings.TrimSpace(value)
	if isLocalSubnetAddress(value) {
		return LocalSubnet
	}
	return value
}
