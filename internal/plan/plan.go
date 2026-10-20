// Package plan defines the side-effect-free execution and rollback plans used
// by the target launcher.  A plan describes work; another package is
// responsible for applying it after explicit user confirmation.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"remote-bridge/internal/model"
)

const (
	// SchemaVersion is incremented when the JSON shape changes incompatibly.
	SchemaVersion         = 1
	DefaultWinRMHTTPPort  = 5985
	DefaultWinRMHTTPSPort = 5986
)

var (
	ErrInvalidRequest = errors.New("invalid plan request")
	ErrInvalidPlan    = errors.New("invalid plan")
)

// ActionKind identifies one declarative operation.  The executor must map
// these values to narrowly scoped platform operations and require --apply.
type ActionKind string

const (
	ActionCheckWinRM             ActionKind = "check_winrm"
	ActionCreateTemporaryAccount ActionKind = "create_temporary_account"
	ActionConfigureWinRM         ActionKind = "configure_winrm"
	ActionConfigureFirewall      ActionKind = "configure_firewall"
	ActionEmitConnectionInfo     ActionKind = "emit_connection_info"

	ActionRemoveTemporaryAccount ActionKind = "remove_temporary_account"
	ActionRemoveWinRM            ActionKind = "remove_winrm"
	ActionRemoveFirewall         ActionKind = "remove_firewall"
)

// CheckStatus is the result of a read-only precondition check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
)

// Check is attached to a plan to make preconditions visible before apply.
type Check struct {
	Name     string      `json:"name"`
	Status   CheckStatus `json:"status"`
	Required bool        `json:"required"`
	Detail   string      `json:"detail,omitempty"`
}

// Action is a safe declarative operation.  Parameters must contain only
// configuration metadata, never passwords, private keys, or complete tokens.
type Action struct {
	ID          string            `json:"id"`
	Kind        ActionKind        `json:"kind"`
	Description string            `json:"description"`
	Parameters  map[string]string `json:"parameters,omitempty"`
	Reversible  bool              `json:"reversible"`
}

// RollbackPlan is executed in response to revoke/cleanup.  Actions are
// already ordered from last-applied to first-applied.
type RollbackPlan struct {
	Actions []Action `json:"actions"`
}

// Rollback is a compatibility alias for callers that prefer the shorter name.
type Rollback = RollbackPlan

// Plan is the complete dry-run document.  Connection contains only public
// routing data; a pairing code is intentionally absent.
type Plan struct {
	Version    int                   `json:"version"`
	ID         string                `json:"id"`
	DeviceID   string                `json:"device_id"`
	CreatedAt  time.Time             `json:"created_at"`
	Mode       string                `json:"mode"`
	Checks     []Check               `json:"checks"`
	Actions    []Action              `json:"actions"`
	Rollback   RollbackPlan          `json:"rollback"`
	Connection *model.ConnectionInfo `json:"connection,omitempty"`
}

// BuildRequest is input for Build.  It has no field for a password or
// plaintext token by design.  ManagementAddress must be an IP so generated
// firewall rules do not silently broaden their scope.
type BuildRequest struct {
	PlanID            string
	DeviceID          string
	TargetAddress     string
	ManagementAddress string
	Hostname          string
	TemporaryAccount  string
	PairingID         string
	PairingExpiresAt  *time.Time
	WinRMHTTPS        bool
	WinRMPort         int
}

// Build creates a deterministic declarative plan.  It performs no network,
// process, account, service or firewall operation.  Callers should pass the
// current time explicitly so tests and previews remain reproducible.
func Build(req BuildRequest, now time.Time) (Plan, error) {
	if err := validateRequest(req); err != nil {
		return Plan{}, err
	}
	// HTTPS is the safe default for an unspecified port.  Callers that
	// intentionally use HTTP must explicitly pass port 5985.
	https := req.WinRMHTTPS
	if req.WinRMPort == 0 {
		https = true
	}
	port := req.WinRMPort
	if port == 0 {
		if https {
			port = DefaultWinRMHTTPSPort
		} else {
			port = DefaultWinRMHTTPPort
		}
	}
	if (https && port != DefaultWinRMHTTPSPort) || (!https && port != DefaultWinRMHTTPPort) {
		return Plan{}, fmt.Errorf("%w: WinRM transport must use its standard port", ErrInvalidRequest)
	}
	transport := "winrm-http"
	if https {
		transport = "winrm-https"
	}
	planID := strings.TrimSpace(req.PlanID)
	if planID == "" {
		planID = deterministicID(req, now, port, https)
	} else if !planIDPattern.MatchString(planID) {
		return Plan{}, fmt.Errorf("%w: plan id is invalid", ErrInvalidRequest)
	}
	ruleName := "RemoteBridge-" + planID
	account := strings.TrimSpace(req.TemporaryAccount)
	actions := []Action{
		{
			ID:          "check-winrm",
			Kind:        ActionCheckWinRM,
			Description: "检查 WinRM 服务、监听器和端口",
			Parameters: map[string]string{
				"transport": transport,
				"port":      fmt.Sprintf("%d", port),
			},
			Reversible: false,
		},
		{
			ID:          "create-temporary-account",
			Kind:        ActionCreateTemporaryAccount,
			Description: "创建会话范围内的临时维护账号",
			Parameters: map[string]string{
				"account": account,
				"expires": "session_end",
			},
			Reversible: true,
		},
		{
			ID:          "configure-winrm",
			Kind:        ActionConfigureWinRM,
			Description: "配置受限的 WinRM 监听器",
			Parameters: map[string]string{
				"transport": transport,
				"port":      fmt.Sprintf("%d", port),
				"source":    req.ManagementAddress,
			},
			Reversible: true,
		},
		{
			ID:          "configure-firewall",
			Kind:        ActionConfigureFirewall,
			Description: "添加仅允许管理机地址的临时防火墙规则",
			Parameters: map[string]string{
				"rule_name": ruleName,
				"source":    req.ManagementAddress,
				"port":      fmt.Sprintf("%d", port),
			},
			Reversible: true,
		},
		{
			ID:          "emit-connection-info",
			Kind:        ActionEmitConnectionInfo,
			Description: "输出管理端连接所需的非敏感信息",
			Parameters: map[string]string{
				"address":    req.TargetAddress,
				"transport":  transport,
				"pairing_id": req.PairingID,
			},
			Reversible: false,
		},
	}
	connection := &model.ConnectionInfo{
		DeviceID:  req.DeviceID,
		Hostname:  req.Hostname,
		Address:   req.TargetAddress,
		Port:      port,
		Transport: transport,
		PairingID: req.PairingID,
		ExpiresAt: req.PairingExpiresAt,
	}
	result := Plan{
		Version:   SchemaVersion,
		ID:        planID,
		DeviceID:  req.DeviceID,
		CreatedAt: now,
		Mode:      "lan-winrm",
		Checks: []Check{
			{Name: "management_address", Status: CheckPass, Required: true, Detail: "管理机地址已限定为单一 IP"},
			{Name: "winrm_port", Status: CheckPass, Required: true, Detail: fmt.Sprintf("使用端口 %d", port)},
		},
		Actions:    actions,
		Connection: connection,
	}
	result.Rollback = BuildRollback(result)
	return result, nil
}

// BuildPlan is an explicit alias for Build.
func BuildPlan(req BuildRequest, now time.Time) (Plan, error) { return Build(req, now) }

// BuildRollback returns a new reverse-order cleanup plan.  It never mutates
// the source Plan or its action maps.
func BuildRollback(p Plan) RollbackPlan {
	rollback := RollbackPlan{Actions: make([]Action, 0, len(p.Actions))}
	for i := len(p.Actions) - 1; i >= 0; i-- {
		action, ok := rollbackAction(p.Actions[i])
		if ok {
			rollback.Actions = append(rollback.Actions, action)
		}
	}
	return rollback
}

// Validate checks a plan before it is displayed or applied.  The check also
// rejects parameter names that could accidentally carry secrets.
func (p Plan) Validate() error {
	if p.Version != SchemaVersion || strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.DeviceID) == "" {
		return ErrInvalidPlan
	}
	if len(p.Actions) == 0 {
		return ErrInvalidPlan
	}
	for _, action := range append(append([]Action{}, p.Actions...), p.Rollback.Actions...) {
		if strings.TrimSpace(action.ID) == "" || action.Kind == "" || strings.TrimSpace(action.Description) == "" {
			return ErrInvalidPlan
		}
		for key, value := range action.Parameters {
			if forbiddenSecretWord(key) || forbiddenSecretWord(value) {
				return fmt.Errorf("%w: secret-looking action parameter %q", ErrInvalidPlan, key)
			}
		}
	}
	return nil
}

// MarshalJSON validates and serializes a plan for dry-run output.  It is
// explicit so callers can use it instead of exposing implementation fields.
func MarshalJSON(p Plan) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

// UnmarshalJSON decodes and validates a plan received from a file or process.
func UnmarshalJSON(data []byte) (Plan, error) {
	var p Plan
	if err := json.Unmarshal(data, &p); err != nil {
		return Plan{}, err
	}
	if err := p.Validate(); err != nil {
		return Plan{}, err
	}
	return p, nil
}

func validateRequest(req BuildRequest) error {
	if strings.TrimSpace(req.DeviceID) == "" {
		return fmt.Errorf("%w: device id is required", ErrInvalidRequest)
	}
	managementIP := net.ParseIP(strings.TrimSpace(req.ManagementAddress))
	if managementIP == nil || managementIP.IsUnspecified() || managementIP.IsMulticast() || managementIP.IsLoopback() {
		return fmt.Errorf("%w: management address must be an IP", ErrInvalidRequest)
	}
	if strings.TrimSpace(req.TargetAddress) != "" {
		targetIP := net.ParseIP(strings.TrimSpace(req.TargetAddress))
		if targetIP == nil || targetIP.IsUnspecified() || targetIP.IsMulticast() || targetIP.IsLoopback() {
			return fmt.Errorf("%w: target address must be an IP", ErrInvalidRequest)
		}
	}
	if strings.TrimSpace(req.TemporaryAccount) == "" || !accountPattern.MatchString(strings.TrimSpace(req.TemporaryAccount)) {
		return fmt.Errorf("%w: temporary account is invalid", ErrInvalidRequest)
	}
	if req.WinRMPort < 0 || req.WinRMPort > 65535 {
		return fmt.Errorf("%w: WinRM port is invalid", ErrInvalidRequest)
	}
	return nil
}

var accountPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var planIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func deterministicID(req BuildRequest, now time.Time, port int, https bool) string {
	parts := []string{
		req.DeviceID,
		req.TargetAddress,
		req.ManagementAddress,
		req.TemporaryAccount,
		req.PairingID,
		fmt.Sprintf("%t", https),
		fmt.Sprintf("%d", port),
		now.UTC().Format(time.RFC3339Nano),
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "plan_" + hex.EncodeToString(h[:8])
}

func rollbackAction(a Action) (Action, bool) {
	parameters := cloneParameters(a.Parameters)
	switch a.Kind {
	case ActionCreateTemporaryAccount:
		return Action{ID: "remove-" + a.ID, Kind: ActionRemoveTemporaryAccount, Description: "删除会话临时维护账号", Parameters: parameters, Reversible: false}, true
	case ActionConfigureWinRM:
		return Action{ID: "remove-" + a.ID, Kind: ActionRemoveWinRM, Description: "移除本次创建的 WinRM 配置", Parameters: parameters, Reversible: false}, true
	case ActionConfigureFirewall:
		return Action{ID: "remove-" + a.ID, Kind: ActionRemoveFirewall, Description: "移除本次创建的防火墙规则", Parameters: parameters, Reversible: false}, true
	default:
		return Action{}, false
	}
}

func cloneParameters(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func forbiddenSecretWord(value string) bool {
	value = strings.ToLower(strings.ReplaceAll(value, "-", "_"))
	for _, word := range []string{"password", "passwd", "secret", "private_key", "privatekey", "access_token", "refresh_token", "bearer"} {
		if strings.Contains(value, word) {
			return true
		}
	}
	return false
}

// StableParameterKeys returns sorted keys for deterministic CLI display and
// tests.  It does not expose values that are not already in the action.
func StableParameterKeys(action Action) []string {
	keys := make([]string, 0, len(action.Parameters))
	for key := range action.Parameters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
