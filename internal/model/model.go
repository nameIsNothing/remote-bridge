// Package model contains the data exchanged by the bridge components.
//
// The types in this package deliberately contain identifiers, timestamps and
// public connection metadata only.  They must not be used to persist a
// plaintext password, pairing code or private key.
package model

import "time"

// DeviceStatus describes the lifecycle state of a registered target machine.
type DeviceStatus string

const (
	DeviceStatusPending DeviceStatus = "pending"
	DeviceStatusOnline  DeviceStatus = "online"
	DeviceStatusOffline DeviceStatus = "offline"
	DeviceStatusRevoked DeviceStatus = "revoked"
	DeviceStatusExpired DeviceStatus = "expired"
)

// PairingStatus describes whether a pairing code can still be consumed.
type PairingStatus string

const (
	PairingStatusPending  PairingStatus = "pending"
	PairingStatusConsumed PairingStatus = "consumed"
	// Used is kept as a semantic alias for callers that use the term used.
	PairingStatusUsed    PairingStatus = PairingStatusConsumed
	PairingStatusRevoked PairingStatus = "revoked"
	PairingStatusExpired PairingStatus = "expired"
	PairingStatusLocked  PairingStatus = "locked"
)

// SessionStatus describes a remote command session.
type SessionStatus string

const (
	SessionStatusPending SessionStatus = "pending"
	SessionStatusActive  SessionStatus = "active"
	SessionStatusClosed  SessionStatus = "closed"
	SessionStatusFailed  SessionStatus = "failed"
	SessionStatusRevoked SessionStatus = "revoked"
)

// TunnelStatus describes a relay or local forwarding tunnel.
type TunnelStatus string

const (
	TunnelStatusPending TunnelStatus = "pending"
	TunnelStatusActive  TunnelStatus = "active"
	TunnelStatusClosed  TunnelStatus = "closed"
	TunnelStatusFailed  TunnelStatus = "failed"
)

// Device is public metadata for a target computer.  Private device keys are
// intentionally not represented here and must remain in a local keystore.
type Device struct {
	ID        string       `json:"id"`
	Name      string       `json:"name,omitempty"`
	Hostname  string       `json:"hostname,omitempty"`
	Platform  string       `json:"platform,omitempty"`
	Transport string       `json:"transport,omitempty"`
	Addresses []string     `json:"addresses,omitempty"`
	Port      int          `json:"port,omitempty"`
	Status    DeviceStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
	RevokedAt *time.Time   `json:"revoked_at,omitempty"`
}

// Pairing stores the verifier for a one-time pairing code.  CodeHash and
// CodeSalt are safe to persist; the plaintext code is returned only at
// creation time and must never be put in this structure or in an audit event.
type Pairing struct {
	ID          string        `json:"id"`
	DeviceID    string        `json:"device_id"`
	CodeHash    string        `json:"code_hash"`
	CodeSalt    string        `json:"code_salt,omitempty"`
	Status      PairingStatus `json:"status"`
	CreatedAt   time.Time     `json:"created_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
	UsedAt      *time.Time    `json:"used_at,omitempty"`
	RevokedAt   *time.Time    `json:"revoked_at,omitempty"`
	Attempts    int           `json:"attempts"`
	MaxAttempts int           `json:"max_attempts"`
}

// Session represents one authorized command session.
type Session struct {
	ID             string        `json:"id"`
	DeviceID       string        `json:"device_id"`
	PairingID      string        `json:"pairing_id,omitempty"`
	OperatorID     string        `json:"operator_id,omitempty"`
	Transport      string        `json:"transport"`
	Status         SessionStatus `json:"status"`
	StartedAt      time.Time     `json:"started_at"`
	EndedAt        *time.Time    `json:"ended_at,omitempty"`
	LastActivityAt *time.Time    `json:"last_activity_at,omitempty"`
	ExitCode       *int          `json:"exit_code,omitempty"`
}

// Tunnel represents the connection metadata for a relay/local forwarding
// path.  It does not contain private session keys or terminal contents.
type Tunnel struct {
	ID         string       `json:"id"`
	SessionID  string       `json:"session_id"`
	Transport  string       `json:"transport"`
	Status     TunnelStatus `json:"status"`
	CreatedAt  time.Time    `json:"created_at"`
	ClosedAt   *time.Time   `json:"closed_at,omitempty"`
	RemoteAddr string       `json:"remote_addr,omitempty"`
	LocalAddr  string       `json:"local_addr,omitempty"`
}

// ConnectionInfo is the non-secret data a target launcher can hand to the
// management CLI.  A pairing code is deliberately absent; callers should
// transfer that short-lived value out-of-band and keep it in memory.
type ConnectionInfo struct {
	DeviceID  string     `json:"device_id"`
	Hostname  string     `json:"hostname,omitempty"`
	Address   string     `json:"address"`
	Port      int        `json:"port"`
	Transport string     `json:"transport"`
	PairingID string     `json:"pairing_id,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// AuditEvent is an append-only record of an authorization or lifecycle
// action.  Command output is intentionally not part of the model by default.
type AuditEvent struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	DeviceID   string            `json:"device_id,omitempty"`
	SessionID  string            `json:"session_id,omitempty"`
	PairingID  string            `json:"pairing_id,omitempty"`
	OperatorID string            `json:"operator_id,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
	Success    bool              `json:"success"`
	Detail     string            `json:"detail,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// LocalConfig contains non-secret settings for the portable CLI/target
// launcher.  Secrets and private keys must be supplied at runtime or loaded
// from a protected OS keystore instead of this structure.
type LocalConfig struct {
	Version           int    `json:"version"`
	DeviceID          string `json:"device_id,omitempty"`
	ManagementAddress string `json:"management_address,omitempty"`
	ListenAddress     string `json:"listen_address,omitempty"`
	WinRMPort         int    `json:"winrm_port,omitempty"`
	PairingTTLSeconds int64  `json:"pairing_ttl_seconds,omitempty"`
	DataDir           string `json:"data_dir,omitempty"`
	AuditPath         string `json:"audit_path,omitempty"`
}

// Config is an alias retained for concise callers.
type Config = LocalConfig

// ExitCode is the stable process result used by bridge commands.
type ExitCode int

const (
	ExitOK            ExitCode = 0
	ExitUsage         ExitCode = 2
	ExitCheckFailed   ExitCode = 10
	ExitUnauthorized  ExitCode = 11
	ExitNotFound      ExitCode = 12
	ExitExpired       ExitCode = 13
	ExitRevoked       ExitCode = 14
	ExitConnection    ExitCode = 20
	ExitRemoteCommand ExitCode = 21
	ExitInternal      ExitCode = 70
)
