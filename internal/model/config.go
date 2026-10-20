package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	DefaultConfigVersion       = 1
	DefaultConfigWinRMPort     = 5986
	DefaultConfigPairingTTL    = int64(10 * 60)
	MaxConfigPairingTTLSeconds = int64(24 * 60 * 60)
)

var ErrInvalidConfig = errors.New("invalid local config")

// DefaultConfig returns the safe portable defaults.  The listener is local by
// default; a caller must explicitly set the management endpoint for a LAN
// connection.
func DefaultConfig() LocalConfig {
	return LocalConfig{
		Version:           DefaultConfigVersion,
		ListenAddress:     "127.0.0.1",
		WinRMPort:         DefaultConfigWinRMPort,
		PairingTTLSeconds: DefaultConfigPairingTTL,
	}
}

// Validate checks configuration without touching the filesystem or network.
func (c LocalConfig) Validate() error {
	if c.Version != 0 && c.Version != DefaultConfigVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidConfig, c.Version)
	}
	if c.WinRMPort != 0 && c.WinRMPort != 5985 && c.WinRMPort != 5986 {
		return fmt.Errorf("%w: WinRM port must be 5985 or 5986", ErrInvalidConfig)
	}
	if c.PairingTTLSeconds < 0 || c.PairingTTLSeconds > MaxConfigPairingTTLSeconds {
		return fmt.Errorf("%w: pairing TTL is outside the allowed range", ErrInvalidConfig)
	}
	if address := strings.TrimSpace(c.ManagementAddress); address != "" {
		ip := net.ParseIP(address)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
			return fmt.Errorf("%w: management_address must be a concrete LAN IP", ErrInvalidConfig)
		}
	}
	if address := strings.TrimSpace(c.ListenAddress); address != "" {
		ip := net.ParseIP(address)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("%w: listen_address must be a concrete IP", ErrInvalidConfig)
		}
	}
	return nil
}

// MarshalConfig serializes non-secret local settings.
func MarshalConfig(c LocalConfig) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(c, "", "  ")
}

// UnmarshalConfig decodes and validates local settings.
func UnmarshalConfig(data []byte) (LocalConfig, error) {
	var c LocalConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return LocalConfig{}, err
	}
	if err := c.Validate(); err != nil {
		return LocalConfig{}, err
	}
	return c, nil
}
