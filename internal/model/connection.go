package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

var ErrInvalidConnectionInfo = errors.New("invalid connection info")

// Validate ensures the connection document contains only a concrete LAN
// endpoint.  It intentionally rejects wildcard and multicast addresses so a
// caller cannot turn a dry-run document into a broad firewall rule.
func (c ConnectionInfo) Validate() error {
	if strings.TrimSpace(c.DeviceID) == "" {
		return fmt.Errorf("%w: device_id is required", ErrInvalidConnectionInfo)
	}
	ip := net.ParseIP(strings.TrimSpace(c.Address))
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return fmt.Errorf("%w: address must be a concrete IP", ErrInvalidConnectionInfo)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%w: port is invalid", ErrInvalidConnectionInfo)
	}
	if strings.TrimSpace(c.Transport) == "" {
		return fmt.Errorf("%w: transport is required", ErrInvalidConnectionInfo)
	}
	return nil
}

// MarshalConnectionInfo serializes non-secret connection metadata.  The
// explicit helper makes it clear that no pairing code is part of this JSON.
func MarshalConnectionInfo(c ConnectionInfo) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(c, "", "  ")
}

// UnmarshalConnectionInfo decodes and validates connection metadata.
func UnmarshalConnectionInfo(data []byte) (ConnectionInfo, error) {
	var c ConnectionInfo
	if err := json.Unmarshal(data, &c); err != nil {
		return ConnectionInfo{}, err
	}
	if err := c.Validate(); err != nil {
		return ConnectionInfo{}, err
	}
	return c, nil
}
