// Package managedsession exposes one visible, short-lived manager-owned
// remote session to local CLI and MCP clients. No Windows password enters Go.
package managedsession

import (
	"errors"
	"regexp"
	"time"

	"remote-bridge/internal/unixssh"
	"remote-bridge/internal/winrmlease"
)

const MaxOutput = 512 * 1024
const MaxCommand = 64 * 1024
const MaxLifetime = winrmlease.MaxLifetime
const MaxSSHLifetime = unixssh.MaxLifetime

var IDPattern = regexp.MustCompile(`^rb-[a-f0-9]{24}$`)
var ErrClosed = errors.New("托管会话已结束或失去连接，请在管理端重新连接")
var ErrBusy = errors.New("此会话正在执行命令，请等待完成后重试")

type Info struct {
	ID         string    `json:"id"`
	InstanceID string    `json:"instance_id"`
	Target     string    `json:"target"`
	Hostname   string    `json:"hostname"`
	Username   string    `json:"username"`
	SID        string    `json:"sid,omitempty"`
	Transport  string    `json:"transport,omitempty"`
	Shell      string    `json:"shell,omitempty"`
	UID        string    `json:"uid,omitempty"`
	Port       int       `json:"port"`
	State      string    `json:"state"`
	Reason     string    `json:"reason,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Result struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}

type Request struct {
	Operation string `json:"operation"`
	Command   string `json:"command,omitempty"`
	Timeout   int    `json:"timeout_seconds,omitempty"`
}

type Response struct {
	Info   Info    `json:"session"`
	Result *Result `json:"result,omitempty"`
	Error  string  `json:"error,omitempty"`
}

type Work struct {
	Operation string `json:"operation"`
	ID        string `json:"id,omitempty"`
	Command   string `json:"command,omitempty"`
	Timeout   int    `json:"timeout_seconds,omitempty"`
}

type WorkerMessage struct {
	Operation string  `json:"operation"`
	ID        string  `json:"id,omitempty"`
	Info      *Info   `json:"session,omitempty"`
	Result    *Result `json:"result,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Record is never returned by CLI/MCP tools. Its bearer token only travels
// between the protected current-user catalog and the loopback client.
type Record struct {
	Info        Info   `json:"session"`
	Endpoint    string `json:"endpoint,omitempty"`
	Token       string `json:"token,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}
