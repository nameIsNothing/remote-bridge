package sshclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"remote-bridge/internal/cliutil"
)

var (
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	userPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@\\-]{0,255}$`)
)

// KeyPair is a short-lived OpenSSH key pair created for one bridge pairing.
// The private key is deliberately represented only by its temporary path;
// callers must enforce their session expiry and remove the directory when
// the approved session is forgotten or next checked after expiry.
type KeyPair struct {
	PrivatePath string
	PublicKey   string
}

// Result captures an OpenSSH process without persisting command output.
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Truncated bool
}

// MaxOutput bounds each captured stream while continuing to drain the child.
const MaxOutput = 512 * 1024

// GenerateKeyPair creates an Ed25519 key using the platform OpenSSH tooling.
// It refuses to overwrite an existing path and never supplies a passphrase or
// private key through command-line arguments. The key is temporary and must be
// protected and removed by the caller.
func GenerateKeyPair(ctx context.Context, directory, name string) (KeyPair, error) {
	directory = strings.TrimSpace(directory)
	name = strings.TrimSpace(name)
	if directory == "" || !namePattern.MatchString(name) {
		return KeyPair{}, errors.New("invalid SSH key directory or name")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return KeyPair{}, fmt.Errorf("create SSH key directory: %w", err)
	}
	if err := ProtectDirectory(directory); err != nil {
		return KeyPair{}, fmt.Errorf("protect SSH key directory: %w", err)
	}
	privatePath := filepath.Join(directory, name)
	publicPath := privatePath + ".pub"
	if _, err := os.Stat(privatePath); err == nil {
		return KeyPair{}, fmt.Errorf("refusing to overwrite SSH private key: %s", privatePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyPair{}, err
	}
	if _, err := os.Stat(publicPath); err == nil {
		return KeyPair{}, fmt.Errorf("refusing to overwrite SSH public key: %s", publicPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return KeyPair{}, err
	}
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		return KeyPair{}, errors.New("ssh-keygen not found; install the OpenSSH client on the management machine")
	}
	comment := "remote-bridge-" + name
	cmd := exec.CommandContext(ctx, keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", privatePath)
	hideCapturedProcess(cmd)
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyPair{}, fmt.Errorf("ssh-keygen failed: %w", err)
	}
	publicBytes, err := os.ReadFile(publicPath)
	if err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyPair{}, fmt.Errorf("read generated SSH public key: %w", err)
	}
	publicKey := strings.TrimSpace(string(publicBytes))
	if err := ValidatePublicKey(publicKey); err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyPair{}, fmt.Errorf("generated SSH public key is invalid: %w", err)
	}
	// A private key is not a repository/config secret, but it must not be left
	// world-readable on platforms that honor chmod. Windows callers should also
	// apply an ACL to the temporary directory when possible.
	_ = os.Chmod(privatePath, 0o600)
	_ = os.Chmod(publicPath, 0o600)
	if err := protectPrivateKey(privatePath); err != nil {
		_ = os.Remove(privatePath)
		_ = os.Remove(publicPath)
		return KeyPair{}, fmt.Errorf("protect generated SSH private key: %w", err)
	}
	return KeyPair{PrivatePath: privatePath, PublicKey: publicKey}, nil
}

// ValidatePublicKey accepts the public OpenSSH key line sent by the manager to
// the target. It rejects controls, options, paths, and oversized values so a
// pairing packet cannot turn into an authorized_keys directive.
func ValidatePublicKey(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 16*1024 || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("public key is empty, too large, or contains control characters")
	}
	parts := strings.Fields(value)
	if len(parts) < 2 || len(parts) > 3 {
		return errors.New("public key must contain key type and base64 data")
	}
	if parts[0] != "ssh-ed25519" && parts[0] != "ssh-rsa" && !strings.HasPrefix(parts[0], "ecdsa-sha2-") {
		return fmt.Errorf("unsupported public key type %q", parts[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(decoded) < 32 {
		return errors.New("public key data is not valid base64")
	}
	return nil
}

// FormatKnownHost creates one strict known_hosts line from a target's public
// host key. The target sends only public material; the manager still pins it
// to the exact discovered endpoint and port.
func FormatKnownHost(host string, port int, keyLine string) (string, error) {
	host = strings.TrimSpace(host)
	if !validHost(host) {
		return "", errors.New("invalid SSH host")
	}
	if port < 1 || port > 65535 {
		return "", errors.New("invalid SSH port")
	}
	keyLine = strings.TrimSpace(keyLine)
	if err := ValidatePublicKey(keyLine); err != nil {
		return "", fmt.Errorf("invalid SSH host key: %w", err)
	}
	parts := strings.Fields(keyLine)
	knownHost := host
	if port != 22 {
		knownHost = "[" + host + "]:" + strconv.Itoa(port)
	}
	return knownHost + " " + parts[0] + " " + parts[1], nil
}

// WriteKnownHosts writes exactly one pinned host key. It never appends an
// unverified key to the user's global known_hosts file.
func WriteKnownHosts(path, line string) error {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("invalid known_hosts path")
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n\x00") {
		return errors.New("invalid known_hosts line")
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create known_hosts directory: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		return fmt.Errorf("write known_hosts: %w", err)
	}
	return nil
}

// Run executes one non-interactive PowerShell command over SSH. The command
// is encoded as UTF-16LE PowerShell -EncodedCommand text to avoid shell
// quoting and command-injection ambiguity.
func Run(ctx context.Context, target string, port int, username, privateKey, knownHosts, command string) (Result, error) {
	return RunShell(ctx, target, port, username, privateKey, knownHosts, "", command)
}

// RunShell executes a command using the target's paired shell. Empty shell
// preserves the Windows protocol; posix sends UTF-8 script text to sh -s.
func RunShell(ctx context.Context, target string, port int, username, privateKey, knownHosts, shell, command string) (Result, error) {
	if err := validateConnection(target, port, username, privateKey, knownHosts); err != nil {
		return Result{ExitCode: -1}, err
	}
	if strings.TrimSpace(command) == "" || strings.ContainsRune(command, 0) {
		return Result{ExitCode: -1}, errors.New("remote command is required")
	}
	remote, input, err := shellCommand(shell, command, false)
	if err != nil {
		return Result{ExitCode: -1}, err
	}
	if shell == "posix" {
		seconds := 120
		if deadline, ok := ctx.Deadline(); ok {
			remaining := int((time.Until(deadline) + time.Second - 1) / time.Second)
			if remaining < 1 {
				remaining = 1
			}
			if remaining < seconds {
				seconds = remaining
			}
		}
		input = strings.NewReader(fmt.Sprintf("# remote-bridge-timeout: %d\n", seconds) + command)
	}
	return run(ctx, target, port, username, privateKey, knownHosts, remote, input, false, false)
}

func shellCommand(shell, command string, interactive bool) ([]string, io.Reader, error) {
	if shell == "posix" {
		if interactive {
			return nil, nil, nil
		}
		return []string{"sh", "-s"}, strings.NewReader(command + "\n"), nil
	}
	if shell != "" {
		return nil, nil, errors.New("unsupported SSH shell")
	}
	if interactive {
		return []string{"powershell.exe", "-NoLogo", "-NoProfile"}, nil, nil
	}
	encoded, err := cliutil.EncodePowerShell("$ErrorActionPreference = 'Stop'; " + command)
	if err != nil {
		return nil, nil, err
	}
	remote := []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded}
	return remote, strings.NewReader(""), nil
}

// RunInteractive opens a PowerShell session over SSH. It intentionally uses
// the caller's stdio instead of capturing terminal contents in audit logs.
func RunInteractive(ctx context.Context, target string, port int, username, privateKey, knownHosts string) (Result, error) {
	return RunShellInteractive(ctx, target, port, username, privateKey, knownHosts, "")
}

func RunShellInteractive(ctx context.Context, target string, port int, username, privateKey, knownHosts, shell string) (Result, error) {
	if err := validateConnection(target, port, username, privateKey, knownHosts); err != nil {
		return Result{ExitCode: -1}, err
	}
	remote, input, err := shellCommand(shell, "", true)
	if err != nil {
		return Result{ExitCode: -1}, err
	}
	return run(ctx, target, port, username, privateKey, knownHosts, remote, input, true, shell == "posix")
}

func run(ctx context.Context, target string, port int, username, privateKey, knownHosts string, remote []string, input io.Reader, interactive, requestPTY bool) (Result, error) {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return Result{ExitCode: -1}, errors.New("ssh client not found on the management machine")
	}
	args := []string{
		"-F", "none",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "IdentityAgent=none",
		"-o", "PreferredAuthentications=publickey",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "GlobalKnownHostsFile=none",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=2",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-i", privateKey,
		"-p", strconv.Itoa(port),
	}
	if requestPTY {
		args = append(args, "-tt")
	}
	args = append(args, username+"@"+target)
	args = append(args, remote...)
	cmd := exec.CommandContext(ctx, sshPath, args...)
	cmd.Stdin = input
	return runProcess(cmd, interactive)
}

func runProcess(cmd *exec.Cmd, interactive bool) (Result, error) {
	started := time.Now()
	result := Result{ExitCode: -1}
	if interactive {
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		result.Duration = time.Since(started)
		if cmd.ProcessState != nil {
			result.ExitCode = cmd.ProcessState.ExitCode()
		}
		return result, err
	}
	var stdout, stderr boundedOutput
	hideCapturedProcess(cmd)
	// Bound pipe draining if a canceled SSH helper leaves inherited handles.
	cmd.WaitDelay = 2 * time.Second
	if cmd.Stdin == nil {
		cmd.Stdin = strings.NewReader("")
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	result.Truncated = stdout.truncated || stderr.truncated
	result.Duration = time.Since(started)
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	return result, err
}

type boundedOutput struct {
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedOutput) String() string {
	value := strings.ToValidUTF8(b.buffer.String(), "\uFFFD")
	if len(value) > MaxOutput {
		b.truncated = true
		end := MaxOutput
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		value = value[:end]
	}
	return value
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	written := len(data)
	remaining := MaxOutput - b.buffer.Len()
	if len(data) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(data)
	return written, nil
}

func validateConnection(target string, port int, username, privateKey, knownHosts string) error {
	if !validHost(target) || port < 1 || port > 65535 {
		return errors.New("invalid SSH target or port")
	}
	username = strings.TrimSpace(username)
	if username == "" || !userPattern.MatchString(username) || strings.HasPrefix(username, "-") {
		return errors.New("invalid SSH username")
	}
	for _, path := range []string{privateKey, knownHosts} {
		if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("invalid SSH key or known_hosts path")
		}
	}
	return nil
}

func validHost(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 253 || strings.ContainsAny(value, " \t\r\n/\\'\"[];,$&|<>`") {
		return false
	}
	if value == "localhost" || strings.HasPrefix(value, "-") {
		return false
	}
	return true
}
