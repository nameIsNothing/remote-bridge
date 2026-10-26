// Package unixssh implements a visible, temporary Unix SSH entry using the
// system sshd, an isolated configuration and a short-lived source-bound key.
package unixssh

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxLifetime = 3 * time.Hour
const HeartbeatGrace = 5 * time.Second

var instancePattern = regexp.MustCompile(`^usb-[a-f0-9]{24}$`)
var userPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$`)

type Lease struct {
	Version   int       `json:"version"`
	Instance  string    `json:"instance_id"`
	Username  string    `json:"username"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
	Shell     string    `json:"login_shell"`
	Addresses []string  `json:"addresses"`
	Subnets   []string  `json:"subnets"`
	Port      int       `json:"port"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Active    bool      `json:"active"`
}

func (l Lease) Validate() error {
	if l.Version != 1 || !instancePattern.MatchString(l.Instance) || !userPattern.MatchString(l.Username) || l.UID <= 0 || l.GID < 0 || l.Port < 1024 || l.Port > 65535 || !path.IsAbs(l.Shell) || strings.ContainsAny(l.Shell, "\r\n\x00\" ") {
		return errors.New("invalid Unix SSH identity or endpoint")
	}
	if l.CreatedAt.IsZero() || !l.ExpiresAt.After(l.CreatedAt) || l.ExpiresAt.After(l.CreatedAt.Add(MaxLifetime)) || len(l.Addresses) == 0 || len(l.Addresses) > 16 || len(l.Subnets) == 0 || len(l.Subnets) > 16 {
		return errors.New("invalid Unix SSH lifetime or network")
	}
	for _, a := range l.Addresses {
		p := net.ParseIP(a)
		if p == nil || p.To4() == nil || !p.IsPrivate() || p.IsLoopback() {
			return errors.New("Unix SSH requires private LAN IPv4 addresses")
		}
	}
	for _, s := range l.Subnets {
		_, n, e := net.ParseCIDR(s)
		ones, bits := 0, 0
		if n != nil {
			ones, bits = n.Mask.Size()
		}
		if e != nil || bits != 32 || ones < 8 || !n.IP.IsPrivate() {
			return errors.New("invalid LAN subnet")
		}
	}
	return nil
}

func (l Lease) Check(now time.Time, uid int) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if !l.Active || uid != l.UID || !now.Before(l.ExpiresAt) || l.UpdatedAt.After(now.Add(time.Second)) || now.Sub(l.UpdatedAt) > HeartbeatGrace {
		return errors.New("Unix SSH entry has ended or its controller is unavailable")
	}
	return nil
}

func (l Lease) Allows(ip net.IP) bool {
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		return false
	}
	for _, s := range l.Subnets {
		_, n, e := net.ParseCIDR(s)
		if e == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func Config(l Lease, dir string) (string, error) {
	if err := l.Validate(); err != nil {
		return "", err
	}
	if !path.IsAbs(dir) || strings.ContainsAny(dir, " \t\r\n\x00\"'`$%") || filepath.Base(dir) != "RemoteBridge-"+l.Instance {
		return "", errors.New("invalid runtime directory")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Port %d\nAddressFamily inet\n", l.Port)
	for _, a := range l.Addresses {
		fmt.Fprintf(&b, "ListenAddress %s\n", a)
	}
	for _, s := range l.Subnets {
		fmt.Fprintf(&b, "AllowUsers %s@%s\n", l.Username, s)
	}
	fmt.Fprintf(&b, "HostKey %s/host\nAuthorizedKeysFile %s/authorized_keys\nPidFile %s/sshd.pid\nForceCommand %s/bridge-target ssh-unix-session %s\n", dir, dir, dir, dir, dir)
	b.WriteString("UsePAM yes\nStrictModes yes\nPubkeyAuthentication yes\nAuthenticationMethods publickey\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitEmptyPasswords no\nPermitRootLogin no\nHostbasedAuthentication no\nGSSAPIAuthentication no\nAuthorizedKeysCommand none\nAuthorizedPrincipalsFile none\nTrustedUserCAKeys none\nPermitUserEnvironment no\nPermitUserRC no\nDisableForwarding yes\nAllowTcpForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTunnel no\nGatewayPorts no\nPermitTTY yes\nUseDNS no\nPrintMotd no\nPrintLastLog no\nLoginGraceTime 15\nMaxAuthTries 3\nMaxStartups 3:30:6\nClientAliveInterval 5\nClientAliveCountMax 1\nLogLevel ERROR\n")
	return b.String(), nil
}

func readLease(dir string) (Lease, error) {
	var l Lease
	data, err := os.ReadFile(filepath.Join(dir, "lease.json"))
	if err != nil {
		return l, err
	}
	if len(data) > 16384 {
		return l, errors.New("oversized lease")
	}
	if err = json.Unmarshal(data, &l); err != nil {
		return l, err
	}
	return l, l.Validate()
}
func writeLease(dir string, l Lease) error {
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "lease.tmp")
	if err = os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err = os.Chmod(tmp, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, "lease.json"))
}
func parseUID(value string) (int, error) {
	n, e := strconv.Atoi(value)
	if e != nil || n <= 0 {
		return 0, errors.New("a non-root local user is required")
	}
	return n, nil
}
