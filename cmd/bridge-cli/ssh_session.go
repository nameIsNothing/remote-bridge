package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"remote-bridge/internal/discovery"
	"remote-bridge/internal/sshclient"
	"remote-bridge/internal/unixssh"
)

const (
	// Legacy Windows SSH and uncommitted staging directories keep their
	// original limit. Unix approvals share the target's current policy.
	sshSessionLifetime = 30 * time.Minute
	sshSessionLockWait = 3 * time.Second
	sshSessionVersion  = 1
)

func sshSessionLifetimeForShell(shell string) time.Duration {
	if shell == "posix" {
		return unixssh.MaxLifetime
	}
	return sshSessionLifetime
}

var (
	errSSHSessionBusy     = errors.New("该目标已有一个管理端命令或交互会话正在运行，请结束后重试")
	errSSHSessionExpired  = errors.New("SSH 授权会话已过期")
	errSSHSessionRejected = errors.New("目标机拒绝 SSH 公钥配对")
	sshSessionNamePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// The record contains only public connection material. The private key stays
// in a user-only directory and is supplied to OpenSSH by path, never by value.
type sshSessionRecord struct {
	Version       int       `json:"version"`
	InstanceID    string    `json:"instance_id"`
	Address       string    `json:"address"`
	Port          int       `json:"port"`
	DiscoveryPort int       `json:"discovery_port"`
	Username      string    `json:"username"`
	Shell         string    `json:"shell,omitempty"`
	ManagerID     string    `json:"manager_id"`
	PublicKey     string    `json:"public_key"`
	HostKey       string    `json:"host_key"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type sshSessionCache struct {
	root string
	now  func() time.Time
}

type lockedSSHSession struct {
	cache     *sshSessionCache
	instance  string
	directory string
	lock      *os.File
}

type sshPairFunc func(context.Context, discovery.PairRequest) (discovery.PairResponse, error)
type sshKeygenFunc func(context.Context, string, string) (sshclient.KeyPair, error)

func defaultSSHSessionCache() (*sshSessionCache, error) {
	directory, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return newSSHSessionCache(filepath.Join(directory, "RemoteBridge", "ssh-sessions"))
}

func newSSHSessionCache(root string) (*sshSessionCache, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	if err := sshclient.ProtectDirectory(root); err != nil {
		return nil, fmt.Errorf("保护 SSH 会话缓存目录：%w", err)
	}
	return &sshSessionCache{root: root, now: time.Now}, nil
}

func sshSessionName(instance string) (string, error) {
	if strings.TrimSpace(instance) == "" || len(instance) > 128 || strings.ContainsAny(instance, "\r\n\x00") {
		return "", errors.New("目标实例 ID 无效")
	}
	digest := sha256.Sum256([]byte(instance))
	return hex.EncodeToString(digest[:]), nil
}

// A process-owned OS lock lives outside the session directory, so forgetting
// a session cannot replace a lock while another command still uses its key.
// Windows releases the sharing lock even if the manager process crashes.
func (c *sshSessionCache) open(ctx context.Context, instance string) (*lockedSSHSession, error) {
	name, err := sshSessionName(instance)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(c.root, name+".lock")
	lockCtx, cancel := context.WithTimeout(ctx, sshSessionLockWait)
	defer cancel()
	var lock *os.File
	for {
		if info, statErr := os.Lstat(lockPath); statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
			return nil, errors.New("SSH 会话锁文件异常")
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		lock, err = trySSHSessionLock(lockPath)
		if err == nil {
			break
		}
		if !errors.Is(err, errSSHSessionBusy) {
			return nil, err
		}
		select {
		case <-lockCtx.Done():
			return nil, errSSHSessionBusy
		case <-time.After(50 * time.Millisecond):
		}
	}
	session := &lockedSSHSession{cache: c, instance: instance, directory: filepath.Join(c.root, name), lock: lock}
	if err := session.ensureDirectory(); err != nil {
		lock.Close()
		return nil, err
	}
	return session, nil
}

func (s *lockedSSHSession) close() { _ = s.lock.Close() }

// Expiry during a running SSH command is enforced by its child context. That
// command also removes its now-expired local files before releasing the lock.
func (s *lockedSSHSession) finish() error {
	defer s.close()
	if _, err := s.readRecord(); errors.Is(err, errSSHSessionExpired) {
		return s.clear()
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *lockedSSHSession) ensureDirectory() error {
	if err := os.Mkdir(s.directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return sshclient.ProtectDirectory(s.directory)
}

func (s *lockedSSHSession) privatePath() string    { return filepath.Join(s.directory, "manager") }
func (s *lockedSSHSession) knownHostsPath() string { return filepath.Join(s.directory, "known_hosts") }

func readSSHSessionFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.New("SSH 会话缓存文件异常")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func (s *lockedSSHSession) readRecord() (sshSessionRecord, error) {
	data, err := readSSHSessionFile(filepath.Join(s.directory, "session.json"), 16*1024)
	if err != nil {
		return sshSessionRecord{}, err
	}
	var record sshSessionRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return sshSessionRecord{}, fmt.Errorf("SSH 会话缓存损坏，请使用 --forget-session 清除后重试：%w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return sshSessionRecord{}, errors.New("SSH 会话缓存包含额外数据")
	}
	if record.Version != sshSessionVersion || record.InstanceID != s.instance || (record.Shell != "" && record.Shell != "posix") || record.CreatedAt.IsZero() || record.ExpiresAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) || record.ExpiresAt.After(record.CreatedAt.Add(sshSessionLifetimeForShell(record.Shell))) {
		return sshSessionRecord{}, errors.New("SSH 会话缓存的实例或有效期异常，请使用 --forget-session 清除后重试")
	}
	if !s.cache.now().Before(record.ExpiresAt) {
		return sshSessionRecord{}, errSSHSessionExpired
	}
	if s.cache.now().Before(record.CreatedAt.Add(-time.Minute)) {
		return sshSessionRecord{}, errors.New("系统时间早于 SSH 授权时间，请检查时钟")
	}
	return record, nil
}

func (s *lockedSSHSession) save(record sshSessionRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temporary := filepath.Join(s.directory, "session.json.tmp")
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(s.directory, "session.json"))
}

// clear removes only fixed manager-owned files, never an arbitrary recursive
// directory tree. Symlinks are unlinked rather than traversed; unexpected
// subdirectories or files prevent directory removal and are reported.
func (s *lockedSSHSession) clear() error {
	info, err := os.Lstat(s.directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("SSH 会话目录异常，拒绝清除")
	}
	for _, name := range []string{"manager", "manager.pub", "known_hosts", "session.json", "session.json.tmp"} {
		path := filepath.Join(s.directory, name)
		if info, err := os.Lstat(path); err == nil && info.IsDir() {
			return errors.New("SSH 会话文件被目录替代，拒绝清除")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(s.directory)
}

func (c *sshSessionCache) forget(ctx context.Context, instance string) error {
	session, err := c.open(ctx, instance)
	if err != nil {
		return err
	}
	defer session.close()
	return session.clear()
}

// pruneExpired is opportunistic. It cannot promise physical key deletion
// while bridge-cli is closed; expired keys are never used or renewed.
func (c *sshSessionCache) pruneExpired() error {
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !sshSessionNamePattern.MatchString(entry.Name()) {
			continue
		}
		lockPath := filepath.Join(c.root, entry.Name()+".lock")
		if info, err := os.Lstat(lockPath); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
			continue
		}
		lock, err := trySSHSessionLock(lockPath)
		if errors.Is(err, errSSHSessionBusy) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		session := &lockedSSHSession{cache: c, directory: filepath.Join(c.root, entry.Name()), lock: lock}
		data, readErr := readSSHSessionFile(filepath.Join(session.directory, "session.json"), 16*1024)
		var record sshSessionRecord
		expired := false
		if readErr == nil && json.Unmarshal(data, &record) == nil && record.Version == sshSessionVersion {
			name, nameErr := sshSessionName(record.InstanceID)
			expired = nameErr == nil && name == entry.Name() && !record.ExpiresAt.IsZero() && !c.now().Before(record.ExpiresAt)
		} else if errors.Is(readErr, os.ErrNotExist) {
			// A crash before the pair response left no approval record. The
			// bounded staging lifetime is based on this owned directory's age.
			if info, statErr := entry.Info(); statErr == nil {
				expired = !c.now().Before(info.ModTime().Add(sshSessionLifetime))
			}
		}
		if expired {
			if err := session.clear(); err != nil {
				failures = append(failures, err)
			}
		}
		session.close()
	}
	return errors.Join(failures...)
}

func canonicalSSHKey(value string) (string, error) {
	if err := sshclient.ValidatePublicKey(value); err != nil {
		return "", err
	}
	parts := strings.Fields(value)
	return parts[0] + " " + parts[1], nil
}

func (s *lockedSSHSession) validateBinding(record sshSessionRecord, selected discovery.Announcement, endpoint *net.UDPAddr, username string) error {
	if record.InstanceID != selected.InstanceID || record.Address != endpoint.IP.String() || record.Port != selected.Port || record.DiscoveryPort != endpoint.Port || record.Shell != selected.Shell || !sameSSHUsername(record.Shell, record.Username, selected.Username) || (username != "" && !sameSSHUsername(record.Shell, record.Username, username)) {
		return errors.New("目标实例、地址、端口或账号与已批准的会话不一致；拒绝沿用旧授权，请检查目标后使用 --forget-session")
	}
	if record.ManagerID == "" || strings.ContainsAny(record.ManagerID, "\r\n\x00") {
		return errors.New("SSH 会话管理端身份异常")
	}
	if _, err := canonicalSSHKey(record.PublicKey); err != nil {
		return err
	}
	knownLine, err := sshclient.FormatKnownHost(record.Address, record.Port, record.HostKey)
	if err != nil {
		return err
	}
	publicBytes, err := readSSHSessionFile(s.privatePath()+".pub", 16*1024)
	if err != nil {
		return err
	}
	publicKey, err := canonicalSSHKey(string(publicBytes))
	if err != nil || publicKey != record.PublicKey {
		return errors.New("SSH 会话公钥文件与批准记录不一致")
	}
	knownBytes, err := readSSHSessionFile(s.knownHostsPath(), 16*1024)
	if err != nil || strings.TrimSpace(string(knownBytes)) != knownLine {
		return errors.New("SSH 会话固定的主机密钥文件异常，拒绝重写")
	}
	info, err := os.Lstat(s.privatePath())
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() == 0 || info.Size() > 64*1024 {
		return errors.New("SSH 会话私钥文件异常")
	}
	return nil
}

// authorize refreshes the UDP response using the same approved key, but never
// refreshes the approval lifetime or replaces a pinned host key. Successful
// pairing is saved before SSH starts, including when that SSH attempt fails.
func (s *lockedSSHSession) authorize(ctx context.Context, selected discovery.Announcement, endpoint *net.UDPAddr, username string, pair sshPairFunc, keygen sshKeygenFunc) (record sshSessionRecord, reused bool, returnErr error) {
	if endpoint == nil || endpoint.IP.To4() == nil || selected.InstanceID != s.instance || (selected.Shell != "" && selected.Shell != "posix") || selected.Expired(s.cache.now()) {
		return record, false, errors.New("SSH 目标实例、地址或有效期无效")
	}
	username = strings.TrimSpace(username)
	record, err := s.readRecord()
	if errors.Is(err, errSSHSessionExpired) || errors.Is(err, os.ErrNotExist) {
		if err := s.clear(); err != nil {
			return record, false, err
		}
		if err := s.ensureDirectory(); err != nil {
			return record, false, err
		}
		committed := false
		defer func() {
			if !committed {
				returnErr = errors.Join(returnErr, s.clear())
			}
		}()
		keys, err := keygen(ctx, s.directory, "manager")
		if err != nil {
			return record, false, err
		}
		managerID, err := ephemeralManagerID()
		if err != nil {
			return record, false, err
		}
		publicKey, err := canonicalSSHKey(keys.PublicKey)
		if err != nil {
			return record, false, err
		}
		created := s.cache.now()
		record = sshSessionRecord{Version: sshSessionVersion, InstanceID: selected.InstanceID, Address: endpoint.IP.String(), Port: selected.Port, DiscoveryPort: endpoint.Port, Username: selected.Username, Shell: selected.Shell, ManagerID: managerID, PublicKey: publicKey, CreatedAt: created, ExpiresAt: earlierSSHExpiry(created.Add(sshSessionLifetimeForShell(selected.Shell)), selected.ExpiresAt)}
		if username != "" && !sameSSHUsername(record.Shell, username, selected.Username) {
			return record, false, errors.New("指定的 SSH 用户名与目标公告不一致")
		}
		response, err := s.requestPair(ctx, record, pair)
		if err != nil {
			return record, false, err
		}
		if err := s.acceptResponse(&record, response, false); err != nil {
			return record, false, err
		}
		knownLine, err := sshclient.FormatKnownHost(record.Address, record.Port, record.HostKey)
		if err != nil {
			return record, false, err
		}
		if err := sshclient.WriteKnownHosts(s.knownHostsPath(), knownLine); err != nil {
			return record, false, err
		}
		if err := s.save(record); err != nil {
			return record, false, err
		}
		committed = true
		return record, false, nil
	}
	if err != nil {
		return record, false, err
	}
	if err := s.validateBinding(record, selected, endpoint, username); err != nil {
		return record, true, err
	}
	record.ExpiresAt = earlierSSHExpiry(record.ExpiresAt, selected.ExpiresAt)
	response, err := s.requestPair(ctx, record, pair)
	if err != nil {
		return record, true, err
	}
	if err := s.acceptResponse(&record, response, true); err != nil {
		return record, true, err
	}
	if err := s.save(record); err != nil {
		return record, true, err
	}
	return record, true, nil
}

func (s *lockedSSHSession) requestPair(ctx context.Context, record sshSessionRecord, pair sshPairFunc) (discovery.PairResponse, error) {
	nonce, err := discovery.NewQuery()
	if err != nil {
		return discovery.PairResponse{}, err
	}
	request := discovery.PairRequest{V: discovery.Version, Type: discovery.PairRequestType, InstanceID: record.InstanceID, RequestNonce: nonce.RequestNonce, ManagerID: record.ManagerID, ManagerHostname: localManagerHostname(), PublicKey: record.PublicKey}
	pairCtx, cancel := context.WithDeadline(ctx, record.ExpiresAt)
	defer cancel()
	if deadline, ok := pairCtx.Deadline(); ok {
		request.ConfirmUntil = deadline
	}
	response, err := pair(pairCtx, request)
	if err != nil {
		return discovery.PairResponse{}, err
	}
	if err := response.Validate(); err != nil || response.InstanceID != request.InstanceID || response.RequestNonce != request.RequestNonce {
		return discovery.PairResponse{}, errors.New("SSH 配对响应与本次请求不一致")
	}
	if !response.Accepted {
		return discovery.PairResponse{}, fmt.Errorf("%w：%s", errSSHSessionRejected, strings.TrimSpace(response.Reason))
	}
	return response, nil
}

func (s *lockedSSHSession) acceptResponse(record *sshSessionRecord, response discovery.PairResponse, reused bool) error {
	if response.Port != record.Port || response.Shell != record.Shell || !sameSSHUsername(record.Shell, response.Username, record.Username) || !s.cache.now().Before(response.ExpiresAt) {
		return errors.New("SSH 配对响应的端口、账号或有效期与目标入口不一致")
	}
	hostKey, err := canonicalSSHKey(response.HostKey)
	if err != nil {
		return err
	}
	if reused && hostKey != record.HostKey {
		return errors.New("目标 SSH 主机密钥发生变化，拒绝替换已固定的密钥；请在目标机核实后使用 --forget-session")
	}
	record.HostKey = hostKey
	record.ExpiresAt = earlierSSHExpiry(record.ExpiresAt, response.ExpiresAt)
	if !s.cache.now().Before(record.ExpiresAt) {
		return errSSHSessionExpired
	}
	return nil
}

func sameSSHUsername(shell, a, b string) bool {
	if shell == "posix" {
		return a == b
	}
	return strings.EqualFold(a, b)
}

func earlierSSHExpiry(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
