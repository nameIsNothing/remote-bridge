package managedsession

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"remote-bridge/internal/sshclient"
)

func DefaultRoot() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "RemoteBridge", "managed-sessions"), nil
}
func PrepareDirectory(root, id string) (string, error) {
	if !IDPattern.MatchString(id) {
		return "", errors.New("会话编号无效")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if err := validateLocalPath(root); err != nil {
		return "", err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err := sshclient.ProtectDirectory(root); err != nil {
		return "", err
	}
	directory := filepath.Join(root, id)
	if err := os.Mkdir(directory, 0700); err != nil {
		return "", err
	}
	if err := sshclient.ProtectDirectory(directory); err != nil {
		return "", err
	}
	return directory, nil
}
func WriteRecord(directory string, record Record) error {
	if !IDPattern.MatchString(record.Info.ID) || filepath.Base(directory) != record.Info.ID {
		return errors.New("会话目录与编号不一致")
	}
	if err := validateLocalPath(directory); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temp := filepath.Join(directory, "session.json.tmp")
	if err := validateLocalPath(temp); err != nil {
		return err
	}
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	target := filepath.Join(directory, "session.json")
	if err := validateLocalPath(target); err != nil {
		return err
	}
	return os.Rename(temp, target)
}
func LoadRecord(root, id string) (Record, error) {
	var record Record
	if !IDPattern.MatchString(id) {
		return record, errors.New("会话编号无效")
	}
	path := filepath.Join(root, id, "session.json")
	if err := validateLocalPath(path); err != nil {
		return record, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return record, ErrClosed
	}
	if !info.Mode().IsRegular() || info.Size() > 16384 {
		return record, errors.New("会话记录异常")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16385))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, errors.New("会话记录无法读取")
	}
	if err := decoder.Decode(new(any)); err != io.EOF || record.Info.ID != id {
		return Record{}, errors.New("会话记录不匹配")
	}
	return record, nil
}

func Call(ctx context.Context, record Record, request Request) (Response, error) {
	var response Response
	if record.Info.State == "closed" {
		response.Info = record.Info
		if request.Operation == "status" || request.Operation == "close" {
			return response, nil
		}
		return response, ErrClosed
	}
	address, err := url.Parse(record.Endpoint)
	if err != nil || address.Scheme != "https" || address.Hostname() != "127.0.0.1" || address.Port() == "" || address.User != nil || address.Path != "" || address.RawQuery != "" || address.Fragment != "" {
		return response, errors.New("会话地址不合法")
	}
	if len(record.Token) != 64 || len(record.Fingerprint) != 64 {
		return response, errors.New("会话认证记录异常")
	}
	if _, err := hex.DecodeString(record.Token); err != nil {
		return response, errors.New("会话认证记录异常")
	}
	if _, err := hex.DecodeString(record.Fingerprint); err != nil {
		return response, errors.New("会话证书记录异常")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			// The per-session certificate is pinned, never accepted generically.
			if len(state.PeerCertificates) != 1 {
				return errors.New("会话证书不匹配")
			}
			hash := sha256.Sum256(state.PeerCertificates[0].Raw)
			if hex.EncodeToString(hash[:]) != record.Fingerprint {
				return errors.New("会话证书不匹配")
			}
			return nil
		}}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 130 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("会话接口不允许重定向") }}
	data, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, record.Endpoint+"/v1/call", bytes.NewReader(data))
	if err != nil {
		return response, err
	}
	req.Header.Set("Authorization", "Bearer "+record.Token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return response, fmt.Errorf("%w（本地会话接口不可用）", ErrClosed)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return response, fmt.Errorf("会话请求被拒绝（%d）", res.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(res.Body, 8*MaxOutput+16384))
	if err := decoder.Decode(&response); err != nil {
		return response, errors.New("会话响应无效")
	}
	if response.Info.ID != record.Info.ID {
		return Response{}, errors.New("会话响应编号不匹配")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
func List(ctx context.Context, root string) ([]Info, error) {
	items := []Info{}
	if err := validateLocalPath(root); err != nil {
		return items, err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return items, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !IDPattern.MatchString(entry.Name()) {
			continue
		}
		record, err := LoadRecord(root, entry.Name())
		if err != nil {
			return nil, err
		}
		if record.Info.State == "closed" || !time.Now().Before(record.Info.ExpiresAt) {
			continue
		}
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		response, err := Call(probe, record, Request{Operation: "status"})
		cancel()
		if err == nil && response.Info.State != "closed" {
			items = append(items, response.Info)
		}
	}
	return items, nil
}
func Handoff(info Info, program string) string {
	if info.Transport == "ssh" {
		return fmt.Sprintf("使用 Remote Bridge SSH 托管会话 %s（%s，账号 %s，UID %s，Shell 为 POSIX sh，有效至 %s）。先查看会话状态，再按我的请求操作。已配置 MCP 时使用 bridge_status / bridge_execute；否则用程序 %q 的 session status / session exec --id %s 子命令。不要索取密码或另建连接。每条命令使用独立 Shell，权限保持为该账号。", info.ID, info.Hostname, info.Username, info.UID, info.ExpiresAt.Local().Format("15:04:05"), program, info.ID)
	}
	return fmt.Sprintf("使用 Remote Bridge 托管会话 %s（%s，账号 %s，有效至 %s）。先查看会话状态，再按我的请求操作。已配置 MCP 时使用 bridge_status / bridge_execute；否则用程序 %q 的 session status / session exec --id %s 子命令。不要索取密码，也不要另建 WinRM 连接。", info.ID, info.Hostname, info.Username, info.ExpiresAt.Local().Format("15:04:05"), program, info.ID)
}

func checkLocalParents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || strings.ContainsRune(current, 0)) {
			return errors.New("会话路径包含链接")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
