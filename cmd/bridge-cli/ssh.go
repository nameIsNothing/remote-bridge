package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/model"
	"remote-bridge/internal/sshclient"
)

// runSSH uses an instance-bound, short-lived approved key and pinned host key.
// Global SSH configuration is untouched.
func runSSH(args []string) int {
	fs := flag.NewFlagSet("bridge-cli ssh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target := ""
	instance := ""
	username := ""
	command := ""
	broadcast := "255.255.255.255"
	timeout := discovery.DefaultDiscoverTimeout
	pairTimeout := 120 * time.Second
	port := discovery.DefaultPort
	discover := false
	jsonOutput := false
	forgetSession := false
	fs.BoolVar(&discover, "discover", false, "通过 UDP 发现并配对目标")
	fs.StringVar(&target, "target", "", "目标 IP/主机名；省略时使用发现结果")
	fs.StringVar(&instance, "instance", "", "目标实例 ID（可选，用于多个目标时消歧）")
	fs.StringVar(&username, "username", "", "目标 SSH 用户名（通常由配对响应返回）")
	fs.StringVar(&command, "command", "", "目标 PowerShell 命令；省略进入交互会话")
	fs.StringVar(&broadcast, "broadcast", broadcast, "IPv4 广播或定向广播地址")
	fs.DurationVar(&timeout, "timeout", timeout, "UDP 发现等待时间，例如 2s")
	fs.DurationVar(&pairTimeout, "pair-timeout", pairTimeout, "目标机点击配对确认的等待时间，例如 120s")
	fs.IntVar(&port, "discovery-port", port, "UDP 发现端口")
	fs.BoolVar(&jsonOutput, "json", false, "仅输出发现元数据 JSON，不配对、不启动 SSH")
	fs.BoolVar(&forgetSession, "forget-session", false, "清除选定实例的本地 SSH 授权缓存并结束；可与 --instance 离线使用")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return fail(model.ExitUsage, errors.New("timeout 必须在 1ns 到 30s 之间"))
	}
	if pairTimeout <= 0 || pairTimeout > 5*time.Minute {
		return fail(model.ExitUsage, errors.New("pair-timeout 必须在 1ns 到 5m 之间"))
	}
	if port < 1 || port > 65535 {
		return fail(model.ExitUsage, errors.New("discovery-port 必须在 1 到 65535 之间"))
	}
	if forgetSession && (jsonOutput || strings.TrimSpace(command) != "") {
		return fail(model.ExitUsage, errors.New("forget-session 不可与 --json 或 --command 一起使用"))
	}
	if !discover && strings.TrimSpace(target) == "" && !(forgetSession && strings.TrimSpace(instance) != "") {
		return fail(model.ExitUsage, errors.New("ssh 需要 --discover 或 --target"))
	}
	if _, err := discovery.ParseBroadcastAddress(broadcast, port); err != nil {
		return fail(model.ExitUsage, err)
	}
	if forgetSession && strings.TrimSpace(instance) != "" {
		return forgetSSHSession(strings.TrimSpace(instance))
	}

	discoverCtx, discoverCancel := context.WithTimeout(context.Background(), timeout)
	defer discoverCancel()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fail(model.ExitConnection, fmt.Errorf("打开 SSH 配对 UDP 端口：%w", err))
	}
	defer conn.Close()
	discoverAddress := broadcast
	if parsedTarget := net.ParseIP(strings.TrimSpace(target)); parsedTarget != nil && parsedTarget.To4() != nil {
		discoverAddress = parsedTarget.To4().String()
	}
	announcements, err := discovery.Discover(discoverCtx, conn, discoverAddress, port)
	if err != nil {
		return fail(model.ExitConnection, fmt.Errorf("发现 SSH 目标：%w", err))
	}
	selected, endpoint, err := selectSSHAnnouncement(announcements, target, instance, port)
	if err != nil {
		return fail(model.ExitConnection, err)
	}
	if jsonOutput {
		return printJSON(map[string]any{"target": selected, "endpoint": endpoint.String()})
	}
	if forgetSession {
		return forgetSSHSession(selected.InstanceID)
	}
	cache, err := defaultSSHSessionCache()
	if err != nil {
		return fail(model.ExitInternal, fmt.Errorf("准备 SSH 授权缓存：%w", err))
	}
	if err := cache.pruneExpired(); err != nil {
		return fail(model.ExitInternal, fmt.Errorf("清理已过期 SSH 授权缓存：%w", err))
	}
	session, err := cache.open(context.Background(), selected.InstanceID)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	defer func() {
		if err := session.finish(); err != nil {
			fmt.Fprintf(os.Stderr, "SSH 授权缓存收尾未完成：%v\n", err)
		}
	}()
	pairCtx, pairCancel := context.WithTimeout(context.Background(), pairTimeout)
	defer pairCancel()
	fmt.Printf("发现目标 %s (%s)，正在核对 SSH 授权；首次连接请在目标机确认...\n", selected.Hostname, endpoint.IP)
	record, reused, err := session.authorize(pairCtx, selected, endpoint, username, func(ctx context.Context, request discovery.PairRequest) (discovery.PairResponse, error) {
		return discovery.Pair(ctx, conn, endpoint, request)
	}, sshclient.GenerateKeyPair)
	if err != nil {
		appendSSHAudit("manager.ssh.pair", endpoint.IP.String(), "", "", selected.Port, -1, err, selected.InstanceID)
		if errors.Is(err, errSSHSessionRejected) {
			return fail(model.ExitUnauthorized, err)
		}
		return fail(model.ExitConnection, fmt.Errorf("SSH 授权失败或超时：%w", err))
	}
	username = record.Username
	eventType := "manager.ssh.pair"
	if reused {
		eventType = "manager.ssh.reuse"
	}
	appendSSHAudit(eventType, endpoint.IP.String(), username, "", record.Port, 0, nil, selected.InstanceID)
	sessionCtx, sessionCancel := context.WithDeadline(context.Background(), record.ExpiresAt)
	defer sessionCancel()
	if strings.TrimSpace(command) == "" {
		fmt.Printf("授权已就绪：%s@%s:%d，有效至 %s，正在打开 PowerShell。\n", username, endpoint.IP, record.Port, record.ExpiresAt.Local().Format("15:04:05"))
		result, runErr := sshclient.RunInteractive(sessionCtx, endpoint.IP.String(), record.Port, username, session.privatePath(), session.knownHostsPath())
		appendSSHAudit("manager.ssh.shell", endpoint.IP.String(), username, "", record.Port, result.ExitCode, runErr, selected.InstanceID)
		if runErr != nil {
			return int(model.ExitConnection)
		}
		return int(model.ExitOK)
	}
	result, runErr := sshclient.Run(sessionCtx, endpoint.IP.String(), record.Port, username, session.privatePath(), session.knownHostsPath(), command)
	if strings.TrimSpace(result.Stdout) != "" {
		fmt.Print(result.Stdout)
	}
	if strings.TrimSpace(result.Stderr) != "" {
		fmt.Fprint(os.Stderr, result.Stderr)
	}
	appendSSHAudit("manager.ssh.exec", endpoint.IP.String(), username, command, record.Port, result.ExitCode, runErr, selected.InstanceID)
	if runErr != nil || result.ExitCode != 0 {
		return int(model.ExitRemoteCommand)
	}
	return int(model.ExitOK)
}

func forgetSSHSession(instance string) int {
	cache, err := defaultSSHSessionCache()
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	if err := cache.forget(context.Background(), instance); err != nil {
		return fail(model.ExitInternal, fmt.Errorf("清除 SSH 授权缓存：%w", err))
	}
	appendSSHAudit("manager.ssh.forget", "", "", "", 0, 0, nil, instance)
	fmt.Println("已清除该目标的本地 SSH 授权缓存；这不会关闭目标机的 SSH 入口。")
	return int(model.ExitOK)
}

func selectSSHAnnouncement(items []discovery.Announcement, target, instance string, discoveryPort int) (discovery.Announcement, *net.UDPAddr, error) {
	target = strings.TrimSpace(target)
	instance = strings.TrimSpace(instance)
	var matches []discovery.Announcement
	for _, item := range items {
		if item.Transport != "ssh" {
			continue
		}
		if instance != "" && item.InstanceID != instance {
			continue
		}
		if target != "" {
			matched := strings.EqualFold(item.Hostname, target)
			for _, address := range item.Addresses {
				if strings.EqualFold(strings.TrimSpace(address), target) {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		matches = append(matches, item)
	}
	if len(matches) == 0 {
		if target == "" {
			return discovery.Announcement{}, nil, errors.New("未发现 SSH 目标；请先在目标机运行 bridge-target，确认 UDP 发现端口可达")
		}
		return discovery.Announcement{}, nil, fmt.Errorf("未发现匹配 %q 的 SSH 目标", target)
	}
	if len(matches) > 1 {
		return discovery.Announcement{}, nil, errors.New("发现多个 SSH 目标；请使用 --instance 指定实例 ID")
	}
	item := matches[0]
	if len(item.Addresses) == 0 {
		return discovery.Announcement{}, nil, errors.New("SSH 目标没有可连接地址")
	}
	address := item.Addresses[0]
	if parsedTarget := net.ParseIP(target); parsedTarget != nil {
		for _, candidate := range item.Addresses {
			if parsed := net.ParseIP(candidate); parsed != nil && parsed.Equal(parsedTarget) {
				address = candidate
				break
			}
		}
	}
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return discovery.Announcement{}, nil, errors.New("SSH 目标地址不是 IPv4")
	}
	return item, &net.UDPAddr{IP: ip.To4(), Port: discoveryPort}, nil
}

func ephemeralManagerID() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "manager-" + hex.EncodeToString(raw[:]), nil
}

func localManagerHostname() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "remote-bridge-manager"
	}
	return strings.TrimSpace(host)
}

func appendSSHAudit(eventType, target, username, command string, port, exitCode int, runErr error, instances ...string) {
	metadata := map[string]string{"target": target, "port": fmt.Sprintf("%d", port), "exit_code": fmt.Sprintf("%d", exitCode)}
	if len(instances) > 0 && instances[0] != "" {
		metadata["instance_id"] = instances[0]
	}
	if username != "" {
		metadata["username"] = username
	}
	if command != "" {
		metadata["command_hash"] = audit.Digest(command)
		metadata["command_length"] = fmt.Sprintf("%d", len(command))
	}
	_ = audit.Append(audit.DefaultPath(), model.AuditEvent{Type: eventType, Success: runErr == nil && exitCode == 0, Metadata: metadata})
}

func printJSON(value any) int {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fail(model.ExitInternal, err)
	}
	return int(model.ExitOK)
}
