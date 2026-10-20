package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/diagnostic"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/platform/windows"
)

type desktopBackend struct{}

func (b *desktopBackend) Check(ctx context.Context) ([]guiCheck, error) {
	checks := []guiCheck{}
	addresses := localIPv4Details()
	checks = append(checks, guiCheck{Name: "局域网地址", Status: "正常", Detail: strings.Join(addressStrings(addresses), " / ")})
	if len(addresses) == 0 {
		checks[0].Status, checks[0].Detail, checks[0].Blocked = "异常", "未发现 IPv4 地址。请接入局域网后重新检查。", true
	}
	script := `$ErrorActionPreference = 'Stop'; $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $tcp = @(Get-NetTCPConnection -State Listen -LocalPort 2222 -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess }); $udp = @(Get-NetUDPEndpoint -LocalPort 37020 -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess }); $u = Get-LocalUser -Name 'RemoteBridge' -ErrorAction SilentlyContinue; $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.InterfaceAlias) + ' / ' + ([string]$_.NetworkCategory) }); [pscustomobject]@{ admin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); tcp = $tcp; udp = $udp; description = $(if ($null -eq $u) { '' } else { [string]$u.Description }); profiles = ($profiles -join ', ') } | ConvertTo-Json -Compress`
	result, err := windows.NewRunner().Run(ctx, windows.PowerShellCommand(script, true))
	var probe struct {
		Admin       bool   `json:"admin"`
		TCP         []int  `json:"tcp"`
		UDP         []int  `json:"udp"`
		Description string `json:"description"`
		Profiles    string `json:"profiles"`
	}
	if err != nil || result.ExitCode != 0 {
		return checks, fmt.Errorf("读取 Windows 配置失败：%s", strings.TrimSpace(result.Stderr))
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &probe); err != nil {
		return checks, fmt.Errorf("读取检查结果失败：%w", err)
	}
	admin := guiCheck{Name: "管理员权限", Status: "正常", Detail: "已获得配置临时账号、服务和防火墙的权限"}
	if !probe.Admin {
		admin.Status, admin.Detail = "待配置", "点击开始后使用标准 Windows UAC 授权，无需运行命令"
	}
	checks = append(checks, admin)
	status, _ := windows.DetectOpenSSH(ctx, windows.NewRunner())
	packagePath, manifestPath := discoverUSBOpenSSHPackage()
	component := guiCheck{Name: "连接组件", Status: "正常"}
	if findOpenSSHExecutable() != "" {
		component.Detail = "使用已安装的 OpenSSH；保留原有 SSH 服务设置"
	} else if packagePath != "" && manifestPath != "" {
		manifest, manifestErr := windows.ReadOpenSSHPackageManifest(manifestPath)
		if manifestErr == nil {
			manifestErr = windows.VerifyOpenSSHPackageDigest(packagePath, manifest)
		}
		if manifestErr == nil {
			manifestErr = validateUSBOpenSSHCompatibility(status, manifestPath)
		}
		if manifestErr != nil {
			component.Status, component.Detail, component.Blocked = "异常", "离线连接包校验失败："+manifestErr.Error(), true
		} else {
			component.Status, component.Detail = "待配置", "离线包已校验，确认后自动解压，无需联网安装"
		}
	} else {
		component.Status, component.Detail = "待配置", "缺少离线包，确认后通过 Windows 在线安装 OpenSSH（需要联网）"
	}
	checks = append(checks, component)
	old, stateErr := readPreviousSSHState()
	ownedOld := stateErr == nil && old != nil && (old.ExpiresAt.IsZero() || !time.Now().Before(old.ExpiresAt))
	port := guiCheck{Name: "连接端口", Status: "正常", Detail: "TCP 2222 和 UDP 37020 可用"}
	if len(probe.TCP) > 0 || len(probe.UDP) > 0 {
		port.Status, port.Detail, port.Blocked = "异常", "连接端口已被使用。请关闭旧 Remote Bridge 窗口或占用程序后重新检查。", true
		if ownedOld && allPIDsMatch(probe.TCP, old.PID) && len(probe.UDP) == 0 {
			port.Status, port.Detail, port.Blocked = "待配置", "发现上次过期入口，确认后先回收再准备新连接", false
		}
	}
	checks = append(checks, port)
	firewall := guiCheck{Name: "局域网访问", Status: "待配置", Detail: "确认后自动添加仅 LocalSubnet 可访问的 TCP / UDP 规则"}
	if probe.Profiles != "" {
		firewall.Detail += "；当前网络：" + probe.Profiles
	}
	checks = append(checks, firewall)
	resources := guiCheck{Name: "临时配置", Status: "待配置", Detail: "确认后创建临时账号和专用服务；30 分钟后结束"}
	if stateErr != nil && !probe.Admin && errors.Is(stateErr, os.ErrPermission) {
		resources.Detail = "旧配置需要管理员权限检查；确认 UAC 后会继续检查和恢复"
	} else if stateErr != nil {
		resources.Status, resources.Detail, resources.Blocked = "异常", "旧连接状态无法安全恢复："+stateErr.Error(), true
	}
	if probe.Description != "" && !strings.HasPrefix(probe.Description, sshAccountMarkerPrefix) && !strings.HasPrefix(probe.Description, legacySSHAccountMarkerPrefix) && !strings.Contains(probe.Description, "Remote Bridge") {
		resources.Status, resources.Detail, resources.Blocked = "异常", "RemoteBridge 账号已存在且不属于本工具，请先处理账号名冲突。", true
	}
	checks = append(checks, resources)
	return checks, nil
}

func allPIDsMatch(pids []int, expected int) bool {
	for _, pid := range pids {
		if pid != expected {
			return false
		}
	}
	return true
}

func (b *desktopBackend) Start(ctx context.Context, event func(guiEvent), confirm func(context.Context, string) bool) (guiSession, error) {
	if !targetIsAdministrator() {
		return nil, errors.New("未获得管理员权限，请在 UAC 中允许本次配置")
	}
	releaseLock, err := acquireTargetLock()
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			releaseLock()
		}
	}()
	event(guiEvent{Kind: "progress", Detail: "正在回收上次临时配置…"})
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.started", Step: "回收旧 SSH 配置"})
	if err := cleanupPreviousSSH(ctx); err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "configuration.step.failed", Step: "回收旧 SSH 配置", Error: err.Error()})
		return nil, err
	}
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.completed", Step: "回收旧 SSH 配置"})
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.started", Step: "回收旧 WinRM 配置"})
	if err := cleanupPreviousWinRM(ctx); err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "configuration.step.failed", Step: "回收旧 WinRM 配置", Error: err.Error()})
		return nil, err
	}
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.completed", Step: "回收旧 WinRM 配置"})
	id, err := newSSHPlanID()
	if err != nil {
		return nil, err
	}
	packagePath, manifestPath := discoverUSBOpenSSHPackage()
	source := windows.OpenSSHSourceOnline
	if findOpenSSHExecutable() != "" {
		source = windows.OpenSSHSourceExisting
	} else if packagePath != "" && manifestPath != "" {
		source = windows.OpenSSHSourceUSB
	}
	event(guiEvent{Kind: "progress", Detail: "正在准备 OpenSSH、临时账号和局域网规则…"})
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.started", Step: "准备 SSH 运行环境", Instance: id})
	prepared, err := prepareSSHRuntime(ctx, sshTargetPrepareOptions{PlanID: id, Source: source, PackagePath: packagePath, ManifestPath: manifestPath, RuntimeDir: sshRuntimeDirectory(id), TTL: sshPlanTTL, OnEvent: event, Confirm: confirm})
	if err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "configuration.step.failed", Step: "准备 SSH 运行环境", Instance: id, Error: err.Error()})
		return nil, err
	}
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.completed", Step: "准备 SSH 运行环境", Instance: id})
	prepared.releaseLock = releaseLock
	transferred = true
	rollback := func(reason error) (guiSession, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		return nil, errors.Join(reason, prepared.Cleanup(cleanupCtx))
	}
	if err := writeSSHState(defaultSSHStatePath(), prepared); err != nil {
		return rollback(err)
	}
	addresses := localIPv4Details()
	if len(addresses) == 0 {
		return rollback(errors.New("配置期间局域网地址消失，请检查网络连接"))
	}
	event(guiEvent{Kind: "progress", Detail: "SSH 已通过启动检查，正在开始局域网广播…"})
	targetDiagnostic(diagnostic.Event{Event: "discovery.started", Instance: id, Message: "SSH 启动检查通过，开始广播"})
	announcement := discovery.Announcement{V: discovery.Version, Type: discovery.AnnouncementType, InstanceID: id, Hostname: localHostname(), Addresses: addressStrings(addresses), Port: prepared.port, Transport: "ssh", Username: prepared.username, ExpiresAt: prepared.expiresAt}
	responder, err := startTargetDiscoveryResponderWithPairing(announcement, defaultSSHStatePath(), prepared.Pair)
	if err != nil {
		return rollback(fmt.Errorf("启动广播失败：%w", err))
	}
	session := &desktopSession{runtime: prepared, responder: responder, endpoint: fmt.Sprintf("%s@%s:%d", prepared.username, firstAddress(addresses), prepared.port), done: make(chan error, 1)}
	go func() {
		select {
		case failure := <-prepared.done:
			session.done <- failure
		case <-responder.done:
			if ctx.Err() == nil {
				session.done <- errors.New("局域网广播已停止，请重新检查连接端口")
			}
		case <-ctx.Done():
		}
	}()
	return session, nil
}

type desktopSession struct {
	runtime   *sshTargetRuntime
	responder *targetDiscoveryResponder
	endpoint  string
	once      sync.Once
	err       error
	done      chan error
}

func (s *desktopSession) Endpoint() string   { return s.endpoint }
func (s *desktopSession) Expiry() time.Time  { return s.runtime.expiresAt }
func (s *desktopSession) Done() <-chan error { return s.done }
func (s *desktopSession) Close(ctx context.Context) error {
	s.once.Do(func() { s.responder.Stop(); s.err = s.runtime.Cleanup(ctx) })
	return s.err
}
