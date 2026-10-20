package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/discovery"
	"remote-bridge/internal/platform/windows"
	"remote-bridge/internal/winrmlease"
)

// winrmTargetIdentity identifies the current process account. Preserving the
// original interactive account across a different-user UAC elevation remains
// a separate task; do not infer that protection from this structure.
type winrmTargetIdentity struct {
	Principal string `json:"principal"`
	SID       string `json:"sid"`
}

type winrmProbe struct {
	Admin    bool   `json:"admin"`
	Identity string `json:"identity"`
	SID      string `json:"sid"`
	TCP      []int  `json:"tcp"`
	UDP      []int  `json:"udp"`
	Profiles string `json:"profiles"`
}

type winrmDesktopBackend struct{}

func winrmLifetimeText() string {
	return fmt.Sprintf("%d 小时", int(winrmlease.MaxLifetime/time.Hour))
}

func currentWinRMIdentity(ctx context.Context) (winrmTargetIdentity, error) {
	script := `$ErrorActionPreference = 'Stop'; $id = [Security.Principal.WindowsIdentity]::GetCurrent(); [pscustomobject]@{ principal = [string]$id.Name; sid = [string]$id.User.Value } | ConvertTo-Json -Compress`
	result, err := windows.NewRunner().Run(ctx, windows.PowerShellCommand(script, true))
	if err != nil || result.ExitCode != 0 {
		if strings.TrimSpace(result.Stderr) != "" {
			return winrmTargetIdentity{}, fmt.Errorf("读取当前 Windows 账号失败：%s", strings.TrimSpace(result.Stderr))
		}
		if err != nil {
			return winrmTargetIdentity{}, err
		}
		return winrmTargetIdentity{}, fmt.Errorf("读取当前 Windows 账号失败，退出码 %d", result.ExitCode)
	}
	var identity winrmTargetIdentity
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &identity); err != nil {
		return winrmTargetIdentity{}, fmt.Errorf("解析当前 Windows 账号失败：%w", err)
	}
	identity.Principal, identity.SID = strings.TrimSpace(identity.Principal), strings.TrimSpace(identity.SID)
	if identity.Principal == "" || identity.SID == "" {
		return winrmTargetIdentity{}, errors.New("当前 Windows 账号信息为空")
	}
	return identity, nil
}

func (b *winrmDesktopBackend) Check(ctx context.Context) ([]guiCheck, error) {
	checks := make([]guiCheck, 0, 7)
	addresses := localIPv4Details()
	addressCheck := guiCheck{Name: "局域网地址", Status: "正常", Detail: strings.Join(addressStrings(addresses), " / ")}
	if len(addresses) == 0 {
		addressCheck.Status, addressCheck.Detail, addressCheck.Blocked = "异常", "未发现 IPv4 地址。请接入局域网后重新检查。", true
	}
	checks = append(checks, addressCheck)

	identity, identityErr := currentWinRMIdentity(ctx)
	accountCheck := guiCheck{Name: "当前账号", Status: "正常", Detail: identity.Principal + "（密码由管理端在连接时输入）"}
	if identityErr != nil {
		accountCheck.Status, accountCheck.Detail, accountCheck.Blocked = "异常", identityErr.Error(), true
	}
	checks = append(checks, accountCheck)

	probe, probeErr := readWinRMGUIProbe(ctx)
	adminCheck := guiCheck{Name: "管理员权限", Status: "正常", Detail: "已获得配置 WinRM 服务和局域网规则的权限"}
	if probeErr != nil {
		adminCheck.Status, adminCheck.Detail = "待配置", "点击开始后使用标准 Windows UAC 授权"
	} else if !probe.Admin {
		adminCheck.Status, adminCheck.Detail = "待配置", "点击开始后使用标准 Windows UAC 授权"
	}
	checks = append(checks, adminCheck)

	winrmStatus, listenerErr := windows.DetectWinRM(ctx, windows.NewRunner())
	serviceCheck := guiCheck{Name: "WinRM 服务", Status: "正常", Detail: "服务和监听器已就绪"}
	if listenerErr != nil {
		serviceCheck.Status = "待配置"
		serviceCheck.Detail = "无法在当前权限下完整读取 listener；确认 UAC 后会再次检查"
	} else if !winrmStatus.ServicePresent {
		serviceCheck.Status, serviceCheck.Detail, serviceCheck.Blocked = "异常", "系统未发现 WinRM 服务。", true
	} else if !winrmStatus.ServiceRunning || !winrmStatus.ListenerPresent {
		serviceCheck.Status, serviceCheck.Detail = "待配置", "确认后自动启动服务，并仅在缺少 listener 时准备 HTTP/5985"
	}
	checks = append(checks, serviceCheck)

	portCheck := guiCheck{Name: "连接端口", Status: "正常", Detail: "WinRM TCP 5985 和 UDP 37020 可用"}
	if probeErr == nil && (len(probe.TCP) > 0 || len(probe.UDP) > 0) {
		portCheck.Status, portCheck.Detail = "待检查", "端口已有监听；确认后会复用现有 WinRM，UDP 发现由本窗口占用"
	}
	checks = append(checks, portCheck)

	firewall := guiCheck{Name: "局域网访问", Status: "待配置", Detail: "确认后添加仅 LocalSubnet 可访问的 WinRM TCP / UDP 规则"}
	if probe.Profiles != "" {
		firewall.Detail += "；当前网络：" + probe.Profiles
	}
	checks = append(checks, firewall)

	resources := guiCheck{Name: "当前账号直连", Status: "正常", Detail: "不会创建、改密码或删除当前账号；连接有效期 " + winrmLifetimeText()}
	if identityErr != nil {
		resources.Status, resources.Detail, resources.Blocked = "异常", "无法确认当前账号，不能安全广播用户名。", true
	}
	checks = append(checks, resources)
	return checks, nil
}

func readWinRMGUIProbe(ctx context.Context) (winrmProbe, error) {
	script := `$ErrorActionPreference = 'Stop'; $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $tcp = @(Get-NetTCPConnection -State Listen -LocalPort 5985 -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess }); $udp = @(Get-NetUDPEndpoint -LocalPort 37020 -ErrorAction SilentlyContinue | ForEach-Object { [int]$_.OwningProcess }); $profiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { ([string]$_.InterfaceAlias) + ' / ' + ([string]$_.NetworkCategory) }); [pscustomobject]@{ admin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); identity = [string]$id.Name; sid = [string]$id.User.Value; tcp = $tcp; udp = $udp; profiles = ($profiles -join ', ') } | ConvertTo-Json -Compress`
	result, err := windows.NewRunner().Run(ctx, windows.PowerShellCommand(script, true))
	if err != nil || result.ExitCode != 0 {
		if err != nil {
			return winrmProbe{}, err
		}
		return winrmProbe{}, fmt.Errorf("读取 WinRM 检查结果失败，退出码 %d", result.ExitCode)
	}
	var probe winrmProbe
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &probe); err != nil {
		return winrmProbe{}, err
	}
	return probe, nil
}

func (b *winrmDesktopBackend) Start(ctx context.Context, event func(guiEvent), _ func(context.Context, string) bool) (guiSession, error) {
	if !targetIsAdministrator() {
		return nil, errors.New("未获得管理员权限，请在 UAC 中允许本次 WinRM 配置")
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

	event(guiEvent{Kind: "progress", Detail: "正在回收上次 WinRM 临时规则…"})
	if err := cleanupPreviousWinRM(ctx); err != nil {
		return nil, err
	}
	identity, err := currentWinRMIdentity(ctx)
	if err != nil {
		return nil, err
	}
	configure, warning := detectListenerPreparation()
	if warning != "" {
		event(guiEvent{Kind: "progress", Detail: "WinRM listener 检查提示：" + warning})
	}
	id, err := newSSHPlanID()
	if err != nil {
		return nil, err
	}
	plan, err := windows.BuildPlan(windows.PlanOptions{
		ID: id, ManagementAddress: simpleLANManagementAddress, Transport: windows.TransportHTTP,
		AllowHTTP: true, ConfigureListener: configure, EnableDiscovery: true,
		AccountTTL: winrmlease.MaxLifetime, CurrentUser: true,
		CurrentUserPrincipal: identity.Principal, CurrentUserSID: identity.SID,
	})
	if err != nil {
		return nil, err
	}
	event(guiEvent{Kind: "progress", Detail: "正在准备 WinRM 服务和局域网规则…"})
	runReport, applyErr := windows.Apply(ctx, windows.NewRunner(), plan)
	appendExecutionAudit("target.winrm-current.apply", plan, runReport, applyErr)
	if applyErr != nil {
		cleanupReport, cleanupErr := windows.Revoke(context.Background(), windows.NewRunner(), plan)
		appendExecutionAudit("target.winrm-current.rollback", plan, cleanupReport, cleanupErr)
		return nil, errors.Join(applyErr, cleanupErr)
	}
	lease, err := winrmlease.Prepare(ctx, windows.NewRunner(), sshProgramDataDirectory(), winrmlease.Lease{
		InstanceID: plan.ID, Username: identity.Principal, SID: identity.SID, Hostname: localHostname(),
		ControllerPID: os.Getpid(), ExpiresAt: time.Now().UTC().Add(plan.Options.AccountTTL)})
	if err != nil {
		_, cleanupErr := windows.Revoke(context.Background(), windows.NewRunner(), plan)
		return nil, errors.Join(err, cleanupErr)
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred {
			_ = lease.Close()
		}
	}()
	statePath := defaultStatePath()
	if err := writeState(statePath, plan, true); err != nil {
		_, cleanupErr := windows.Revoke(context.Background(), windows.NewRunner(), plan)
		return nil, errors.Join(err, cleanupErr)
	}
	addresses := localIPv4Details()
	if len(addresses) == 0 {
		_, cleanupErr := windows.Revoke(context.Background(), windows.NewRunner(), plan)
		return nil, errors.Join(errors.New("配置期间局域网地址消失，请检查网络连接"), cleanupErr)
	}
	announcement := discovery.Announcement{V: discovery.Version, Type: discovery.AnnouncementType,
		InstanceID: plan.ID, Hostname: localHostname(), Addresses: addressStrings(addresses),
		Port: plan.Options.Port, Transport: "winrm-http", Username: identity.Principal,
		ExpiresAt: lease.Lease.ExpiresAt}
	responder, err := startTargetDiscoveryResponder(announcement, statePath)
	if err != nil {
		_, cleanupErr := windows.Revoke(context.Background(), windows.NewRunner(), plan)
		return nil, errors.Join(fmt.Errorf("启动 WinRM 广播失败：%w", err), cleanupErr)
	}
	transferred = true
	leaseTransferred = true
	event(guiEvent{Kind: "progress", Detail: "WinRM 已配置，正在广播当前账号：" + identity.Principal})
	session := &winrmDesktopSession{plan: plan, statePath: statePath, responder: responder,
		endpoint:  fmt.Sprintf("%s@%s:%d", identity.Principal, firstAddress(addresses), plan.Options.Port),
		expiresAt: announcement.ExpiresAt, done: make(chan error, 1), releaseLock: releaseLock, lease: lease, monitorDone: make(chan struct{})}
	go session.monitorFeedback(event)
	go func() {
		if err := lease.Maintain(ctx); err != nil && ctx.Err() == nil {
			select {
			case session.done <- err:
			case <-ctx.Done():
			}
		}
	}()
	go func() {
		select {
		case <-responder.done:
			if ctx.Err() == nil {
				session.done <- errors.New("WinRM 广播已停止")
			}
		case <-ctx.Done():
		}
	}()
	return session, nil
}

type winrmDesktopSession struct {
	plan        windows.Plan
	statePath   string
	responder   *targetDiscoveryResponder
	endpoint    string
	expiresAt   time.Time
	done        chan error
	releaseLock func()
	once        sync.Once
	err         error
	lease       *winrmlease.Runtime
	monitorDone chan struct{}
}

func (s *winrmDesktopSession) Endpoint() string   { return s.endpoint }
func (s *winrmDesktopSession) Expiry() time.Time  { return s.expiresAt }
func (s *winrmDesktopSession) Done() <-chan error { return s.done }
func (s *winrmDesktopSession) Close(ctx context.Context) error {
	s.once.Do(func() {
		close(s.monitorDone)
		leaseErr := s.lease.Close()
		s.responder.Stop()
		report, revokeErr := windows.Revoke(ctx, windows.NewRunner(), s.plan)
		appendExecutionAudit("target.winrm-current.revoke", s.plan, report, revokeErr)
		s.err = errors.Join(leaseErr, revokeErr)
		if revokeErr == nil {
			_ = os.Remove(discoveryRevocationMarker(s.statePath))
		}
		if s.releaseLock != nil {
			s.releaseLock()
			s.releaseLock = nil
		}
	})
	return s.err
}

func (s *winrmDesktopSession) monitorFeedback(event func(guiEvent)) {
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	previous := ""
	for {
		select {
		case <-s.monitorDone:
			return
		case <-ticker.C:
			feedback, err := s.lease.Feedback()
			key := feedback.SessionID + ":" + feedback.State
			if err == nil && key != previous {
				previous = key
				event(guiEvent{Kind: feedback.State, Manager: feedback.SessionID, Detail: "管理端托管会话状态已更新。"})
			}
		}
	}
}

func invalidateWinRMLease(instance string) error {
	if !winrmlease.InstancePattern.MatchString(instance) {
		return nil
	}
	path := filepath.Join(sshProgramDataDirectory(), winrmlease.RootName, instance, "lease.json")
	if err := validateSSHOwnedPath(path); err != nil {
		return err
	}
	return winrmlease.RevokeFile(path, instance)
}
