package main

import (
	"bufio"
	"context"
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

	"remote-bridge/internal/diagnostic"
	"remote-bridge/internal/platform/windows"
)

func sshServiceName(id string) string { return "RemoteBridge-" + id }
func psSSHString(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

const sshRuntimeLogName = "sshd-startup.log"

func runSSHSystemScript(ctx context.Context, action, script string) (windows.Result, error) {
	return runSSHScript(ctx, windows.NewRunner(), action, script)
}

func runSSHScript(ctx context.Context, runner windows.Runner, action, script string) (windows.Result, error) {
	targetDiagnostic(diagnostic.Event{Event: "configuration.step.started", Step: action})
	result, err := runner.Run(ctx, windows.PowerShellCommand(script, false))
	entry := diagnostic.Event{Event: "configuration.step.completed", Step: action, ExitCode: &result.ExitCode, DurationMS: result.Duration.Milliseconds()}
	if err != nil || result.ExitCode != 0 {
		detail := safeTargetDiagnosticText(strings.TrimSpace(result.Stderr))
		if detail == "" && err != nil {
			detail = safeTargetDiagnosticText(err.Error())
		}
		entry.Level, entry.Event, entry.Error = "error", "configuration.step.failed", detail
		targetDiagnostic(entry)
		return result, fmt.Errorf("%s失败（exit %d）：%s", action, result.ExitCode, detail)
	}
	targetDiagnostic(entry)
	return result, nil
}

// OpenSSH needs the service logon identity to create Windows user tokens.
// This visible, manual-start service is owned by the current plan; neither
// the administrator's sshd service nor the global sshd_config is changed.
func startSSHService(ctx context.Context, r *sshTargetRuntime) error {
	r.serviceName = sshServiceName(r.id)
	program, err := os.Executable()
	if err != nil {
		return err
	}
	source, err := os.Open(program)
	if err != nil {
		return err
	}
	defer source.Close()
	serviceProgram := filepath.Join(r.root, "bridge-service.exe")
	destination, err := os.OpenFile(serviceProgram, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := protectSSHRuntimeFiles(ctx, r); err != nil {
		return err
	}
	if err := writeSSHState(r.statePath, r); err != nil {
		return err
	}
	controllerStart, err := sshControllerStartMillis(os.Getpid())
	if err != nil {
		return err
	}
	binary := fmt.Sprintf(`"%s" ssh-service --instance %s --root "%s" --sshd "%s" --controller %d --controller-start %d --expires %s`, serviceProgram, r.id, r.root, r.sshdPath, os.Getpid(), controllerStart, r.expiresAt.UTC().Format(time.RFC3339))
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $name = %s; if ($null -ne (Get-Service -Name $name -ErrorAction SilentlyContinue)) { throw 'service name already exists; refusing to replace it' }; New-Service -Name $name -DisplayName ('Remote Bridge 临时连接 ' + %s) -Description %s -BinaryPathName %s -StartupType Manual | Out-Null; try { Start-Service -Name $name -ErrorAction Stop } catch { $reason = $_.Exception.Message; $status = Get-CimInstance Win32_Service -Filter ("Name = '" + $name + "'") -ErrorAction SilentlyContinue; if ($null -ne $status) { $reason += ('; state=' + $status.State + '; win32_exit=' + $status.ExitCode + '; service_exit=' + $status.ServiceSpecificExitCode) }; throw $reason }; $s = Get-CimInstance Win32_Service -Filter ("Name = '" + $name + "'"); if ([string]$s.State -ne 'Running' -or [int]$s.ProcessId -le 0) { throw 'SSH service did not become ready' }; [pscustomobject]@{ pid = [int]$s.ProcessId } | ConvertTo-Json -Compress`, psSSHString(r.serviceName), psSSHString(r.id), psSSHString("Remote Bridge temporary SSH plan "+r.id), psSSHString(binary))
	result, err := runSSHSystemScript(ctx, "启动本次 SSH 服务", script)
	if err != nil {
		return err
	}
	var status struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &status); err != nil || status.PID <= 0 {
		return fmt.Errorf("无法确认 SSH 服务进程")
	}
	r.pid = status.PID
	return nil
}

func stopSSHService(ctx context.Context, name, id, root string) error {
	if name != sshServiceName(id) || !validSSHPlanID(id) || !samePath(root, sshRuntimeDirectory(id)) {
		return fmt.Errorf("SSH 服务所有权无效，未执行清理")
	}
	// Normal SCM shutdown lets the host close its child job and report STOPPED.
	// A stalled host is stopped through an immutable, image-checked handle.
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$name = %s
$s = Get-CimInstance Win32_Service -Filter ("Name = '" + $name + "'")
if ($null -ne $s) {
    $expectedBinaryPrefix = '"' + %s + '" '
    if ([string]$s.Description -ne %s -or -not ([string]$s.PathName).StartsWith($expectedBinaryPrefix, [StringComparison]::OrdinalIgnoreCase) -or [string]$s.StartMode -ne 'Manual') { throw 'SSH service ownership mismatch' }
    $running = Get-Service -Name $name -ErrorAction Stop
    if ([string]$running.Status -ne 'Stopped') {
        try { $running.Stop(); $running.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(20)) }
        catch {
            $current = Get-CimInstance Win32_Service -Filter ("Name = '" + $name + "'")
            if ($null -eq $current -or [int]$current.ProcessId -le 0) { throw }
            [pscustomobject]@{ stalled_pid = [int]$current.ProcessId } | ConvertTo-Json -Compress
            exit 0
        }
    }
    & (Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe') delete $name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'failed to remove temporary SSH service' }
}
[pscustomobject]@{ stalled_pid = 0 } | ConvertTo-Json -Compress`, psSSHString(name), psSSHString(filepath.Join(root, "bridge-service.exe")), psSSHString("Remote Bridge temporary SSH plan "+id))
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSSHSystemScript(ctx, "清理本次 SSH 服务", script)
		if err != nil {
			return err
		}
		var status struct {
			StalledPID uint32 `json:"stalled_pid"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &status); err != nil {
			return fmt.Errorf("读取 SSH 服务停止结果：%w", err)
		}
		if status.StalledPID == 0 {
			return nil
		}
		if attempt > 0 {
			return fmt.Errorf("本次 SSH 服务在结束宿主后仍未停止")
		}
		if err := stopRecoveryProcess(ctx, status.StalledPID, id, root, filepath.Join(root, "bridge-service.exe"), nativeSSHRecoveryOperations{}); err != nil {
			return err
		}
	}
	return errors.New("本次 SSH 服务停止失败")
}

func protectSSHRuntimeRoot(ctx context.Context, root string) error {
	// Protect the parent before writing host keys or extracting executables:
	// ordinary local users cannot replace code later launched as SYSTEM.
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $root = %s; $base = Split-Path -Parent $root; $parent = Split-Path -Parent $base; foreach ($directory in @($parent, $base, $root)) { $item = Get-Item -LiteralPath $directory -Force; if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'runtime directory is a reparse point' }; $acl = New-Object Security.AccessControl.DirectorySecurity; $acl.SetAccessRuleProtection($true, $false); foreach ($sid in @('S-1-5-18','S-1-5-32-544')) { $identity = New-Object Security.Principal.SecurityIdentifier($sid); $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'); $acl.AddAccessRule($rule) }; if ($directory -ne $root) { $users = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545'); $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))) }; $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))); Set-Acl -LiteralPath $directory -AclObject $acl }`, psSSHString(root))
	_, err := runSSHSystemScript(ctx, "保护临时目录", script)
	return err
}

func protectSSHRuntimeFiles(ctx context.Context, r *sshTargetRuntime) error {
	ownerScript := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $owner = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'); Get-ChildItem -LiteralPath %s -Force -Recurse | ForEach-Object { if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'runtime files contain a reparse point' }; $acl = Get-Acl -LiteralPath $_.FullName; $acl.SetOwner($owner); Set-Acl -LiteralPath $_.FullName -AclObject $acl }`, psSSHString(r.root))
	if _, err := runSSHSystemScript(ctx, "保护本次连接文件所有权", ownerScript); err != nil {
		return err
	}
	hostKeyPath := filepath.Join(r.root, "ssh_host_ed25519_key")
	if err := validateSSHOwnedPath(hostKeyPath); err != nil {
		return err
	}
	// ssh-keygen leaves an explicit creator ACE after an owner-only change.
	// sshd running as SYSTEM rejects this grant to a different account.
	if _, err := runSSHSystemScript(ctx, "收紧 SSH 主机私钥权限", buildSSHHostKeyProtectionScript(hostKeyPath)); err != nil {
		return err
	}
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $user = (Get-LocalUser -Name %s -ErrorAction Stop).SID; $root = %s; $acl = Get-Acl -LiteralPath $root; $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user, 'Traverse', 'None', 'None', 'Allow'))); Set-Acl -LiteralPath $root -AclObject $acl; $keys = %s; $keyAcl = Get-Acl -LiteralPath $keys; $keyAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user, 'Read', 'Allow'))); Set-Acl -LiteralPath $keys -AclObject $keyAcl; $portable = Join-Path $root 'openssh'; if (Test-Path -LiteralPath $portable) { $binaryAcl = Get-Acl -LiteralPath $portable; $binaryAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($user, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))); Set-Acl -LiteralPath $portable -AclObject $binaryAcl }`, psSSHString(r.username), psSSHString(r.root), psSSHString(r.keyPath))
	_, err := runSSHSystemScript(ctx, "保护 SSH 配置与公钥", script)
	return err
}

func buildSSHHostKeyProtectionScript(path string) string {
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$path = %s
$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'SSH host key must be a regular owned file' }
$allowed = @('S-1-5-18', 'S-1-5-32-544')
$owner = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($owner)
foreach ($sid in $allowed) {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
$verified = Get-Acl -LiteralPath $path -ErrorAction Stop
$rules = @($verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (-not $verified.AreAccessRulesProtected -or $verified.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544' -or $rules.Count -ne 2) { throw 'SSH host key permission verification failed' }
foreach ($rule in $rules) {
    if ($rule.IdentityReference.Value -notin $allowed -or $rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl) { throw 'SSH host key has an unexpected access rule' }
}
[pscustomobject]@{ owner = 'S-1-5-32-544'; access = 'SYSTEM,Administrators'; verified = $true } | ConvertTo-Json -Compress`, psSSHString(path))
	return script
}

func waitSSHReady(ctx context.Context, r *sshTargetRuntime) error {
	readyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	for readyCtx.Err() == nil {
		if !sshProcessAlive(r.pid) {
			return fmt.Errorf("SSH 服务在启动后退出，请检查连接组件或端口占用")
		}
		conn, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", r.port), time.Second)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			banner, readErr := bufio.NewReader(io.LimitReader(conn, 512)).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && strings.HasPrefix(banner, "SSH-2.0-") {
				return nil
			}
		}
		select {
		case <-readyCtx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("SSH 服务没有在 20 秒内完成协议启动。请复制诊断信息后重试；尚未开始广播。")
}

func (r *sshTargetRuntime) monitor(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var offset int64
	var partial string

	// Do not silently turn an unreadable log into a claim that SSH failed.
	// One structured warning per runtime bounds repeated polling failures.
	reportedLogFailure := false
	reportLogFailure := func(err error) {
		if reportedLogFailure {
			return
		}
		reportedLogFailure = true
		targetDiagnostic(diagnostic.Event{Level: "warning", Event: "ssh.authentication.log.failed", Step: "读取 SSH 登录状态", Instance: r.id, Error: err.Error()})
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !sshProcessAlive(r.pid) {
				select {
				case r.done <- fmt.Errorf("本次 SSH 服务已退出，请重新检查并配置"):
				default:
				}
				return
			}
			file, err := os.Open(r.logPath)
			if err != nil {
				reportLogFailure(err)
				continue
			}
			buf := make([]byte, 32*1024)
			n, readErr := file.ReadAt(buf, offset)
			_ = file.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				reportLogFailure(readErr)
			}
			offset += int64(n)
			partial += string(buf[:n])
			lines := strings.Split(partial, "\n")
			partial = lines[len(lines)-1]
			if len(partial) > 8192 {
				partial = ""
			}
			for _, line := range lines[:len(lines)-1] {
				if address, accepted := acceptedSSHLogin(line, r.username); accepted {
					r.authMu.Lock()
					r.authSerial++
					r.authMu.Unlock()
					r.emit(guiEvent{Kind: "connected", Manager: address})
					r.audit("target.ssh.authenticated", true, address)
				} else if strings.Contains(line, "Failed publickey") || strings.Contains(line, "Authentication refused") || strings.Contains(line, "User ") && strings.Contains(line, "not allowed") {
					r.emit(guiEvent{Kind: "connection-error", Detail: "SSH 身份验证未通过。管理端可重试；若持续失败，请复制诊断信息。"})
				}
			}
		}
	}
}

// Match the complete server-auth message after a constrained logger prefix.
// User-controlled invalid usernames must never forge a success state.
var sshAcceptedPattern = regexp.MustCompile(`^(?:[0-9]+ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+:? )?(?:sshd(?:-session)?(?:\[[0-9]+\])?: )?Accepted publickey for ([A-Za-z0-9_.-]+) from ([0-9a-fA-F:.]+) port ([0-9]+) ssh2(?::.*)?\r?$`)

func acceptedSSHLogin(line, username string) (string, bool) {
	parts := sshAcceptedPattern.FindStringSubmatch(line)
	if len(parts) != 4 || !strings.EqualFold(parts[1], username) || net.ParseIP(parts[2]) == nil {
		return "", false
	}
	return parts[2], true
}

func (r *sshTargetRuntime) watchAuthentication() {
	r.authMu.Lock()
	r.authSerial++
	serial := r.authSerial
	r.authMu.Unlock()
	go func() {
		timer := time.NewTimer(25 * time.Second)
		defer timer.Stop()
		<-timer.C
		r.authMu.Lock()
		stillPending := r.authSerial == serial
		r.authMu.Unlock()
		if stillPending && time.Now().Before(r.expiresAt) {
			r.emit(guiEvent{Kind: "connection-error", Detail: "已允许管理端，暂未收到登录成功信息。管理端可直接重试，无需再次确认；若持续出现，请复制诊断信息。"})
		}
	}()
}
