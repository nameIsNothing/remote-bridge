// bridge-cli is the management-side command line client for the LAN WinRM
// first version.  It never accepts a password in argv; exec/shell prompt with
// PowerShell's secure input and keep the credential in memory only.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/cliutil"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/model"
)

const version = "0.3.1-test.1"

func main() {
	args := os.Args[1:]
	code := run(args)
	if len(args) == 0 && code != 0 {
		pauseManagerOnStartupError()
	}
	os.Exit(code)
}

func run(args []string) int {
	if len(args) == 0 {
		return runInteractive()
	}
	switch strings.ToLower(args[0]) {
	case "version", "--version", "-v":
		fmt.Printf("bridge-cli %s\n", version)
		return int(model.ExitOK)
	case "check":
		return runCheck(args[1:])
	case "trust":
		return runTrust(args[1:])
	case "discover":
		return runDiscover(args[1:])
	case "ssh":
		return runSSH(args[1:])
	case "winrm":
		return runWinRM(args[1:])
	case "manage":
		return runManage(args[1:])
	case "session":
		return runSession(args[1:])
	case "mcp":
		return runMCP(args[1:])
	case "exec":
		return runExec(args[1:])
	case "shell":
		return runShell(args[1:])
	case "connect":
		if hasArg(args[1:], "--ssh") {
			sshArgs := make([]string, 0, len(args)-2)
			for _, arg := range args[1:] {
				if arg != "--ssh" {
					sshArgs = append(sshArgs, arg)
				}
			}
			return runSSH(sshArgs)
		}
		if hasArg(args[1:], "--command") || hasArg(args[1:], "--username") {
			return runWinRM(args[1:])
		}
		return runManage(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return int(model.ExitOK)
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", args[0])
		printUsage()
		return int(model.ExitUsage)
	}
}

// runDiscover performs one request/response discovery round on the local LAN.
// Discovery carries endpoint metadata only; it never carries a password or a
// state path and it never modifies TrustedHosts. The operator can inspect the
// result and then run `trust`; that command requests standard UAC consent when
// the current process is not elevated.
func runDiscover(args []string) int {
	fs := flag.NewFlagSet("bridge-cli discover", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	once := false
	timeout := discovery.DefaultDiscoverTimeout
	broadcast := "255.255.255.255"
	port := discovery.DefaultPort
	jsonOutput := false
	fs.BoolVar(&once, "once", false, "只执行一次发现请求（默认行为，保留该参数便于脚本表达意图）")
	fs.DurationVar(&timeout, "timeout", timeout, "等待响应的时长，例如 2s")
	fs.StringVar(&broadcast, "broadcast", broadcast, "IPv4 广播或定向广播地址")
	fs.IntVar(&port, "port", port, "UDP 发现端口")
	fs.BoolVar(&jsonOutput, "json", false, "输出机器可读 JSON")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	_ = once
	if timeout <= 0 || timeout > 30*time.Second {
		return fail(model.ExitUsage, errors.New("timeout 必须在 1ns 到 30s 之间"))
	}
	if _, err := discovery.ParseBroadcastAddress(broadcast, port); err != nil {
		return fail(model.ExitUsage, err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fail(model.ExitConnection, fmt.Errorf("打开 UDP 发现端口：%w", err))
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	announcements, discoverErr := discovery.Discover(ctx, conn, broadcast, port)
	metadata := map[string]string{
		"broadcast": broadcast,
		"port":      fmt.Sprintf("%d", port),
		"count":     fmt.Sprintf("%d", len(announcements)),
	}
	if discoverErr != nil {
		metadata["failed"] = "true"
	}
	_ = audit.Append(audit.DefaultPath(), model.AuditEvent{Type: "manager.discover", Success: discoverErr == nil && len(announcements) > 0, Metadata: metadata})
	if discoverErr != nil {
		return fail(model.ExitConnection, fmt.Errorf("局域网发现失败：%w", discoverErr))
	}
	if jsonOutput {
		payload := struct {
			Count   int                      `json:"count"`
			Targets []discovery.Announcement `json:"targets"`
			Warning string                   `json:"warning,omitempty"`
		}{Count: len(announcements), Targets: announcements}
		if len(announcements) > 0 {
			payload.Warning = "发现公告未经过身份认证；连接前请确认目标并执行 trust，公告不包含密码"
		}
		if err := printDiscoverJSON(payload); err != nil {
			return fail(model.ExitInternal, err)
		}
	} else if len(announcements) == 0 {
		fmt.Println("未发现 Remote Bridge 目标。请确认目标机已 apply、仍在向导窗口中，且 UDP 发现端口未被防火墙拦截。")
	} else {
		fmt.Printf("发现 %d 个目标（仅为未验证公告）：\n", len(announcements))
		for index, announcement := range announcements {
			fmt.Printf("%d. %s  地址=%s  WinRM=%s/%d  账号=%s  过期=%s\n",
				index+1,
				announcement.Hostname,
				strings.Join(announcement.Addresses, ","),
				announcement.Transport,
				announcement.Port,
				announcement.Username,
				announcement.ExpiresAt.Local().Format(time.RFC3339),
			)
		}
		fmt.Println("发现公告未经过身份认证；确认目标后，先运行 bridge-cli trust <目标IP>，再执行 check/exec。")
	}
	if len(announcements) == 0 {
		return int(model.ExitConnection)
	}
	return int(model.ExitOK)
}

func printDiscoverJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

// runTrust adds one target to the local WinRM TrustedHosts list. The operation
// changes a machine-wide management setting. When the current process is not
// elevated, the command requests the standard Windows UAC confirmation and
// waits for an elevated copy of this same executable to finish. It never
// silently bypasses UAC and it deliberately accepts exactly one IP address or
// DNS/NetBIOS hostname.
func runTrust(args []string) int {
	options, err := parseTrustOptions(args)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	target := options.target
	script := trustScript(target)
	result, runErr := cliutil.RunPowerShell(script, nil)
	if runErr != nil && result.ExitCode == 740 && !options.uacChild {
		fmt.Println("当前操作需要管理员权限，正在请求 Windows UAC 确认...")
		childCode, elevateErr := elevateTrust(target)
		auditErr := elevateErr
		if auditErr == nil && childCode != int(model.ExitOK) {
			auditErr = fmt.Errorf("elevated trust exited with code %d", childCode)
		}
		appendManagerAudit("manager.trust.elevation", target, "", "", 0, childCode, auditErr)
		if elevateErr != nil {
			if errors.Is(elevateErr, errElevationCancelled) {
				fmt.Fprintln(os.Stderr, "管理员授权已取消，TrustedHosts 未修改。")
				return int(model.ExitUnauthorized)
			}
			return fail(model.ExitInternal, elevateErr)
		}
		if childCode != int(model.ExitOK) {
			return childCode
		}
		fmt.Println("TrustedHosts 配置已完成。")
		return int(model.ExitOK)
	}
	appendManagerAudit("manager.trust", target, "", "", 0, result.ExitCode, runErr)
	if strings.TrimSpace(result.Stdout) != "" {
		fmt.Println(strings.TrimSpace(result.Stdout))
	}
	if runErr != nil {
		if strings.TrimSpace(result.Stderr) != "" {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(result.Stderr))
		}
		if result.ExitCode == 740 {
			return int(model.ExitUnauthorized)
		}
		return int(model.ExitInternal)
	}
	return int(model.ExitOK)
}

type trustOptions struct {
	target   string
	uacChild bool
}

func parseTrustOptions(args []string) (trustOptions, error) {
	fs := flag.NewFlagSet("bridge-cli trust", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	flagTarget := ""
	uacChild := false
	fs.StringVar(&flagTarget, "target", "", "目标 IP 或主机名（必填）")
	fs.BoolVar(&uacChild, "uac-child", false, "内部 UAC 子进程标志")
	if err := fs.Parse(args); err != nil {
		return trustOptions{}, err
	}
	positionals := fs.Args()
	if flagTarget != "" && len(positionals) != 0 {
		return trustOptions{}, errors.New("trust 只能指定一个目标：位置参数或 --target，不能同时使用")
	}
	target := strings.TrimSpace(flagTarget)
	if len(positionals) == 1 {
		target = strings.TrimSpace(positionals[0])
	}
	if target == "" {
		return trustOptions{}, errors.New("trust 需要一个目标 IP 或主机名，例如：bridge-cli trust 192.168.100.27")
	}
	if !validTrustedHost(target) {
		return trustOptions{}, errors.New("trust 只接受单个合法 IP 或主机名，禁止逗号、分号、通配符和路径字符")
	}
	return trustOptions{target: target, uacChild: uacChild}, nil
}

func parseTrustTarget(args []string) (string, error) {
	options, err := parseTrustOptions(args)
	if err != nil {
		return "", err
	}
	return options.target, nil
}

func validTrustedHost(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	if strings.ContainsAny(value, ",;*?\\/\"'\t\r\n") {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	// TrustedHosts accepts DNS and NetBIOS names.  Keep the grammar narrow so
	// the value cannot become a second PowerShell/WSMan expression.
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func trustScript(target string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent());
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  [Console]::Error.WriteLine('需要管理员权限：请确认 Windows UAC 后重试 bridge-cli trust');
  exit 740
}
$path = 'WSMan:\localhost\Client\TrustedHosts';
$before = [string](Get-Item -LiteralPath $path -ErrorAction Stop).Value;
$items = @($before -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' });
$present = $false;
foreach ($item in $items) { if ($item -eq '*' -or $item -ieq $target) { $present = $true; break } }
$changed = $false;
if (-not $present) {
  $after = (($items + $target) -join ',');
  Set-Item -LiteralPath $path -Value $after -Force;
  $changed = $true;
} else { $after = $before }
[pscustomobject]@{ target = $target; changed = $changed; trusted_hosts = $after } | ConvertTo-Json -Compress`, encodeValue(target))
}

// runInteractive makes the management exe usable directly from a USB drive:
// it asks for the endpoint and either opens a shell or executes one command.
// The password prompt remains inside the PowerShell child and is never read
// into Go memory.
func runInteractive() int {
	return runManage([]string{"--discover"})
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("bridge-cli check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target := ""
	port := 5985
	fs.StringVar(&target, "target", "", "目标主机名或 IP（必填）")
	fs.IntVar(&port, "port", port, "WinRM 端口：5985 或 5986")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if strings.TrimSpace(target) == "" || (port != 5985 && port != 5986) {
		return fail(model.ExitUsage, errors.New("target 必填，port 只能是 5985 或 5986"))
	}
	encodedTarget := encodeValue(target)
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')); $r = Test-NetConnection -ComputerName $target -Port %d -WarningAction SilentlyContinue; [pscustomobject]@{ target = $target; port = %d; tcp_test_succeeded = [bool]$r.TcpTestSucceeded; remote_address = [string]$r.RemoteAddress } | ConvertTo-Json -Compress; if (-not $r.TcpTestSucceeded) { exit 20 }`, encodedTarget, port, port)
	result, err := cliutil.RunPowerShell(script, nil)
	appendManagerAudit("manager.check", target, "", "", port, result.ExitCode, err)
	if strings.TrimSpace(result.Stdout) != "" {
		fmt.Println(strings.TrimSpace(result.Stdout))
	}
	if err != nil {
		if strings.TrimSpace(result.Stderr) != "" {
			fmt.Fprintln(os.Stderr, strings.TrimSpace(result.Stderr))
		}
		return int(model.ExitConnection)
	}
	return int(model.ExitOK)
}

func runExec(args []string) int {
	fs := flag.NewFlagSet("bridge-cli exec", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target, username, command := "", "", ""
	port := 5985
	fs.StringVar(&target, "target", "", "目标主机名或 IP（必填）")
	fs.StringVar(&username, "username", "", "临时账号名（必填）")
	fs.StringVar(&command, "command", "", "在目标机执行的一条 PowerShell 命令（必填）")
	fs.IntVar(&port, "port", port, "WinRM 端口：5985 或 5986")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if strings.TrimSpace(target) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(command) == "" || (port != 5985 && port != 5986) {
		return fail(model.ExitUsage, errors.New("target、username、command 必填，port 只能是 5985 或 5986"))
	}
	script := remoteExecScript(target, username, command, port)
	code, err := cliutil.RunPowerShellInteractive(script)
	appendManagerAudit("manager.exec", target, username, command, port, code, err)
	if err != nil && code < 0 {
		return int(model.ExitConnection)
	}
	if code == 20 {
		return int(model.ExitConnection)
	}
	if code != 0 {
		return int(model.ExitRemoteCommand)
	}
	return int(model.ExitOK)
}

func runShell(args []string) int {
	fs := flag.NewFlagSet("bridge-cli shell", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	target, username := "", ""
	port := 5985
	fs.StringVar(&target, "target", "", "目标主机名或 IP（必填）")
	fs.StringVar(&username, "username", "", "临时账号名（必填）")
	fs.IntVar(&port, "port", port, "WinRM 端口：5985 或 5986")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if strings.TrimSpace(target) == "" || strings.TrimSpace(username) == "" || (port != 5985 && port != 5986) {
		return fail(model.ExitUsage, errors.New("target、username 必填，port 只能是 5985 或 5986"))
	}
	script := remoteShellScript(target, username, port)
	code, err := cliutil.RunPowerShellInteractive(script)
	appendManagerAudit("manager.shell", target, username, "", port, code, err)
	if err != nil && code < 0 {
		return int(model.ExitConnection)
	}
	if code != 0 {
		return int(model.ExitConnection)
	}
	return int(model.ExitOK)
}

func remoteExecScript(target, username, command string, port int) string {
	endpoint := fmt.Sprintf("-Port %d", port)
	if port == 5986 {
		endpoint += " -UseSSL"
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$remoteCommand = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$secure = Read-Host ('Remote Bridge password for ' + $username) -AsSecureString;
$credential = [PSCredential]::new($username, $secure);
$remoteScript = {
  param([string]$bridgeCommand)
  $ErrorActionPreference = 'Continue';
  # Passing a variable directly after -Command is parsed as multiple native
  # arguments by Windows PowerShell 5.1; commands with spaces or pipelines can
  # therefore be truncated to their first token.  Encode the complete script
  # as UTF-16LE so the nested process receives it as one opaque argument.
  $encodedBridgeCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bridgeCommand));
  $output = (& powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedBridgeCommand 2>&1 | Out-String);
  $code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE };
  [pscustomobject]@{ output = $output; exit_code = $code }
};
try {
  $results = @(Invoke-Command -ComputerName $target %s -Credential $credential -Authentication Negotiate -ScriptBlock $remoteScript -ArgumentList $remoteCommand);
  $results | ConvertTo-Json -Depth 5;
  if ($results.Count -gt 0 -and $null -ne $results[-1].exit_code -and [int]$results[-1].exit_code -ne 0) { exit ([int]$results[-1].exit_code) }
} catch {
  Write-Error $_.Exception.Message;
  exit 20
}`, encodeValue(target), encodeValue(username), encodeValue(command), endpoint)
}

func remoteShellScript(target, username string, port int) string {
	endpoint := fmt.Sprintf("-Port %d", port)
	if port == 5986 {
		endpoint += " -UseSSL"
	}
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$secure = Read-Host ('Remote Bridge password for ' + $username) -AsSecureString;
$credential = [PSCredential]::new($username, $secure);
try { Enter-PSSession -ComputerName $target %s -Credential $credential -Authentication Negotiate } catch { Write-Error $_.Exception.Message; exit 20 }`, encodeValue(target), encodeValue(username), endpoint)
}

func encodeValue(value string) string {
	return base64.StdEncoding.EncodeToString([]byte(value))
}

func appendManagerAudit(eventType, target, username, command string, port, exitCode int, runErr error) {
	metadata := map[string]string{
		"target":    target,
		"port":      fmt.Sprintf("%d", port),
		"exit_code": fmt.Sprintf("%d", exitCode),
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

func fail(code model.ExitCode, err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
	}
	return int(code)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `用法：
  bridge-cli manage --discover [--target <IP>]
  bridge-cli manage --ssh [--target <IP>]
  bridge-cli session list
  bridge-cli session status --id <rb-会话编号>
  bridge-cli session exec --id <rb-会话编号> --command <远程Shell命令>
  bridge-cli session close --id <rb-会话编号>
  bridge-cli mcp
  bridge-cli check --target <主机名或IP> [--port 5985]
  bridge-cli trust <主机名或IP>
  bridge-cli trust --target <主机名或IP>
  bridge-cli discover --once [--json] [--timeout 2s]
  bridge-cli ssh --discover [--pair-timeout 60s] [--command <远程Shell命令>]
  bridge-cli ssh --target <主机名或IP> [--instance <实例ID>] [--command <远程Shell命令>]
  bridge-cli ssh --target <Unix目标IP> --manage
  bridge-cli connect --discover [--command <PowerShell命令>]
  bridge-cli exec  --target <主机名或IP> --username <临时账号> --command <PowerShell命令>
  bridge-cli shell --target <主机名或IP> --username <临时账号>

ssh/discover 只在同一局域网查找交互式目标窗口；SSH 使用一次性 Ed25519 公钥配对和临时 known_hosts，不需要输入密码。
公告未认证且不包含密码，不会自动修改 TrustedHosts；目标机必须在配对弹窗中确认管理端公钥。
exec/shell 会在控制台安全提示密码，不接受 --password，避免密码出现在进程参数和日志中。
trust 会幂等添加本机 WinRM TrustedHosts；非管理员运行时会唤起标准 Windows UAC，用户确认后继续。只接受单个 IP 或主机名。`)
}

func hasArg(args []string, want string) bool {
	for _, arg := range args {
		if strings.EqualFold(strings.TrimSpace(arg), want) {
			return true
		}
	}
	return false
}
