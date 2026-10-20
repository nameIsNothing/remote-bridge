package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"remote-bridge/internal/cliutil"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/model"
)

// runWinRM is the current-account WinRM path. With --discover it uses the
// username and WinRM endpoint announced by the target; the password is read
// by PowerShell as a SecureString and never enters Go or a process argument.
func runWinRM(args []string) int {
	fs := flag.NewFlagSet("bridge-cli winrm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	discover := false
	target, username, command, broadcast := "", "", "", "255.255.255.255"
	timeout := discovery.DefaultDiscoverTimeout
	port := 5985
	discoveryPort := discovery.DefaultPort
	fs.BoolVar(&discover, "discover", false, "通过 UDP 发现目标并使用公告中的当前账号")
	fs.StringVar(&target, "target", "", "目标主机名或 IP")
	fs.StringVar(&username, "username", "", "当前 Windows 账号；使用 --discover 时从公告读取")
	fs.StringVar(&command, "command", "", "目标 PowerShell 命令；省略则进入逐行会话，exit 结束")
	fs.StringVar(&broadcast, "broadcast", broadcast, "IPv4 广播或定向广播地址")
	fs.DurationVar(&timeout, "timeout", timeout, "UDP 发现等待时间")
	fs.IntVar(&port, "port", port, "WinRM 端口；直连时为 5985 或 5986")
	fs.IntVar(&discoveryPort, "discovery-port", discoveryPort, "UDP 发现端口")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if timeout <= 0 || timeout > 30*time.Second || discoveryPort < 1 || discoveryPort > 65535 {
		return fail(model.ExitUsage, errors.New("timeout 或 discovery-port 无效"))
	}
	if discover {
		items, err := discoverForWinRM(timeout, broadcast, discoveryPort)
		if err != nil {
			return fail(model.ExitConnection, err)
		}
		selected, err := selectWinRMAnnouncement(items, target)
		if err != nil {
			return fail(model.ExitConnection, err)
		}
		target, username, port = selected.Addresses[0], selected.Username, selected.Port
		fmt.Printf("已发现 WinRM 目标 %s (%s)，账号 %s，端口 %d\n", selected.Hostname, target, username, port)
	}
	if strings.TrimSpace(target) == "" || strings.TrimSpace(username) == "" || (port != 5985 && port != 5986) {
		return fail(model.ExitUsage, errors.New("target、username 必须填写，port 只能是 5985 或 5986"))
	}
	if command == "" {
		return runWinRMShell(target, username, port)
	}
	return runWinRMExec(target, username, command, port)
}

func discoverForWinRM(timeout time.Duration, broadcast string, port int) ([]discovery.Announcement, error) {
	if _, err := discovery.ParseBroadcastAddress(broadcast, port); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("打开 UDP 发现端口失败：%w", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	items, err := discovery.Discover(ctx, conn, broadcast, port)
	if err != nil {
		return nil, fmt.Errorf("局域网发现失败：%w", err)
	}
	return items, nil
}

func selectWinRMAnnouncement(items []discovery.Announcement, target string) (discovery.Announcement, error) {
	want := strings.TrimSpace(target)
	var matches []discovery.Announcement
	for _, item := range items {
		transport := strings.ToLower(strings.TrimSpace(item.Transport))
		if transport != "winrm" && transport != "wsman" && transport != "winrm-http" && transport != "winrm-https" && transport != "http" && transport != "https" {
			continue
		}
		if want != "" && !strings.EqualFold(item.Hostname, want) && !containsFold(item.Addresses, want) {
			continue
		}
		if len(item.Addresses) > 0 {
			matches = append(matches, item)
		}
	}
	if len(matches) == 0 {
		return discovery.Announcement{}, errors.New("未发现 WinRM 目标；请确认目标机已完成 WinRM 配置并正在广播")
	}
	if len(matches) > 1 && want == "" {
		return discovery.Announcement{}, errors.New("发现多个 WinRM 目标；请使用 --target 指定主机名或 IP")
	}
	return matches[0], nil
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return true
		}
	}
	return false
}

func runWinRMExec(target, username, command string, port int) int {
	script := verifiedRemoteExecScript(target, username, command, port)
	code, err := cliutil.RunPowerShellInteractive(script)
	appendManagerAudit("manager.winrm.exec", target, username, command, port, code, err)
	if err != nil && code < 0 {
		return int(model.ExitConnection)
	}
	return winRMResultCode(code)
}

func runWinRMShell(target, username string, port int) int {
	script := verifiedRemoteShellScript(target, username, port)
	code, err := cliutil.RunPowerShellInteractive(script)
	appendManagerAudit("manager.winrm.shell", target, username, "", port, code, err)
	if err != nil && code < 0 {
		return int(model.ExitConnection)
	}
	return winRMResultCode(code)
}

// Generated scripts use stable bridge exit codes; remote commands retain
// their original exit code only in the JSON result, avoiding collisions.
func winRMResultCode(code int) int {
	switch model.ExitCode(code) {
	case model.ExitOK, model.ExitUnauthorized, model.ExitConnection, model.ExitRemoteCommand:
		return code
	default:
		return int(model.ExitConnection)
	}
}

func winRMEndpoint(port int) string {
	endpoint := fmt.Sprintf("-Port %d", port)
	if port == 5986 {
		endpoint += " -UseSSL"
	}
	return endpoint
}

func verifiedRemoteExecScript(target, username, command string, port int) string {
	body := fmt.Sprintf(`
$remoteCommand = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$remoteScript = {
  param([string]$bridgeCommand)
  $ErrorActionPreference = 'Continue';
  $encodedBridgeCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bridgeCommand));
  $output = (& powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand $encodedBridgeCommand 2>&1 | Out-String);
  $code = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE };
  [pscustomobject]@{ output = $output; exit_code = $code }
};
$results = @(Invoke-Command -Session $bridgeSession -ScriptBlock $remoteScript -ArgumentList $remoteCommand -ErrorAction Stop);
if ($results.Count -ne 1 -or $null -eq $results[0].exit_code) { throw 'WinRM 未返回有效的命令结果' }
$results | ConvertTo-Json -Depth 5;
$bridgeExitCode = if ([int]$results[0].exit_code -eq 0) { 0 } else { 21 };
`, encodeValue(command))
	return verifiedWinRMSessionScript(target, username, port, body)
}

func verifiedRemoteShellScript(target, username string, port int) string {
	// Enter-PSSession cannot be embedded in a script reliably (see Microsoft's
	// Enter-PSSession documentation). Keep one verified session and submit each
	// line remotely instead. This is a command loop, not a full terminal host.
	return verifiedWinRMSessionScript(target, username, port, `
Write-Host 'Remote Bridge 逐行 PowerShell 会话；输入 exit 结束。不支持多行输入或交互程序。';
$bridgeExitCode = 0;
while ($true) {
  [Console]::Write(('Remote Bridge [{0}@{1}]> ' -f $username, $target));
  $bridgeLine = [Console]::ReadLine();
  if ($null -eq $bridgeLine -or $bridgeLine.Trim() -ieq 'exit' -or $bridgeLine.Trim() -ieq 'Exit-PSSession') { break }
  if ([string]::IsNullOrWhiteSpace($bridgeLine)) { continue }
  try {
    Invoke-Command -Session $bridgeSession -ScriptBlock ([ScriptBlock]::Create($bridgeLine)) -ErrorAction Stop | Out-Host;
  } catch {
    [Console]::Error.WriteLine($_.Exception.Message);
    if ($bridgeSession.State -ne 'Opened') { $bridgeExitCode = 20; break }
  }
}
`)
}

func verifiedWinRMSessionScript(target, username string, port int, body string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop';
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$username = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));
$bridgeSession = $null;
$secure = $null;
$credential = $null;
$bridgeExitCode = 20;
try {
  $secure = Read-Host ('Remote Bridge password for ' + $username) -AsSecureString;
  $credential = [PSCredential]::new($username, $secure);
  $bridgeSession = New-PSSession -ComputerName $target %s -Credential $credential -Authentication Negotiate -ErrorAction Stop;
  $identities = @(Invoke-Command -Session $bridgeSession -ScriptBlock { (whoami).Trim() } -ErrorAction Stop);
  if ($identities.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$identities[0])) { throw 'WinRM 未返回有效的远端身份' }
  $actualName = ([string]$identities[0]).Trim();
  $expectedName = $username.Trim();
  $identityMatches = [string]::Equals($actualName, $expectedName, [StringComparison]::OrdinalIgnoreCase) -or ($expectedName -notmatch '\\' -and [string]::Equals(($actualName -split '\\')[-1], $expectedName, [StringComparison]::OrdinalIgnoreCase));
  if (-not $identityMatches) {
    $bridgeExitCode = 11;
    throw ('远端身份不匹配：预期账号=' + $username + '，实际账号=' + $actualName);
  }
%s
} catch {
  [Console]::Error.WriteLine($_.Exception.Message);
  if ($bridgeExitCode -eq 0) { $bridgeExitCode = 20 }
} finally {
  if ($null -ne $bridgeSession) {
    try { Remove-PSSession -Session $bridgeSession -ErrorAction Stop } catch {
      [Console]::Error.WriteLine(('清理 WinRM 会话失败：' + $_.Exception.Message));
      if ($bridgeExitCode -eq 0) { $bridgeExitCode = 20 }
    }
  }
  $credential = $null;
  if ($null -ne $secure) { $secure.Dispose() }
}
exit $bridgeExitCode;
`, encodeValue(target), encodeValue(username), winRMEndpoint(port), body)
}
