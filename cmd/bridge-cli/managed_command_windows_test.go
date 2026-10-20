//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/winrmlease"
)

// These tests run the actual command/Job implementation against a temporary
// lease. No WinRM sessions, accounts, firewall rules or services are created.
func TestManagedCommandLeaseAndProcessLifetime(t *testing.T) {
	root := t.TempDir()
	script := `param($Root)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
` + winrmlease.RemoteScript + `
$script:fixtureRoot=$Root
function Get-BridgeLeaseRoot {return $script:fixtureRoot}
$instance='ssh-0123456789ab'
$directory=Join-Path $Root $instance
$null=New-Item -ItemType Directory -Path $directory
$path=Join-Path $directory 'lease.json'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$controller=[Diagnostics.Process]::GetCurrentProcess()
$lease=[pscustomobject]@{version=1;instance_id=$instance;sid=$identity.User.Value;username=$identity.Name;hostname=$env:COMPUTERNAME;active=$true;expires_at=[DateTimeOffset]::UtcNow.AddMinutes(2).ToString('o');controller_pid=$PID;controller_start_ticks=$controller.StartTime.ToUniversalTime().Ticks.ToString()}
function Save-Lease { [IO.File]::WriteAllText($path,($lease|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false)) }
Save-Lease
$execute={
param($instance,$command,$timeout)
__COMMAND_BODY__
}
$normal=& $execute $instance "Write-Output '中文'; exit 21" 10
if($normal.exit_code -ne 21 -or $normal.stdout.Trim() -cne '中文') {throw 'Unicode or exit code lost'}
$large=& $execute $instance "Write-Output ('x'*200000)" 10
if(-not $large.truncated -or $large.stdout.Length -gt 131072) {throw 'Output limit failed'}
# A command's descendants must be gone even if the parent exits first.
$pidPath=Join-Path $Root 'child.pid'
$treeCommand=@'
$p=Start-Process powershell.exe -ArgumentList '-NoProfile -Command "Start-Sleep -Seconds 60"' -PassThru -WindowStyle Hidden
[IO.File]::WriteAllText('__PIDPATH__',$p.Id.ToString())
'@
$treeCommand=$treeCommand.Replace('__PIDPATH__',$pidPath.Replace("'","''"))
$null=& $execute $instance $treeCommand 10
$childID=[int][IO.File]::ReadAllText($pidPath)
Start-Sleep -Milliseconds 200
if(Get-Process -Id $childID -ErrorAction SilentlyContinue) {throw 'Child process survived command end'}
$timeoutKilled=$false
try { $null=& $execute $instance "Start-Sleep -Seconds 60" 1 } catch { $timeoutKilled=$_.Exception.Message -like '*timed out*' }
if(-not $timeoutKilled) {throw 'Timeout did not stop command'}
# A background job changes only the temp lease while the real process is running.
$revoke=Start-Job -ArgumentList $path -ScriptBlock {
 param($leasePath)
 Start-Sleep -Seconds 1
 $data=Get-Content -LiteralPath $leasePath -Raw -Encoding UTF8 | ConvertFrom-Json
 $data.active=$false
 [IO.File]::WriteAllText($leasePath,($data|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
}
$revoked=$false
try { $null=& $execute $instance "Start-Sleep -Seconds 60" 10 } catch { $revoked=$_.Exception.Message -like '*ended, expired*' }
Wait-Job $revoke | Out-Null; Receive-Job $revoke | Out-Null; Remove-Job $revoke
if(-not $revoked) {throw 'Running command ignored target end'}
$denied=$false
try { $null=& $execute $instance "throw 'MUST NOT RUN'" 10 } catch { $denied=$_.Exception.Message -like '*ended, expired*' }
if(-not $denied) {throw 'New command accepted after revoke'}
$lease.active=$true; $lease.expires_at=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o');Save-Lease
$expired=$false
try {$null=Read-BridgeLease $instance} catch {$expired=$true}
if(-not $expired) {throw 'Expired lease accepted'}
$lease.expires_at=[DateTimeOffset]::UtcNow.AddMinutes(1).ToString('o');$lease.controller_start_ticks='0';Save-Lease
$reusedPID=$false
try {$null=Read-BridgeLease $instance} catch {$reusedPID=$true}
if(-not $reusedPID) {throw 'Controller process identity ignored'}
[pscustomobject]@{exit_code=$normal.exit_code;unicode=$normal.stdout.Trim();bounded=$large.truncated;timeout=$timeoutKilled;revoke=$revoked;expired=$expired;controller=$reusedPID} | ConvertTo-Json -Compress
`
	script = strings.ReplaceAll(script, "__COMMAND_BODY__", managedCommandScript)
	path := filepath.Join(root, "fixture.ps1")
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(script)...), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", path, "-Root", root).CombinedOutput()
	if err != nil {
		t.Fatalf("command lifecycle failed: %v\n%s", err, output)
	}
	var result map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
		t.Fatalf("invalid result: %v\n%s", err, output)
	}
	if result["revoke"] != true || result["unicode"] != "中文" || result["exit_code"] != float64(21) {
		t.Fatal(result)
	}
}
