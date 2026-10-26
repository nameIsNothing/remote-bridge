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

	"remote-bridge/internal/managedsession"
)

func TestManagedWorkerPromptsOnceAndReusesOneSession(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	info := managedsession.Info{ID: "rb-0123456789abcdef01234567", InstanceID: "ssh-0123456789ab", Hostname: "TEST", Username: `TEST\张三`, Target: "192.0.2.10", Port: 5985, ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Second)}
	server, err := managedsession.NewServer(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	root := t.TempDir()
	// Authentication and target lease are fixtures. Dispatch uses the real
	// PowerShell job, production command body and bounded child process, so
	// argument binding/Unicode/exit-code failures cannot be hidden by a mock.
	leaseFixture := `function Read-BridgeLease([string]$Instance) { if($Instance -cne 'ssh-0123456789ab') {throw 'wrong command instance'}; return [pscustomobject]@{active=$true} }`
	config := map[string]any{"endpoint": server.Endpoint(), "token": server.WorkerToken(), "fingerprint": server.Record().Fingerprint, "session": info, "lease_script": leaseFixture, "command_script": managedCommandScript, "handoff": "fixture"}
	data, _ := json.Marshal(config)
	configPath := filepath.Join(root, "worker.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "worker.ps1")
	if err := os.WriteFile(scriptPath, append([]byte{0xef, 0xbb, 0xbf}, []byte(managedWorkerScript)...), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureUI := `
$global:promptCount=0; $global:sessionCount=0; $global:commandCount=0; $global:removeCount=0; $global:timeouts=@()
$global:fakeSession=[pscustomobject]@{state='Opened'}
function Read-BridgePassword { $global:promptCount++; $global:fixtureSecure=New-Object Security.SecureString; $global:fixtureSecure.AppendChar('x'); return $global:fixtureSecure }
function Show-BridgeManager {}
function Update-BridgeManager {}
function Close-BridgeManager {
  $disposed=$false
  try { $null=$global:fixtureSecure.Copy() } catch { $disposed=$_.Exception.GetBaseException() -is [ObjectDisposedException] }
  [pscustomobject]@{prompts=$global:promptCount;sessions=$global:sessionCount;commands=$global:commandCount;removed=$global:removeCount;disposed=$disposed;timeouts=$global:timeouts} |
    ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'fixture-result.json') -Encoding UTF8
}

function New-PSSession {
 [CmdletBinding()]param($ComputerName,$Port,$Credential,$Authentication,$SessionOption,[switch]$UseSSL)
 if($ComputerName -ne '192.0.2.10' -or $Authentication -ne 'Negotiate') {throw 'unexpected connection'}
 $global:sessionCount++;return $global:fakeSession
}
function Invoke-Command {
 [CmdletBinding()]param($Session,[scriptblock]$ScriptBlock,[object[]]$ArgumentList,[switch]$AsJob)
 if(-not [object]::ReferenceEquals($Session,$global:fakeSession)) {throw 'command left verified session'}
 if($AsJob) {
   if($ArgumentList.Count -ne 3 -or $ArgumentList[0] -cne $config.session.instance_id -or $ArgumentList[1] -isnot [string] -or $ArgumentList[2] -isnot [int]) {throw 'command arguments must be instance, command string, integer timeout'}
   $global:commandCount++
   $global:timeouts+=@($ArgumentList[2])
   return (Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList)
 }
 if($ArgumentList.Count -eq 2) {
   return [pscustomobject]@{hostname=$config.session.hostname;username=$config.session.username;sid='S-1-5-21-1000-2000-3000-1001';instance_id=$config.session.instance_id;expires_at=$config.session.expires_at;PSComputerName='192.0.2.10';RunspaceId='fixture-runspace';PSShowComputerName=$true}
 }
}
function Remove-PSSession { [CmdletBinding()]param($Session);$global:removeCount++ }
`
	if err := os.WriteFile(filepath.Join(root, "ui.ps1"), []byte(fixtureUI), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", scriptPath, "-ConfigPath", configPath)
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	if err := server.WaitReady(ctx); err != nil {
		_ = command.Wait()
		t.Fatalf("worker did not authenticate: %v; %s", err, &output)
	}
	for i, expected := range []string{"first", "中文"} {
		text := "Write-Output '" + expected + "'"
		response, err := managedsession.Call(ctx, server.Record(), managedsession.Request{Operation: "exec", Command: text, Timeout: 7 + 4*i})
		if err != nil || response.Result == nil || strings.TrimSpace(response.Result.Stdout) != expected || response.Result.ExitCode != 0 {
			t.Fatalf("worker call failed: %+v err=%v; %s", response, err, &output)
		}
	}
	catalog, err := managedsession.DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	directory, err := managedsession.PrepareDirectory(catalog, info.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := managedsession.WriteRecord(directory, server.Record()); err != nil {
		t.Fatal(err)
	}
	initialized := true
	request := mcpRequest{JSONRPC: "2.0", Method: "tools/call", Params: json.RawMessage(`{"name":"bridge_execute","arguments":{"session_id":"` + info.ID + `","command":"exit 21"}}`)}
	result, rpcErr := handleMCP(request, &initialized)
	if rpcErr != nil || result.(map[string]any)["isError"] != true {
		t.Fatalf("MCP lost remote failure: %v %v", result, rpcErr)
	}
	if strings.Contains(encodeJSON(result), server.Record().Token) || strings.Contains(encodeJSON(result), server.WorkerToken()) {
		t.Fatal("MCP leaked IPC credentials")
	}
	if code := runSession([]string{"exec", "--id", info.ID, "--command", "exit 21", "--json"}); code != 21 {
		t.Fatalf("JSON CLI lost failure: %d", code)
	}
	request.Params = json.RawMessage(`{"name":"bridge_end_session","arguments":{"session_id":"` + info.ID + `"}}`)
	result, rpcErr = handleMCP(request, &initialized)
	if rpcErr != nil || result.(map[string]any)["isError"] == true {
		t.Fatalf("MCP end failed: %v %v", result, rpcErr)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("worker failed: %v; %s", err, &output)
	}
	file, err := os.ReadFile(filepath.Join(root, "fixture-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Prompts, Sessions, Commands, Removed int
		Disposed                             bool
		Timeouts                             []int
	}
	if err := json.Unmarshal(bytes.TrimPrefix(file, []byte{0xef, 0xbb, 0xbf}), &got); err != nil {
		t.Fatalf("bad fixture result: %v %q", err, file)
	}
	if got.Prompts != 1 || got.Sessions != 1 || got.Commands != 4 || got.Removed != 1 || !got.Disposed {
		t.Fatalf("credential/session lifetime incorrect: %+v; %s", got, &output)
	}
	if encodeJSON(got.Timeouts) != `[7,11,30,30]` {
		t.Fatalf("command timeout values changed across dispatch: %v", got.Timeouts)
	}
	if strings.Contains(output.String(), server.WorkerToken()) {
		t.Fatal("worker token printed")
	}
}

// Authentication fails before a target script can run. Exercise the real
// worker and local HTTPS protocol; only the credential UI and WinRM cmdlets
// are fixtures, so no actual login attempts or target changes are made.
func TestManagedWorkerAuthenticationFailureDoesNotContactTarget(t *testing.T) {
	info := managedsession.Info{ID: "rb-0123456789abcdef01234567", InstanceID: "ssh-0123456789ab", Hostname: "TEST", Username: `TEST\fixture`, Target: "192.0.2.10", Port: 5985, ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Second)}
	server, err := managedsession.NewServer(info, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	root := t.TempDir()
	configPath := filepath.Join(root, "worker.json")
	data, err := json.Marshal(map[string]any{
		"endpoint": server.Endpoint(), "token": server.WorkerToken(), "fingerprint": server.Record().Fingerprint, "session": info,
		"lease_script": "throw 'unauthenticated target lease access'", "command_script": "throw 'unauthenticated command'",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(root, "worker.ps1")
	if err := os.WriteFile(scriptPath, append([]byte{0xef, 0xbb, 0xbf}, []byte(managedWorkerScript)...), 0600); err != nil {
		t.Fatal(err)
	}
	fixtureUI := `
$global:prompts=0; $global:attempts=0; $global:remoteCalls=0; $global:removed=0; $global:shown=0
function Read-BridgePassword {
 $global:prompts++
 $global:fixtureSecure=[Security.SecureString]::new()
 $global:fixtureSecure.AppendChar('x')
 return $global:fixtureSecure
}
function New-PSSession {
 [CmdletBinding()]param($ComputerName,$Port,$Credential,$Authentication,$SessionOption,[switch]$UseSSL)
 $global:attempts++
 throw [Security.Authentication.AuthenticationException]::new('fixture authentication rejected')
}
function Invoke-Command { [CmdletBinding()]param($Session,$ScriptBlock,$ArgumentList,[switch]$AsJob); $global:remoteCalls++; throw 'target must not be contacted after failed authentication' }
function Remove-PSSession { [CmdletBinding()]param($Session); $global:removed++ }
function Show-BridgeManager { $global:shown++ }
function Update-BridgeManager {}
function Close-BridgeManager {
 $disposed=$false
 try { $null=$global:fixtureSecure.Copy() } catch { $disposed=$_.Exception.GetBaseException() -is [ObjectDisposedException] }
 [pscustomobject]@{prompts=$global:prompts;attempts=$global:attempts;remote_calls=$global:remoteCalls;removed=$global:removed;shown=$global:shown;disposed=$disposed} |
  ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'fixture-result.json') -Encoding UTF8
}
`
	if err := os.WriteFile(filepath.Join(root, "ui.ps1"), []byte(fixtureUI), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", scriptPath, "-ConfigPath", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("worker did not handle authentication rejection: %v\n%s", err, output)
	}
	file, err := os.ReadFile(filepath.Join(root, "fixture-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Prompts, Attempts, Removed, Shown int
		RemoteCalls                       int `json:"remote_calls"`
		Disposed                          bool
	}
	if err := json.Unmarshal(bytes.TrimPrefix(file, []byte{0xef, 0xbb, 0xbf}), &result); err != nil {
		t.Fatal(err)
	}
	if result.Prompts != 1 || result.Attempts != 1 || result.RemoteCalls != 0 || result.Removed != 0 || result.Shown != 0 || !result.Disposed {
		t.Fatalf("failed authentication changed target/session lifecycle: %+v", result)
	}
	closed := server.Info()
	if closed.State != "closed" || closed.SID != "" || !strings.Contains(closed.Reason, "[authentication]") {
		t.Fatalf("authentication failure was not reported correctly: %+v", closed)
	}
	if _, err := managedsession.Call(ctx, server.Record(), managedsession.Request{Operation: "exec", Command: "Get-Date"}); err == nil {
		t.Fatal("failed login accepted a command")
	}
	if strings.Contains(string(output), server.WorkerToken()) || strings.Contains(string(output), server.Record().Token) {
		t.Fatal("authentication failure printed interface credentials")
	}
}
