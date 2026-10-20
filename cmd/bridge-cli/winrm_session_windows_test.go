//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/cliutil"
)

func TestVerifiedWinRMExecSessionLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, username, identity string
		code, commands, removed  int
	}{
		{"success", `TARGET\EDY`, `target\edy`, 0, 1, 1},
		{"short-name", "EDY", `target\edy`, 0, 1, 1},
		{"unicode", `电脑\张三`, `电脑\张三`, 0, 1, 1},
		{"mismatch", `TARGET\EDY`, `other\edy`, 11, 0, 1},
		{"new-fails", `TARGET\EDY`, `target\edy`, 20, 0, 0},
		{"identity-fails", `TARGET\EDY`, `target\edy`, 20, 0, 1},
		{"identity-empty", `TARGET\EDY`, "", 20, 0, 1},
		{"identity-many", `TARGET\EDY`, `target\edy`, 20, 0, 1},
		{"transport-fails", `TARGET\EDY`, `target\edy`, 20, 1, 1},
		{"invalid-result", `TARGET\EDY`, `target\edy`, 20, 1, 1},
		{"remote-fails", `TARGET\EDY`, `target\edy`, 21, 1, 1},
		{"cleanup-fails", `TARGET\EDY`, `target\edy`, 20, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Exercise the real nested command in a local child PowerShell,
			// reached only through the in-memory session mock below.
			command := `$x = 'fixture with spaces'; Write-Output ($x + '|中文'); exit 0`
			if tc.name == "remote-fails" {
				command = "exit 21"
			}
			port := 5985
			if tc.name == "unicode" {
				port = 5986
			}
			got := runWinRMSessionFixture(t, verifiedRemoteExecScript("192.0.2.10", tc.username, command, port), tc.name, tc.identity, "", port)
			if got.Code != tc.code || got.Commands != tc.commands || got.Removed != tc.removed {
				t.Fatalf("got %+v; want code=%d commands=%d removed=%d", got, tc.code, tc.commands, tc.removed)
			}
			if got.Created != 1 || got.Prompts != 1 || !got.Disposed {
				t.Fatalf("expected one credential prompt/session and disposed secure input: %+v", got)
			}
			if tc.name == "success" && !strings.Contains(got.Output, "fixture with spaces|中文") {
				t.Fatalf("nested command lost quotes, spaces or Unicode: %q", got.Output)
			}
			if tc.name == "remote-fails" && !strings.Contains(got.Output, `"exit_code":  21`) {
				t.Fatalf("remote exit code lost: %q", got.Output)
			}
		})
	}
}

func TestVerifiedWinRMCommandLoopUsesVerifiedSession(t *testing.T) {
	for _, tc := range []struct {
		name, input, identity string
		code, commands        int
	}{
		{"success", "$remoteValue = 7\n$remoteValue\nexit\n", `target\edy`, 0, 2},
		{"eof", "", `target\edy`, 0, 0},
		{"blank", "\n  \nExit-PSSession\n", `target\edy`, 0, 0},
		{"mismatch", "throw 'must not run locally'\nexit\n", `other\edy`, 11, 0},
		{"command-error", "throw 'remote fixture error'\nGet-Date\nexit\n", `target\edy`, 0, 2},
		{"connection-lost", "Get-Date\nGet-Date\nexit\n", `target\edy`, 20, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runWinRMSessionFixture(t, verifiedRemoteShellScript("192.0.2.10", `TARGET\EDY`, 5985), tc.name, tc.identity, tc.input, 5985)
			if got.Code != tc.code || got.Commands != tc.commands || got.Removed != 1 || got.Created != 1 || got.Prompts != 1 || !got.Disposed {
				t.Fatalf("unexpected command-loop result: %+v", got)
			}
			if tc.name == "success" && strings.Join(got.Lines, "\n") != "$remoteValue = 7\n$remoteValue" {
				t.Fatalf("command text changed before remote dispatch: %q", got.Lines)
			}
		})
	}
}

type winRMSessionFixtureResult struct {
	Lines                                     []string
	Code, Created, Commands, Removed, Prompts int
	Disposed                                  bool
	Output                                    string
}

// Only functions in this fixture receive session operations. They reject
// ComputerName-based Invoke-Command and any object other than the one fake
// session. No WinRM service, listener, TrustedHosts or remote host is touched.
func runWinRMSessionFixture(t *testing.T, script, scenario, identity, input string, port int) winRMSessionFixtureResult {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.ps1")
	// Windows PowerShell 5.1 requires a BOM for UTF-8 script files.
	if err := os.WriteFile(path, []byte("\xef\xbb\xbf"+script), 0600); err != nil {
		t.Fatal(err)
	}
	harness := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$OutputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$global:scenario = '%s'
$global:identity = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
$global:created = 0; $global:commands = 0; $global:removed = 0; $global:prompts = 0; $global:invocations = 0
$global:submitted = New-Object 'Collections.Generic.List[string]'
$global:fakeSession = [pscustomobject]@{ State = 'Opened' }
function Read-Host {
  param([string]$Prompt, [switch]$AsSecureString)
  if (-not $AsSecureString) { throw 'fixture permits only secure credential prompts' }
  $global:prompts++
  $global:fixtureSecure = New-Object Security.SecureString
  $global:fixtureSecure.AppendChar('x')
  return $global:fixtureSecure
}
function New-PSSession {
  [CmdletBinding()]
  param([string]$ComputerName, [int]$Port, [switch]$UseSSL, [PSCredential]$Credential, [string]$Authentication)
  $global:created++
  if ($ComputerName -ne '192.0.2.10' -or $Port -ne %d -or [bool]$UseSSL -ne ($Port -eq 5986) -or $Authentication -ne 'Negotiate' -or $null -eq $Credential) { throw 'invalid connection options' }
  if ($global:scenario -eq 'new-fails') { throw 'fixture connection failure' }
  return $global:fakeSession
}
function Invoke-Command {
  [CmdletBinding()]
  param([object]$Session, [scriptblock]$ScriptBlock, [object[]]$ArgumentList, [string]$ComputerName)
  if ($ComputerName -or -not [object]::ReferenceEquals($Session, $global:fakeSession)) { throw 'operation escaped verified session' }
  $global:invocations++
  if ($global:invocations -eq 1) {
    if ($ScriptBlock.ToString() -notmatch 'whoami') { throw 'identity was not checked first' }
    if ($global:scenario -eq 'identity-fails') { throw 'fixture identity failure' }
    if ($global:scenario -eq 'identity-many') { return @($global:identity, $global:identity) }
    return $global:identity
  }
  $global:commands++
  $global:submitted.Add($ScriptBlock.ToString())
  if ($global:scenario -eq 'transport-fails') { throw 'fixture transport failure' }
  if ($global:scenario -eq 'invalid-result') { return $null }
  if ($global:scenario -eq 'command-error' -and $global:commands -eq 1) { throw 'fixture remote command error' }
  if ($global:scenario -eq 'connection-lost') { $Session.State = 'Broken'; throw 'fixture connection lost' }
  if ($ArgumentList.Count -gt 0) { & $ScriptBlock @ArgumentList }
  # Command-loop text is deliberately not evaluated in the local runspace.
}
function Remove-PSSession {
  [CmdletBinding()]
  param([object]$Session)
  if (-not [object]::ReferenceEquals($Session, $global:fakeSession)) { throw 'cleanup escaped owned session' }
  $global:removed++
  if ($global:scenario -eq 'cleanup-fails') { throw 'fixture cleanup failure' }
}
function Enter-PSSession { throw 'script must not enter an interactive session' }
$fixturePath = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))
$captured = (& $fixturePath | Out-String)
$code = $LASTEXITCODE
$disposed = $false
try { $null = $global:fixtureSecure.Copy() } catch { $disposed = $_.Exception.GetBaseException() -is [ObjectDisposedException] }
$result = [pscustomobject]@{
  Code = $code; Created = $global:created; Commands = $global:commands
  Removed = $global:removed; Prompts = $global:prompts; Disposed = $disposed; Output = $captured
  Lines = @($global:submitted.ToArray())
}
Write-Output ('__RBSESSION__' + ($result | ConvertTo-Json -Compress))
`, scenario, encodeValue(identity), port, encodeValue(path))
	encoded, err := cliutil.EncodePowerShell(harness)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded)
	cmd.Stdin = strings.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("session fixture failed: %v; stdout=%s stderr=%s", err, output, &stderr)
	}
	const marker = "__RBSESSION__"
	index := strings.LastIndex(string(output), marker)
	if index < 0 {
		t.Fatalf("session fixture produced no result: %s", output)
	}
	var got winRMSessionFixtureResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(output)[index+len(marker):])), &got); err != nil {
		t.Fatalf("parse session fixture result: %v; output=%s", err, output)
	}
	return got
}
