//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/platform/windows"
)

func TestSSHHostKeyProtectionScriptBuildsExactProtectedACLInMemory(t *testing.T) {
	root := t.TempDir()
	fixture := filepath.Join(root, "ssh_host_ed25519_key")
	if err := os.WriteFile(fixture, []byte("test fixture only"), 0600); err != nil {
		t.Fatal(err)
	}

	pathLiteral := psSSHString(fixture)
	setup := fmt.Sprintf(`
$script:fixturePath = [IO.Path]::GetFullPath(%s)
$script:setCalls = 0
$script:capturedAcl = $null
$creator = New-Object Security.Principal.SecurityIdentifier('S-1-5-21-1000-2000-3000-1001')
$initial = New-Object Security.AccessControl.FileSecurity
$initial.SetAccessRuleProtection($false, $true)
$initial.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($creator, 'FullControl', 'Allow')))
$script:currentAcl = $initial
function Get-Acl {
    [CmdletBinding()]
    param([string]$Path, [string]$LiteralPath)
    $requested = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ([IO.Path]::GetFullPath($requested) -ine $script:fixturePath) { throw 'Get-Acl rejected non-fixture path' }
    return $script:currentAcl
}
function Set-Acl {
    [CmdletBinding()]
    param([string]$Path, [string]$LiteralPath, [Security.AccessControl.FileSecurity]$AclObject)
    $requested = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ([IO.Path]::GetFullPath($requested) -ine $script:fixturePath) { throw 'Set-Acl rejected non-fixture path' }
    if ($null -eq $AclObject) { throw 'Set-Acl received no FileSecurity object' }
    $script:setCalls++
    $script:capturedAcl = $AclObject
    $script:currentAcl = $AclObject
}
`, pathLiteral)

	observe := `
$acl = Get-Acl -LiteralPath $script:fixturePath
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
    $sid = $_.IdentityReference.Value
    [pscustomobject]@{
        Sid = $sid
        Rights = [string]$_.FileSystemRights
        Inherited = [bool]$_.IsInherited
        Type = [string]$_.AccessControlType
    }
})
$ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
$result = [pscustomobject]@{
    Owner = $ownerSid
    Protected = [bool]$acl.AreAccessRulesProtected
    SetCalls = [int]$script:setCalls
    Rules = $rules
}
Write-Output ('__RBACL__' + (ConvertTo-Json -InputObject $result -Depth 5 -Compress))
`
	command := setup + buildSSHHostKeyProtectionScript(fixture) + observe
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := windows.NewRunner().Run(ctx, windows.PowerShellCommand(command, false))
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("generated ACL script failed: exit=%d err=%v stderr=%q stdout=%q", result.ExitCode, err, result.Stderr, result.Stdout)
	}

	const marker = "__RBACL__"
	index := strings.LastIndex(result.Stdout, marker)
	if index < 0 {
		t.Fatalf("generated ACL script produced no captured ACL result: %q", result.Stdout)
	}
	var got struct {
		Owner     string `json:"Owner"`
		Protected bool   `json:"Protected"`
		SetCalls  int    `json:"SetCalls"`
		Rules     []struct {
			SID       string `json:"Sid"`
			Rights    string `json:"Rights"`
			Inherited bool   `json:"Inherited"`
			Type      string `json:"Type"`
		} `json:"Rules"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout[index+len(marker):])), &got); err != nil {
		t.Fatalf("parse in-memory ACL result: %v; output=%q", err, result.Stdout)
	}
	if got.SetCalls != 1 {
		t.Fatalf("Set-Acl called %d times, want once for the fixture", got.SetCalls)
	}
	if got.Owner != "S-1-5-32-544" || !got.Protected {
		t.Fatalf("owner/protection mismatch: owner=%q protected=%t", got.Owner, got.Protected)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("got %d ACEs, want only SYSTEM and Administrators: %+v", len(got.Rules), got.Rules)
	}
	wantSIDs := map[string]bool{"S-1-5-18": false, "S-1-5-32-544": false}
	for _, rule := range got.Rules {
		if _, ok := wantSIDs[rule.SID]; !ok {
			t.Errorf("unexpected ACE for SID %s (creator ACE should be gone)", rule.SID)
		}
		wantSIDs[rule.SID] = true
		if rule.Rights != "FullControl" || rule.Inherited || rule.Type != "Allow" {
			t.Errorf("unexpected ACE for %s: %+v", rule.SID, rule)
		}
	}
	for sid, seen := range wantSIDs {
		if !seen {
			t.Errorf("missing required ACE for SID %s", sid)
		}
	}
}
