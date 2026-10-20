//go:build windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/platform/windows"
)

// These functions shadow every account/firewall cmdlet, including removal.
// Exercise the generated script in real Windows PowerShell without reading
// or modifying system accounts or rules.
const sshCleanupMocks = `
$scenario = '%s'
function Get-NetFirewallRule {
    [CmdletBinding()] param([string]$DisplayName)
    switch ($scenario) {
        'absent' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('missing rule'), 'CmdletizationQuery_NotFound_DisplayName', [Management.Automation.ErrorCategory]::ObjectNotFound, $DisplayName)) }
        'denied' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('access denied'), 'AccessDenied', [Management.Automation.ErrorCategory]::PermissionDenied, $DisplayName)) }
        'other-missing' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('provider missing'), 'ProviderNotFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $DisplayName)) }
        'foreign' { [pscustomobject]@{Description='different owner'} }
        'mixed' { [pscustomobject]@{Description='fixture marker'}; [pscustomobject]@{Description='different owner'} }
        default { [pscustomobject]@{Description='fixture marker'} }
    }
}
function Remove-NetFirewallRule {
    [CmdletBinding()] param($InputObject)
    if ($scenario -eq 'remove-failed') { throw 'fixture removal failed' }
    Write-Output 'FIXTURE_REMOVED'
}
function Get-LocalUser {
    [CmdletBinding()] param([string]$Name)
    switch ($scenario) {
        'absent' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('missing user'), 'UserNotFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name)) }
        'denied' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('access denied'), 'AccessDenied', [Management.Automation.ErrorCategory]::PermissionDenied, $Name)) }
        'other-missing' { $PSCmdlet.ThrowTerminatingError([Management.Automation.ErrorRecord]::new([Exception]::new('provider missing'), 'ProviderNotFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $Name)) }
        'foreign' { [pscustomobject]@{Description='different owner'} }
        'legacy' { [pscustomobject]@{Description='legacy marker'} }
        default { [pscustomobject]@{Description='fixture marker'} }
    }
}
function Remove-LocalUser {
    [CmdletBinding(SupportsShouldProcess)] param([string]$Name)
    if ($scenario -eq 'remove-failed') { throw 'fixture removal failed' }
    Write-Output 'FIXTURE_REMOVED'
}
`

func TestSSHCleanupScriptsHandleAbsenceAndPreserveRealFailures(t *testing.T) {
	for _, kind := range []string{"firewall", "account"} {
		for _, scenario := range []string{"absent", "owned", "denied", "other-missing", "foreign", "remove-failed", "legacy", "mixed"} {
			if kind == "firewall" && scenario == "legacy" || kind == "account" && scenario == "mixed" {
				continue
			}
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				script := buildSSHFirewallCleanupScript("fixture rule", "fixture marker")
				if kind == "account" {
					script = buildSSHAccountCleanupScript("fixture user", "fixture marker", "legacy marker")
				}
				mocks := strings.Replace(sshCleanupMocks, "%s", scenario, 1)
				// Windows PowerShell cold start and security inspection can
				// exceed 30s on the first process. Keep a bound without making
				// that startup delay look like a cleanup ownership failure.
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				result, err := windows.NewRunner().Run(ctx, windows.PowerShellCommand(mocks+script, true))
				wantFailure := scenario != "absent" && scenario != "owned" && scenario != "legacy"
				if wantFailure {
					if err == nil || result.ExitCode == 0 || strings.TrimSpace(result.Stderr) == "" {
						t.Fatalf("real cleanup failure disappeared: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
					}
				} else if err != nil || result.ExitCode != 0 {
					t.Fatalf("idempotent/owned cleanup failed: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
				}
				removed := strings.Contains(result.Stdout, "FIXTURE_REMOVED")
				if removed != (scenario == "owned" || scenario == "legacy") {
					t.Fatalf("unexpected removal in scenario %s: %q", scenario, result.Stdout)
				}
			})
		}
	}
}
