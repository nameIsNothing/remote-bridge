package main

import "fmt"

// A missing named resource raises ObjectNotFound in Windows PowerShell. Only
// the exact lookup error is an idempotent success; permission/provider errors
// must remain failures. End with a successful metadata command so a handled
// absence cannot leak its previous $? into powershell.exe's process exit code.
func buildSSHFirewallCleanupScript(name, marker string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$rules = @()
try { $rules = @(Get-NetFirewallRule -DisplayName %s -ErrorAction Stop) }
catch {
    if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or ([string]$_.FullyQualifiedErrorId -split ',')[0] -ne 'CmdletizationQuery_NotFound_DisplayName') { throw }
}
$foreign = @($rules | Where-Object { [string]$_.Description -ne %s })
if ($foreign.Count -gt 0) { throw 'firewall rule ownership changed; no rule was removed' }
foreach ($rule in $rules) { Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop }
[pscustomobject]@{ removed = $rules.Count } | ConvertTo-Json -Compress`, psSSHString(name), psSSHString(marker))
}

func buildSSHAccountCleanupScript(username, marker, legacyMarker string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$user = $null
try { $user = Get-LocalUser -Name %s -ErrorAction Stop }
catch {
    if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or ([string]$_.FullyQualifiedErrorId -split ',')[0] -ne 'UserNotFound') { throw }
}
if ($null -ne $user) {
    if ([string]$user.Description -ne %s -and [string]$user.Description -ne %s) { throw 'account ownership changed; no account was removed' }
    Remove-LocalUser -Name %s -Confirm:$false -ErrorAction Stop
}
[pscustomobject]@{ removed = ($null -ne $user) } | ConvertTo-Json -Compress`, psSSHString(username), psSSHString(marker), psSSHString(legacyMarker), psSSHString(username))
}
