package windows

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"remote-bridge/internal/discovery"
)

// BuildPlan validates options and creates a complete inspect/apply/revoke
// lifecycle. It never invokes PowerShell or changes the local machine.
func BuildPlan(options PlanOptions) (Plan, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return Plan{}, err
	}

	pl := Plan{
		Version:     1,
		ID:          normalized.ID,
		CreatedAt:   time.Now().UTC(),
		Options:     normalized,
		Inspect:     buildInspectSteps(normalized),
		ApplySteps:  buildApplySteps(normalized),
		RevokeSteps: buildRevokeSteps(normalized),
	}
	pl.Rollback = append([]Action(nil), pl.RevokeSteps...)

	if normalized.Transport == TransportHTTP {
		pl.Warnings = append(pl.Warnings, "WinRM HTTP is selected; use this only on a trusted LAN and prefer HTTPS when a certificate is available")
	}
	if normalized.Transport == TransportHTTPS {
		pl.Warnings = append(pl.Warnings, "HTTPS certificate provisioning and thumbprint verification are operator responsibilities; this plan does not create a certificate")
	}
	if normalized.ConfigureListener {
		pl.Warnings = append(pl.Warnings, "listener preparation may change an existing WinRM policy; review the dry-run and retain the original policy for rollback")
	}
	if normalized.CurrentUser {
		pl.Warnings = append(pl.Warnings, "the plan uses the target wizard's current Windows account; it never creates, resets, or removes that account")
	}
	if isLocalSubnetAddress(normalized.ManagementAddress) {
		pl.Warnings = append(pl.Warnings, "the firewall source is LocalSubnet; any host on the target's local subnet may reach the temporary WinRM endpoint during this experiment")
	} else if _, network, parseErr := net.ParseCIDR(normalized.ManagementAddress); parseErr == nil {
		bits := 128
		if network.IP.To4() != nil {
			bits = 32
		}
		if ones, _ := network.Mask.Size(); ones < bits {
			pl.Warnings = append(pl.Warnings, "the firewall source is a network range; use a single management IP when possible")
		}
	}
	if normalized.EnableDiscovery {
		pl.Warnings = append(pl.Warnings, "LAN discovery is enabled on UDP 37020 for the visible target window; it carries metadata only and is scoped to the plan's firewall source")
	}
	if !normalized.AllowHTTP && normalized.Transport == TransportHTTP {
		pl.Warnings = append(pl.Warnings, "allow_http was not explicitly acknowledged; Apply remains an explicit caller action")
	}
	return pl, nil
}

// BuildInspectSteps returns the read-only portion of a plan. It is useful for
// a CLI that wants to display checks before constructing the full plan.
func BuildInspectSteps(options PlanOptions) ([]Action, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	return buildInspectSteps(normalized), nil
}

// BuildApplySteps returns mutating steps without executing them. Most callers
// should use BuildPlan so that the corresponding revoke and rollback plans are
// retained together.
func BuildApplySteps(options PlanOptions) ([]Action, error) {
	normalized, err := normalizeOptions(options)
	if err != nil {
		return nil, err
	}
	return buildApplySteps(normalized), nil
}

func buildInspectSteps(o NormalizedOptions) []Action {
	steps := []Action{
		newAction("inspect.admin", "check whether the current process is elevated", psCommand(adminCheckScript(), true), true, true),
		newAction("inspect.os", "inspect Windows version and architecture", psCommand(osCheckScript(), true), true, true),
		newAction("inspect.winrm-service", "inspect the WinRM service state", psCommand(serviceCheckScript(), true), true, true),
		newAction("inspect.winrm-listener", "inspect WinRM listeners", psCommand(listenerCheckScript(), true), true, true),
		newAction("inspect.firewall", "inspect the plan-scoped firewall rule", psCommand(firewallCheckScript(o), true), true, true),
		newAction("inspect.firewall-winrm", "inspect all enabled inbound rules for the WinRM ports", psCommand(winRMFirewallCheckScript(o), true), true, true),
		newAction("inspect.account", inspectAccountDescription(o), psCommand(inspectAccountScript(o), true), true, true),
		newAction("inspect.network", "inspect local network profiles", psCommand(networkCheckScript(), true), true, true),
	}
	if o.EnableDiscovery {
		steps = append(steps, newAction("inspect.discovery-firewall", "inspect the plan-scoped UDP discovery firewall rule", psCommand(discoveryFirewallCheckScript(o), true), true, true))
	}
	return steps
}

func buildApplySteps(o NormalizedOptions) []Action {
	steps := []Action{
		newAction("apply.winrm-service", "start WinRM when it is installed but stopped", psCommand(serviceApplyScript(), false), false, true),
	}
	if o.ConfigureListener {
		steps = append(steps, newAction("apply.winrm-listener", "prepare a WinRM listener when none exists", psCommand(listenerApplyScript(o), false), false, true))
	}
	steps = append(steps,
		newAction("apply.firewall", "create a source-restricted WinRM firewall rule", psCommand(firewallApplyScript(o), false), false, true),
	)
	if o.EnableDiscovery {
		steps = append(steps, newAction("apply.discovery-firewall", "create a source-restricted LAN discovery firewall rule", psCommand(discoveryFirewallApplyScript(o), false), false, true))
	}
	if o.CurrentUser {
		steps = append(steps, newAction("apply.current-user", "verify the target wizard's current Windows account", psCommand(currentUserApplyScript(o), false), false, true))
	} else {
		steps = append(steps,
			newAction("apply.account", "create or renew the temporary local maintenance account", psCommand(accountApplyScript(o), false), false, true),
			newAction("apply.account-group", "add the temporary account to Remote Management Users", psCommand(accountGroupApplyScript(o), false), false, true),
		)
	}
	return steps
}

func buildRevokeSteps(o NormalizedOptions) []Action {
	steps := make([]Action, 0, 3)
	if !o.CurrentUser {
		steps = append(steps, newAction("revoke.account", "remove the plan-owned temporary account", psCommand(accountRevokeScript(o), false), false, true))
	}
	if o.EnableDiscovery {
		steps = append(steps, newAction("revoke.discovery-firewall", "remove the plan-owned UDP discovery firewall rule", psCommand(discoveryFirewallRevokeScript(o), false), false, true))
	}
	steps = append(steps,
		newAction("revoke.firewall", "remove the plan-owned WinRM firewall rule", psCommand(firewallRevokeScript(o), false), false, true),
	)
	return steps
}

func newAction(id, description string, command Command, readOnly, idempotent bool) Action {
	command.ReadOnly = readOnly
	return Action{ID: id, Description: description, Command: command, ReadOnly: readOnly, Idempotent: idempotent}
}

func psCommand(script string, readOnly bool) Command {
	return Command{
		Program:  "powershell.exe",
		Args:     []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", utf8OutputPrefix + script},
		ReadOnly: readOnly,
	}
}

// Windows PowerShell otherwise uses the active console code page for redirected
// output. The Go runner captures bytes directly, so force UTF-8 before emitting
// JSON or diagnostics to avoid mojibake on Chinese Windows installations.
const utf8OutputPrefix = "$OutputEncoding = [Text.Encoding]::UTF8; [Console]::OutputEncoding = [Text.Encoding]::UTF8; "

func psQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func adminCheckScript() string {
	return `$ErrorActionPreference = 'Stop'; $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); [pscustomobject]@{ is_admin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } | ConvertTo-Json -Compress`
}

func osCheckScript() string {
	return `$ErrorActionPreference = 'Stop'; Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress`
}

func serviceCheckScript() string {
	return `$ErrorActionPreference = 'Stop'; $s = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue; $result = if ($null -eq $s) { [pscustomobject]@{ present = $false } } else { [pscustomobject]@{ present = $true; status = [string]$s.Status; start_type = [string]$s.StartType } }; $result | ConvertTo-Json -Compress`
}

func listenerCheckScript() string {
	return `$ErrorActionPreference = 'Stop'; try { $l = @(Get-WSManInstance -ResourceURI 'winrm/config/listener' -Enumerate -ErrorAction Stop); if ($l.Count -eq 0) { [pscustomobject]@{ present = $false } | ConvertTo-Json -Compress } else { $l | Select-Object Address,Enabled,Hostname,Port,Protocol,URLPrefix | ConvertTo-Json -Compress } } catch { [pscustomobject]@{ present = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress; exit 1 }`
}

func networkCheckScript() string {
	return `$ErrorActionPreference = 'Stop'; Get-NetConnectionProfile -ErrorAction SilentlyContinue | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity | ConvertTo-Json -Compress`
}

func firewallCheckScript(o NormalizedOptions) string {
	rule := psQuote(o.FirewallRule)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $r = Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue; $result = if ($null -eq $r) { [pscustomobject]@{ present = $false } } else { $r | Select-Object DisplayName,Enabled,Profile,Direction,Action,Group,Description }; $result | ConvertTo-Json -Compress`, rule)
}

func discoveryFirewallRuleName(o NormalizedOptions) string {
	return "RemoteBridge-" + o.ID + "-Discovery"
}

func discoveryFirewallMarker(o NormalizedOptions) string {
	return "Remote Bridge discovery plan " + o.ID
}

func discoveryFirewallCheckScript(o NormalizedOptions) string {
	rule := psQuote(discoveryFirewallRuleName(o))
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $r = Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue; $result = if ($null -eq $r) { [pscustomobject]@{ present = $false } } else { $r | Select-Object DisplayName,Enabled,Profile,Direction,Action,Group,Description }; $result | ConvertTo-Json -Compress`, rule)
}

func discoveryFirewallApplyScript(o NormalizedOptions) string {
	rule := psQuote(discoveryFirewallRuleName(o))
	group := psQuote(o.FirewallGroup)
	address := psQuote(o.ManagementAddress)
	profile := psQuote(o.FirewallProfile)
	marker := psQuote(discoveryFirewallMarker(o))
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $rules = @(Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue); if ($rules.Count -eq 0) { New-NetFirewallRule -DisplayName %s -Group %s -Description %s -Direction Inbound -Action Allow -Protocol UDP -LocalPort %d -RemoteAddress %s -Profile (%s -split ',') | Out-Null } else { $owned = @($rules | Where-Object { $_.Description -eq %s }); $unowned = @($rules | Where-Object { $_.Description -ne %s }); if ($unowned.Count -gt 0) { throw 'a discovery firewall rule with the plan name already exists and at least one same-name rule is not owned by this plan' }; if ($owned.Count -ne 1) { throw 'expected exactly one discovery firewall rule owned by this plan' }; $r = $owned[0]; $pf = $r | Get-NetFirewallPortFilter -ErrorAction Stop; $af = $r | Get-NetFirewallAddressFilter -ErrorAction Stop; $remote = @($af.RemoteAddress | ForEach-Object { [string]$_ }); $expectedRemote = %s; $expectedProfiles = @(%s -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object); $actualProfiles = @([string]$r.Profile -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object); if ([string]$r.Enabled -ne 'True' -or [string]$r.Direction -ne 'Inbound' -or [string]$r.Action -ne 'Allow' -or [string]$r.Group -ne %s -or [string]$pf.Protocol -ne 'UDP' -or [string]$pf.LocalPort -ne '%d' -or $remote.Count -ne 1 -or $remote[0] -ine $expectedRemote -or ($expectedProfiles -join ',') -ne ($actualProfiles -join ',')) { throw 'the owned discovery firewall rule no longer matches this plan; it was left untouched' } }; [pscustomobject]@{ present = $true; display_name = %s; local_port = %d; protocol = 'UDP' } | ConvertTo-Json -Compress`, rule, rule, group, marker, discovery.DefaultPort, address, profile, marker, marker, address, profile, group, discovery.DefaultPort, rule, discovery.DefaultPort)
}

func discoveryFirewallRevokeScript(o NormalizedOptions) string {
	// SilentlyContinue does not reliably suppress terminating provider errors.
	// Only the exact missing-rule result is a successful repeated cleanup.
	rule := psQuote(discoveryFirewallRuleName(o))
	marker := psQuote(discoveryFirewallMarker(o))
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $rules = @(); try { $rules = @(Get-NetFirewallRule -DisplayName %s -ErrorAction Stop) } catch { if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or ([string]$_.FullyQualifiedErrorId -split ',')[0] -ne 'CmdletizationQuery_NotFound_DisplayName') { throw } }; if ($rules.Count -eq 0) { [pscustomobject]@{ removed = $false; reason = 'already absent' } | ConvertTo-Json -Compress } else { $owned = @($rules | Where-Object { $_.Description -eq %s }); $unowned = @($rules | Where-Object { $_.Description -ne %s }); if ($unowned.Count -gt 0) { throw 'at least one same-name discovery firewall rule is not owned by this plan; no rule was removed' }; foreach ($r in $owned) { Remove-NetFirewallRule -InputObject $r -ErrorAction Stop }; [pscustomobject]@{ removed = $true; count = $owned.Count; display_name = %s } | ConvertTo-Json -Compress }`, rule, marker, marker, rule)
}

func winRMFirewallCheckScript(o NormalizedOptions) string {
	// This is intentionally read-only and reports rules outside the plan. The
	// apply path never disables or rewrites them, because doing so could alter
	// an administrator's existing policy.
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $ports = %d,%d; $rules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue; $out = foreach ($r in $rules) { $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; $number = 0; if ($null -ne $pf -and $pf.Protocol -eq 'TCP' -and [int]::TryParse([string]$pf.LocalPort, [ref]$number) -and ($ports -contains $number)) { $af = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; [pscustomobject]@{ display_name = $r.DisplayName; group = $r.Group; profile = [string]$r.Profile; local_port = [string]$pf.LocalPort; remote_address = [string]$af.RemoteAddress; description = $r.Description } } }; @($out) | ConvertTo-Json -Compress`, DefaultHTTPPort, DefaultHTTPSPort)
}

func inspectAccountDescription(o NormalizedOptions) string {
	if o.CurrentUser {
		return "inspect the current Windows account used for WinRM"
	}
	return "inspect the plan-scoped temporary account"
}

func inspectAccountScript(o NormalizedOptions) string {
	if o.CurrentUser {
		return currentUserCheckScript(o)
	}
	return accountCheckScript(o)
}

func currentUserCheckScript(o NormalizedOptions) string {
	principal := psQuote(o.CurrentUserPrincipal)
	sid := psQuote(o.CurrentUserSID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $name = [string]$id.Name; $sid = [string]$id.User.Value; $expected = %s; $expectedSid = %s; [pscustomobject]@{ present = $true; current_user = $name; sid = $sid; principal_matches = ($name -ieq $expected); sid_matches = ([string]::IsNullOrWhiteSpace($expectedSid) -or $sid -eq $expectedSid) } | ConvertTo-Json -Compress`, principal, sid)
}

func currentUserApplyScript(o NormalizedOptions) string {
	principal := psQuote(o.CurrentUserPrincipal)
	sid := psQuote(o.CurrentUserSID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $id = [Security.Principal.WindowsIdentity]::GetCurrent(); $name = [string]$id.Name; $sid = [string]$id.User.Value; $expected = %s; $expectedSid = %s; if ($name -ine $expected) { throw "the elevated process identity does not match the target interactive account: $name" }; if (-not [string]::IsNullOrWhiteSpace($expectedSid) -and $sid -ne $expectedSid) { throw "the elevated process SID does not match the target interactive account: $sid" }; [pscustomobject]@{ current_user = $name; sid = $sid; verified = $true } | ConvertTo-Json -Compress`, principal, sid)
}

func accountCheckScript(o NormalizedOptions) string {
	user := psQuote(o.TemporaryUser)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $u = Get-LocalUser -Name %s -ErrorAction SilentlyContinue; $result = if ($null -eq $u) { [pscustomobject]@{ present = $false } } else { $u | Select-Object Name,Enabled,AccountExpires,PasswordExpires,Description }; $result | ConvertTo-Json -Compress`, user)
}

func serviceApplyScript() string {
	return `$ErrorActionPreference = 'Stop'; $s = Get-Service -Name 'WinRM' -ErrorAction Stop; if ($s.StartType -eq 'Disabled') { throw 'WinRM is disabled; enable it after reviewing local policy' }; if ($s.Status -ne 'Running') { Start-Service -Name 'WinRM' }; [pscustomobject]@{ status = [string](Get-Service -Name 'WinRM').Status } | ConvertTo-Json -Compress`
}

func listenerApplyScript(o NormalizedOptions) string {
	if o.Transport == TransportHTTPS {
		return `$ErrorActionPreference = 'Stop'; throw 'an HTTPS WinRM listener requires an operator-provisioned certificate; this plan will not create one'`
	}
	return `$ErrorActionPreference = 'Stop'; $l = @(Get-WSManInstance -ResourceURI 'winrm/config/listener' -Enumerate -ErrorAction SilentlyContinue); if ($l.Count -eq 0) { & winrm quickconfig -quiet; if ($LASTEXITCODE -ne 0) { throw "winrm quickconfig failed with exit code $LASTEXITCODE" } }; [pscustomobject]@{ prepared = $true } | ConvertTo-Json -Compress`
}

func firewallApplyScript(o NormalizedOptions) string {
	rule := psQuote(o.FirewallRule)
	group := psQuote(o.FirewallGroup)
	address := psQuote(o.ManagementAddress)
	profile := psQuote(o.FirewallProfile)
	marker := psQuote("Remote Bridge plan " + o.ID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $rules = @(Get-NetFirewallRule -DisplayName %s -ErrorAction SilentlyContinue); if ($rules.Count -eq 0) { New-NetFirewallRule -DisplayName %s -Group %s -Description %s -Direction Inbound -Action Allow -Protocol TCP -LocalPort %d -RemoteAddress %s -Profile (%s -split ',') | Out-Null } else { $owned = @($rules | Where-Object { $_.Description -eq %s }); $unowned = @($rules | Where-Object { $_.Description -ne %s }); if ($unowned.Count -gt 0) { throw 'a firewall rule with the plan name already exists and at least one same-name rule is not owned by this plan' }; if ($owned.Count -ne 1) { throw 'expected exactly one firewall rule owned by this plan' }; $r = $owned[0]; $pf = $r | Get-NetFirewallPortFilter -ErrorAction Stop; $af = $r | Get-NetFirewallAddressFilter -ErrorAction Stop; $remote = @($af.RemoteAddress | ForEach-Object { [string]$_ }); $expectedRemote = %s; $expectedProfiles = @(%s -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object); $actualProfiles = @([string]$r.Profile -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Sort-Object); if ([string]$r.Enabled -ne 'True' -or [string]$r.Direction -ne 'Inbound' -or [string]$r.Action -ne 'Allow' -or [string]$r.Group -ne %s -or [string]$pf.Protocol -ne 'TCP' -or [string]$pf.LocalPort -ne '%d' -or $remote.Count -ne 1 -or $remote[0] -ine $expectedRemote -or ($expectedProfiles -join ',') -ne ($actualProfiles -join ',')) { throw 'the owned firewall rule no longer matches this plan; it was left untouched' } }; [pscustomobject]@{ present = $true; display_name = %s } | ConvertTo-Json -Compress`, rule, rule, group, marker, o.Port, address, profile, marker, marker, address, profile, group, o.Port, rule)
}

func accountApplyScript(o NormalizedOptions) string {
	user := psQuote(o.TemporaryUser)
	marker := psQuote("Remote Bridge temporary account " + o.ID)
	ownerPrefix := psQuote("Remote Bridge temporary account ")
	env := psQuote(o.PasswordEnv)
	// AccountTTL is converted to seconds before interpolation so the generated
	// script does not rely on locale-specific PowerShell duration parsing.
	seconds := int64(o.AccountTTL / time.Second)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $name = %s; $marker = %s; $ownerPrefix = %s; $raw = [Environment]::GetEnvironmentVariable(%s); if ([string]::IsNullOrWhiteSpace($raw)) { throw 'the temporary account password environment variable is missing' }; $secure = ConvertTo-SecureString $raw -AsPlainText -Force; $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue; if ($null -eq $u) { New-LocalUser -Name $name -Password $secure -Description $marker -AccountExpires (Get-Date).AddSeconds(%d) -PasswordNeverExpires:$false -UserMayNotChangePassword:$true | Out-Null } elseif (-not ([string]$u.Description).StartsWith($ownerPrefix, [System.StringComparison]::Ordinal)) { throw 'a local account with the fixed name already exists and is not owned by Remote Bridge' } else { if (-not $u.Enabled) { Enable-LocalUser -Name $name }; Set-LocalUser -Name $name -Password $secure -AccountExpires (Get-Date).AddSeconds(%d) -Description $marker }; [pscustomobject]@{ name = $name; expires = (Get-LocalUser -Name $name).AccountExpires } | ConvertTo-Json -Compress`, user, marker, ownerPrefix, env, seconds, seconds)
}

func accountGroupApplyScript(o NormalizedOptions) string {
	user := psQuote(o.TemporaryUser)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $u = Get-LocalUser -Name %s -ErrorAction Stop; $sid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-580'); $group = Get-LocalGroup -SID $sid -ErrorAction Stop; $members = @(Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue); if (-not ($members | Where-Object { $_.SID -eq $u.SID })) { Add-LocalGroupMember -Group $group.Name -Member $u.Name }; [pscustomobject]@{ name = $u.Name; group = $group.Name; group_sid = [string]$group.SID } | ConvertTo-Json -Compress`, user)
}

func accountRevokeScript(o NormalizedOptions) string {
	user := psQuote(o.TemporaryUser)
	marker := psQuote("Remote Bridge temporary account " + o.ID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $u = $null; try { $u = Get-LocalUser -Name %s -ErrorAction Stop } catch { if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or ([string]$_.FullyQualifiedErrorId -split ',')[0] -ne 'UserNotFound') { throw } }; if ($null -eq $u) { [pscustomobject]@{ removed = $false; reason = 'already absent' } | ConvertTo-Json -Compress } elseif ($u.Description -eq %s) { Remove-LocalUser -Name %s -Confirm:$false -ErrorAction Stop; [pscustomobject]@{ removed = $true; name = %s } | ConvertTo-Json -Compress } else { throw 'the account exists but is not owned by this plan; it was left untouched' }`, user, marker, user, user)
}

func firewallRevokeScript(o NormalizedOptions) string {
	rule := psQuote(o.FirewallRule)
	marker := psQuote("Remote Bridge plan " + o.ID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $rules = @(); try { $rules = @(Get-NetFirewallRule -DisplayName %s -ErrorAction Stop) } catch { if ($_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ObjectNotFound -or ([string]$_.FullyQualifiedErrorId -split ',')[0] -ne 'CmdletizationQuery_NotFound_DisplayName') { throw } }; if ($rules.Count -eq 0) { [pscustomobject]@{ removed = $false; reason = 'already absent' } | ConvertTo-Json -Compress } else { $owned = @($rules | Where-Object { $_.Description -eq %s }); $unowned = @($rules | Where-Object { $_.Description -ne %s }); if ($unowned.Count -gt 0) { throw 'at least one same-name firewall rule is not owned by this plan; no rule was removed' }; foreach ($r in $owned) { Remove-NetFirewallRule -InputObject $r -ErrorAction Stop }; [pscustomobject]@{ removed = $true; count = $owned.Count; display_name = %s } | ConvertTo-Json -Compress }`, rule, marker, marker, rule)
}

// Inspect runs only actions marked ReadOnly. The report is returned even if
// one check fails; the error summarizes the first failure for a CLI exit code.
func Inspect(ctx context.Context, runner Runner, options PlanOptions) (InspectionReport, error) {
	pl, err := BuildPlan(options)
	if err != nil {
		return InspectionReport{}, err
	}
	if runner == nil {
		return InspectionReport{}, ErrNoRunner
	}
	started := time.Now().UTC()
	report := InspectionReport{PlanID: pl.ID, StartedAt: started, Supported: true, Steps: make([]StepResult, 0, len(pl.Inspect)), Warnings: append([]string(nil), pl.Warnings...)}
	var firstErr error
	for _, action := range pl.Inspect {
		if !action.ReadOnly || !action.Command.ReadOnly {
			continue
		}
		result, runErr := runner.Run(ctx, action.Command)
		step := StepResult{ActionID: action.ID, Description: action.Description, Result: result}
		if runErr != nil {
			step.Error = runErr.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", action.ID, runErr)
			}
		}
		report.Steps = append(report.Steps, step)
	}
	report.EndedAt = time.Now().UTC()
	if firstErr != nil && isUnsupported(firstErr) {
		report.Supported = false
	}
	return report, firstErr
}

func isUnsupported(err error) bool {
	for err != nil {
		if err == ErrUnsupported {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Apply explicitly executes mutating apply steps. BuildPlan does not invoke
// this function and therefore cannot modify the target by itself.
func Apply(ctx context.Context, runner Runner, plan Plan) (ExecutionReport, error) {
	return execute(ctx, runner, plan, "apply", plan.ApplySteps, false)
}

// Revoke explicitly removes only resources marked as owned by the plan. It is
// safe to call more than once.
func Revoke(ctx context.Context, runner Runner, plan Plan) (ExecutionReport, error) {
	return execute(ctx, runner, plan, "revoke", plan.RevokeSteps, true)
}

// Rollback is the idempotent cleanup operation for a partially applied plan.
// It intentionally uses the same ownership checks as Revoke and never stops a
// pre-existing WinRM service or removes an unowned firewall rule/account.
func Rollback(ctx context.Context, runner Runner, plan Plan) (ExecutionReport, error) {
	return execute(ctx, runner, plan, "rollback", plan.Rollback, true)
}

func execute(ctx context.Context, runner Runner, plan Plan, operation string, actions []Action, continueOnError bool) (ExecutionReport, error) {
	started := time.Now().UTC()
	report := ExecutionReport{PlanID: plan.ID, Operation: operation, StartedAt: started, Steps: make([]StepResult, 0, len(actions))}
	if runner == nil {
		report.EndedAt = time.Now().UTC()
		return report, ErrNoRunner
	}
	if strings.TrimSpace(plan.ID) == "" {
		report.EndedAt = time.Now().UTC()
		return report, fmt.Errorf("%w: plan id is required", ErrInvalidOptions)
	}
	if plan.Version != 1 {
		report.EndedAt = time.Now().UTC()
		return report, fmt.Errorf("%w: unsupported plan version %d", ErrInvalidOptions, plan.Version)
	}
	if operation == "apply" && plan.Options.Transport == TransportHTTP && !plan.Options.AllowHTTP {
		report.EndedAt = time.Now().UTC()
		return report, fmt.Errorf("%w: applying WinRM HTTP requires AllowHTTP=true", ErrInvalidOptions)
	}
	var firstErr error
	for _, action := range actions {
		// Mutating execution is only reachable through this function. A malformed
		// hand-built plan cannot silently run a read-only command as a mutation,
		// regardless of whether the cleanup operation is revoke or rollback.
		if action.ReadOnly || action.Command.ReadOnly {
			continue
		}
		result, runErr := runner.Run(ctx, action.Command)
		step := StepResult{ActionID: action.ID, Description: action.Description, Result: result}
		if runErr != nil {
			step.Error = runErr.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", action.ID, runErr)
			}
		}
		report.Steps = append(report.Steps, step)
		if runErr != nil && !continueOnError {
			break
		}
	}
	report.EndedAt = time.Now().UTC()
	return report, firstErr
}

// PortForTransport exposes the standard port selection used by BuildPlan.
func PortForTransport(transport Transport) int {
	if transport == TransportHTTPS {
		return DefaultHTTPSPort
	}
	return DefaultHTTPPort
}

// PowerShellCommand is exported for callers that need to display or audit a
// command without constructing a complete plan. It never executes anything.
func PowerShellCommand(script string, readOnly bool) Command {
	return psCommand(script, readOnly)
}

// FormatDurationSeconds is kept small and deterministic for consumers that
// need to display the TTL used by generated PowerShell commands.
func FormatDurationSeconds(duration time.Duration) string {
	return strconv.FormatInt(int64(duration/time.Second), 10)
}
