//go:build windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"remote-bridge/internal/platform/windows"
)

// Run the actual WinRM revoke scripts with every account/firewall cmdlet
// shadowed by the existing in-memory fixtures. No system rules are changed.
func TestWinRMRevokeHandlesAbsentRulesAndPreservesFailures(t *testing.T) {
	plan, err := windows.BuildPlan(windows.PlanOptions{
		ID: "cleanup-fixture", ManagementAddress: windows.LocalSubnet,
		AllowHTTP: true, EnableDiscovery: true, CurrentUser: true,
		CurrentUserPrincipal: `TEST\fixture`, CurrentUserSID: "S-1-5-21-1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range plan.RevokeSteps {
		if action.ID == "revoke.account" {
			t.Fatal("current-account cleanup must never remove an account")
		}
		if action.ID == "revoke.current-user-group" {
			// Marker-gated group cleanup uses different cmdlets than the shared
			// firewall/account mocks shadow; it has its own fixture test below.
			continue
		}
		marker := "Remote Bridge plan " + plan.ID
		if action.ID == "revoke.discovery-firewall" {
			marker = "Remote Bridge discovery plan " + plan.ID
		}
		for _, scenario := range []string{"absent", "owned", "denied", "other-missing", "foreign", "mixed", "remove-failed"} {
			t.Run(action.ID+"/"+scenario, func(t *testing.T) {
				mocks := strings.Replace(sshCleanupMocks, "%s", scenario, 1)
				mocks = strings.ReplaceAll(mocks, "fixture marker", marker)
				command := action.Command
				command.Args = append([]string(nil), action.Command.Args...)
				command.Args[len(command.Args)-1] = mocks + command.Args[len(command.Args)-1]
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer cancel()
				result, err := windows.NewRunner().Run(ctx, command)
				wantFailure := scenario != "absent" && scenario != "owned"
				if wantFailure {
					if err == nil || result.ExitCode == 0 || strings.TrimSpace(result.Stderr) == "" {
						t.Fatalf("cleanup failure hidden: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
					}
				} else if err != nil || result.ExitCode != 0 {
					t.Fatalf("idempotent cleanup failed: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
				}
				if removed := strings.Contains(result.Stdout, "FIXTURE_REMOVED"); removed != (scenario == "owned") {
					t.Fatalf("unexpected deletion in %s: %q", scenario, result.Stdout)
				}
			})
		}
	}
}

func TestWinRMTemporaryAccountRevokeHandlesAbsenceAndPreservesFailures(t *testing.T) {
	plan, err := windows.BuildPlan(windows.PlanOptions{ID: "cleanup-fixture", ManagementAddress: windows.LocalSubnet, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var command windows.Command
	for _, action := range plan.RevokeSteps {
		if action.ID == "revoke.account" {
			command = action.Command
		}
	}
	if command.Program == "" {
		t.Fatal("temporary account revoke step missing")
	}
	for _, scenario := range []string{"absent", "owned", "denied", "other-missing", "foreign", "remove-failed"} {
		t.Run(scenario, func(t *testing.T) {
			mocks := strings.Replace(sshCleanupMocks, "%s", scenario, 1)
			mocks = strings.ReplaceAll(mocks, "fixture marker", "Remote Bridge temporary account "+plan.ID)
			fixtureCommand := command
			fixtureCommand.Args = append([]string(nil), command.Args...)
			fixtureCommand.Args[len(fixtureCommand.Args)-1] = mocks + command.Args[len(command.Args)-1]
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			result, err := windows.NewRunner().Run(ctx, fixtureCommand)
			wantFailure := scenario != "absent" && scenario != "owned"
			if wantFailure {
				if err == nil || result.ExitCode == 0 || strings.TrimSpace(result.Stderr) == "" {
					t.Fatalf("account cleanup failure hidden: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
				}
			} else if err != nil || result.ExitCode != 0 {
				t.Fatalf("idempotent account cleanup failed: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
			}
			if removed := strings.Contains(result.Stdout, "FIXTURE_REMOVED"); removed != (scenario == "owned") {
				t.Fatalf("unexpected account deletion in %s: %q", scenario, result.Stdout)
			}
		})
	}
}

// These functions shadow the marker and group cmdlets used by the current-user
// WinRM grant cleanup. No system group membership or file is read or changed.
const winrmGroupRevokeMocks = `
$scenario = '%s'
function Test-Path { [CmdletBinding()] param([string]$LiteralPath) return ($scenario -ne 'absent') }
function Get-Content { [CmdletBinding()] param([string]$LiteralPath,[switch]$Raw) if ($scenario -eq 'mismatch') { '{"sid":"S-1-5-21-9999","principal":"OTHER"}' } else { '{"sid":"S-1-5-21-1000","principal":"TEST\\fixture"}' } }
function Get-LocalGroup { [CmdletBinding()] param($SID) [pscustomobject]@{ Name = 'Remote Management Users'; SID = $SID } }
function Get-LocalGroupMember { [CmdletBinding()] param([string]$Group) [pscustomobject]@{ SID = 'S-1-5-21-1000' } }
function Remove-LocalGroupMember { [CmdletBinding()] param([string]$Group,$Member) if ($scenario -eq 'remove-failed') { throw 'fixture removal failed' }; Write-Output 'FIXTURE_REMOVED' }
function Remove-Item { [CmdletBinding()] param([string]$LiteralPath,[switch]$Force) }
`

// TestCurrentUserGroupRevokeIsMarkerOwned verifies the current-user WinRM grant
// cleanup removes membership only when a matching plan-owned marker exists,
// never removes a mismatched grant, and preserves real removal failures.
func TestCurrentUserGroupRevokeIsMarkerOwned(t *testing.T) {
	plan, err := windows.BuildPlan(windows.PlanOptions{
		ID: "cleanup-fixture", ManagementAddress: windows.LocalSubnet, AllowHTTP: true,
		CurrentUser: true, CurrentUserPrincipal: `TEST\fixture`, CurrentUserSID: "S-1-5-21-1000",
	})
	if err != nil {
		t.Fatal(err)
	}
	var command windows.Command
	for _, action := range plan.RevokeSteps {
		if action.ID == "revoke.current-user-group" {
			command = action.Command
		}
	}
	if command.Program == "" {
		t.Fatal("current-user group revoke step missing")
	}
	for _, scenario := range []string{"absent", "owned", "mismatch", "remove-failed"} {
		t.Run(scenario, func(t *testing.T) {
			mocks := strings.Replace(winrmGroupRevokeMocks, "%s", scenario, 1)
			fixture := command
			fixture.Args = append([]string(nil), command.Args...)
			fixture.Args[len(fixture.Args)-1] = mocks + command.Args[len(command.Args)-1]
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			result, err := windows.NewRunner().Run(ctx, fixture)
			wantFailure := scenario == "mismatch" || scenario == "remove-failed"
			if wantFailure {
				if err == nil || result.ExitCode == 0 || strings.TrimSpace(result.Stderr) == "" {
					t.Fatalf("group revoke failure hidden: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
				}
			} else if err != nil || result.ExitCode != 0 {
				t.Fatalf("idempotent group revoke failed: exit=%d err=%v stderr=%q", result.ExitCode, err, result.Stderr)
			}
			if removed := strings.Contains(result.Stdout, "FIXTURE_REMOVED"); removed != (scenario == "owned") {
				t.Fatalf("unexpected membership removal in %s: %q", scenario, result.Stdout)
			}
		})
	}
}
