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
