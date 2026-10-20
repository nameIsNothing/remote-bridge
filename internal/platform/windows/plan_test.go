package windows

import (
	"context"
	"strings"
	"testing"

	"remote-bridge/internal/discovery"
)

type recordingRunner struct {
	commands []Command
	err      error
}

func (r *recordingRunner) Run(_ context.Context, command Command) (Result, error) {
	r.commands = append(r.commands, command)
	return Result{ExitCode: 0}, r.err
}

func TestBuildPlanDoesNotExecuteCommands(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "test-plan", ManagementAddress: "192.168.1.10", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.ID != "test-plan" {
		t.Fatalf("plan id = %q", plan.ID)
	}
	if len(plan.ApplySteps) == 0 || len(plan.RevokeSteps) == 0 || len(plan.Rollback) == 0 {
		t.Fatal("expected apply, revoke, and rollback steps")
	}
	for _, action := range plan.ApplySteps {
		if action.ReadOnly || action.Command.ReadOnly {
			t.Fatalf("apply action %q unexpectedly read-only", action.ID)
		}
	}
	for _, action := range plan.Inspect {
		if !action.ReadOnly || !action.Command.ReadOnly {
			t.Fatalf("inspect action %q unexpectedly mutating", action.ID)
		}
	}
}

func TestApplyIsExplicitAndRunsOnlyApplySteps(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "apply-test", ManagementAddress: "10.0.0.8", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	if _, err := Apply(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != len(plan.ApplySteps) {
		t.Fatalf("executed %d commands, want %d", len(runner.commands), len(plan.ApplySteps))
	}
	for _, command := range runner.commands {
		if command.ReadOnly {
			t.Fatal("Apply executed a read-only command")
		}
	}
}

func TestApplyRequiresExplicitHTTPAcknowledgement(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "http-ack", ManagementAddress: "10.0.0.8"})
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	if _, err := Apply(context.Background(), runner, plan); err == nil {
		t.Fatal("expected HTTP acknowledgement to be required")
	}
	if len(runner.commands) != 0 {
		t.Fatal("Apply executed commands before HTTP acknowledgement")
	}
}

func TestRevokeIsIdempotentAtPlanLevel(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "revoke-test", ManagementAddress: "10.0.0.8", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	if _, err := Revoke(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := Revoke(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 2*len(plan.RevokeSteps) {
		t.Fatalf("executed %d commands after two revokes, want %d", len(runner.commands), 2*len(plan.RevokeSteps))
	}
}

func TestPasswordDoesNotAppearInPlan(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "secret-test", ManagementAddress: "10.0.0.8", PasswordEnv: "RB_PASSWORD", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range plan.ApplySteps {
		if strings.Contains(action.Command.String(), "RB_PASSWORD_VALUE") {
			t.Fatal("plan unexpectedly contains a password value")
		}
	}
	var accountScript string
	for _, action := range plan.ApplySteps {
		if action.ID == "apply.account" {
			accountScript = action.Command.String()
		}
	}
	if !strings.Contains(accountScript, "Set-LocalUser -Name $name -Password $secure") {
		t.Fatal("owned account re-apply does not rotate its temporary password")
	}
	if !strings.Contains(accountScript, "StartsWith($ownerPrefix") || !strings.Contains(accountScript, "-Description $marker") {
		t.Fatal("fixed account re-apply does not recognize and refresh a prior Remote Bridge-owned account")
	}
}

func TestDefaultTemporaryUserIsStable(t *testing.T) {
	first, err := BuildPlan(PlanOptions{ID: "stable-one", ManagementAddress: "10.0.0.8", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildPlan(PlanOptions{ID: "stable-two", ManagementAddress: "10.0.0.8", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if first.Options.TemporaryUser != DefaultTemporaryUser || second.Options.TemporaryUser != DefaultTemporaryUser {
		t.Fatalf("default temporary users = %q and %q, want %q", first.Options.TemporaryUser, second.Options.TemporaryUser, DefaultTemporaryUser)
	}
	if first.Options.TemporaryUser != second.Options.TemporaryUser {
		t.Fatal("default temporary user changed with plan ID")
	}
}

func TestValidateRejectsUnsafeAddressAndPort(t *testing.T) {
	if _, err := BuildPlan(PlanOptions{ID: "bad-address", ManagementAddress: "0.0.0.0"}); err == nil {
		t.Fatal("expected unspecified address to be rejected")
	}
	if _, err := BuildPlan(PlanOptions{ID: "bad-port", ManagementAddress: "192.168.1.10", Port: 22}); err == nil {
		t.Fatal("expected non-WinRM port to be rejected")
	}
	if _, err := BuildPlan(PlanOptions{ID: "bad-address-token", ManagementAddress: "Any"}); err == nil {
		t.Fatal("expected unrestricted Any address token to be rejected")
	}
}

func TestLocalSubnetAddressIsExplicitAndCaseInsensitive(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "local-subnet", ManagementAddress: " localsubnet ", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Options.ManagementAddress != LocalSubnet {
		t.Fatalf("management address = %q, want %q", plan.Options.ManagementAddress, LocalSubnet)
	}
	var applyScript string
	for _, action := range plan.ApplySteps {
		if action.ID == "apply.firewall" {
			applyScript = action.Command.String()
			break
		}
	}
	if !strings.Contains(applyScript, "-RemoteAddress 'LocalSubnet'") {
		t.Fatalf("firewall script does not use the LocalSubnet token: %s", applyScript)
	}
	if strings.Contains(applyScript, "-RemoteAddress 'Any'") {
		t.Fatal("firewall script unexpectedly uses unrestricted Any")
	}
	if !strings.Contains(applyScript, "$remote[0] -ine $expectedRemote") {
		t.Fatal("firewall idempotence check is not case-insensitive for LocalSubnet")
	}
	var warned bool
	for _, warning := range plan.Warnings {
		if strings.Contains(warning, "LocalSubnet") {
			warned = true
			break
		}
	}
	if !warned {
		t.Fatal("LocalSubnet plan does not warn about its LAN-wide scope")
	}
}

func TestFirewallCommandsHandleDuplicateDisplayNamesSafely(t *testing.T) {
	plan, err := BuildPlan(PlanOptions{ID: "firewall-duplicates", ManagementAddress: "192.168.1.10", AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	var applyScript, revokeScript string
	for _, action := range plan.ApplySteps {
		if action.ID == "apply.firewall" {
			applyScript = action.Command.String()
		}
	}
	for _, action := range plan.RevokeSteps {
		if action.ID == "revoke.firewall" {
			revokeScript = action.Command.String()
		}
	}
	if !strings.Contains(applyScript, "$owned = @($rules | Where-Object") || !strings.Contains(applyScript, "$unowned = @($rules | Where-Object") {
		t.Fatal("apply script does not distinguish owned and unowned same-name rules")
	}
	if !strings.Contains(applyScript, "$owned.Count -ne 1") {
		t.Fatal("apply script does not require exactly one owned rule")
	}
	if !strings.Contains(revokeScript, "Remove-NetFirewallRule -InputObject $r") {
		t.Fatal("revoke script does not delete selected rule objects")
	}
	if strings.Contains(revokeScript, "Remove-NetFirewallRule -DisplayName") {
		t.Fatal("revoke script can delete unowned same-name rules")
	}
}

func TestDiscoveryFirewallIsOptInAndOwned(t *testing.T) {
	without, err := BuildPlan(PlanOptions{ID: "no-discovery", ManagementAddress: LocalSubnet, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range without.ApplySteps {
		if strings.Contains(action.ID, "discovery") {
			t.Fatalf("discovery action unexpectedly enabled: %s", action.ID)
		}
	}

	with, err := BuildPlan(PlanOptions{ID: "with-discovery", ManagementAddress: LocalSubnet, AllowHTTP: true, EnableDiscovery: true})
	if err != nil {
		t.Fatal(err)
	}
	var applyScript, revokeScript string
	for _, action := range with.ApplySteps {
		if action.ID == "apply.discovery-firewall" {
			applyScript = action.Command.String()
		}
	}
	for _, action := range with.RevokeSteps {
		if action.ID == "revoke.discovery-firewall" {
			revokeScript = action.Command.String()
		}
	}
	if applyScript == "" || revokeScript == "" {
		t.Fatal("discovery firewall actions were not added")
	}
	if !strings.Contains(applyScript, "-Protocol UDP") || !strings.Contains(applyScript, "-LocalPort 37020") || !strings.Contains(applyScript, "-RemoteAddress 'LocalSubnet'") {
		t.Fatalf("discovery firewall apply script is not scoped correctly: %s", applyScript)
	}
	if !strings.Contains(applyScript, "Remote Bridge discovery plan with-discovery") || !strings.Contains(revokeScript, "Remove-NetFirewallRule -InputObject $r") {
		t.Fatalf("discovery firewall ownership checks are missing: apply=%s revoke=%s", applyScript, revokeScript)
	}
	if DefaultDiscoveryPort != discovery.DefaultPort {
		t.Fatalf("discovery port drift: windows=%d protocol=%d", DefaultDiscoveryPort, discovery.DefaultPort)
	}
}
