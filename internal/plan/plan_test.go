package plan

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testRequest() BuildRequest {
	return BuildRequest{
		DeviceID:          "device-1",
		TargetAddress:     "192.168.1.20",
		ManagementAddress: "192.168.1.10",
		Hostname:          "target",
		TemporaryAccount:  "bridge-temp",
		PairingID:         "pair_123",
		WinRMHTTPS:        true,
	}
}

func TestBuildPlanAndRollback(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	p, err := Build(testRequest(), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("plan validation: %v", err)
	}
	if p.Version != SchemaVersion || p.Mode != "lan-winrm" || p.Connection.Port != DefaultWinRMHTTPSPort {
		t.Fatalf("unexpected plan metadata: %#v", p)
	}
	if len(p.Rollback.Actions) != 3 {
		t.Fatalf("rollback actions = %d, want 3", len(p.Rollback.Actions))
	}
	if p.Rollback.Actions[0].Kind != ActionRemoveFirewall || p.Rollback.Actions[2].Kind != ActionRemoveTemporaryAccount {
		t.Fatalf("rollback order = %#v", p.Rollback.Actions)
	}
	before := p.Actions[1].Parameters["account"]
	p.Rollback.Actions[0].Parameters["source"] = "changed"
	if p.Actions[1].Parameters["account"] != before {
		t.Fatal("rollback shares action parameter map")
	}
}

func TestPlanJSONDoesNotContainPlaintextSecret(t *testing.T) {
	p, err := Build(testRequest(), time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"password", "private_key", "access_token", "12345678"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("plan JSON contains %q: %s", forbidden, text)
		}
	}
	decoded, err := UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("decode plan: %v", err)
	}
	if decoded.ID != p.ID || decoded.Connection.PairingID != "pair_123" {
		t.Fatalf("decoded plan mismatch: %#v", decoded)
	}
}

func TestBuildRejectsBroadOrInvalidInputs(t *testing.T) {
	cases := []BuildRequest{
		func() BuildRequest { r := testRequest(); r.ManagementAddress = "0.0.0.0"; return r }(),
		func() BuildRequest { r := testRequest(); r.ManagementAddress = "lan-host"; return r }(),
		func() BuildRequest { r := testRequest(); r.TemporaryAccount = "bridge temp"; return r }(),
		func() BuildRequest { r := testRequest(); r.DeviceID = ""; return r }(),
	}
	for _, req := range cases {
		if _, err := Build(req, time.Now()); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("error = %v, want ErrInvalidRequest", err)
		}
	}
}

func TestPlanValidationRejectsSecretParameter(t *testing.T) {
	p, err := Build(testRequest(), time.Unix(100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	p.Actions[0].Parameters["password"] = "must-not-be-here"
	if err := p.Validate(); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("secret parameter validation = %v", err)
	}
}
