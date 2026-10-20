package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConnectionInfoJSONHasNoCredential(t *testing.T) {
	data, err := MarshalConnectionInfo(ConnectionInfo{
		DeviceID:  "device-1",
		Address:   "192.168.1.20",
		Port:      5986,
		Transport: "winrm-https",
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "password") || strings.Contains(text, "private_key") || strings.Contains(text, "code") {
		t.Fatalf("connection JSON contains a credential field: %s", text)
	}
	decoded, err := UnmarshalConnectionInfo(data)
	if err != nil || decoded.DeviceID != "device-1" {
		t.Fatalf("connection JSON did not round trip: %#v, %v", decoded, err)
	}
}

func TestPairingModelJSONContainsVerifierOnly(t *testing.T) {
	data, err := json.Marshal(Pairing{
		ID:          "pair-1",
		DeviceID:    "device-1",
		CodeHash:    "hash",
		CodeSalt:    "salt",
		Status:      PairingStatusPending,
		MaxAttempts: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "12345678") || strings.Contains(text, "password") {
		t.Fatalf("pairing JSON contains plaintext credential data: %s", text)
	}
}
