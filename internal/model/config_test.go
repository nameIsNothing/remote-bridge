package model

import (
	"errors"
	"strings"
	"testing"
)

func TestDefaultConfigAndJSON(t *testing.T) {
	config := DefaultConfig()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := MarshalConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(data)), "password") || strings.Contains(strings.ToLower(string(data)), "token") {
		t.Fatalf("config JSON contains a secret field: %s", data)
	}
	decoded, err := UnmarshalConfig(data)
	if err != nil || decoded != config {
		t.Fatalf("config did not round trip: %#v, %v", decoded, err)
	}
}

func TestConfigRejectsBroadEndpoints(t *testing.T) {
	config := DefaultConfig()
	config.ManagementAddress = "0.0.0.0"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unspecified management address error = %v", err)
	}
	config = DefaultConfig()
	config.ListenAddress = "0.0.0.0"
	if err := config.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("wildcard listen address error = %v", err)
	}
}
