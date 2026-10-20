package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPHandshakeToolsAndInvalidRequests(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"fixture","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bridge_execute","arguments":{"session_id":"../../escape","command":"Get-Date"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"unknown"}`,
	}, "\n")
	var output bytes.Buffer
	if code := serveMCP(strings.NewReader(input), &output); code != 0 {
		t.Fatal(code)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 5 {
		t.Fatalf("bad response framing: %s", &output)
	}
	var responses []map[string]any
	for _, line := range lines {
		var value map[string]any
		if err := json.Unmarshal([]byte(line), &value); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, value)
	}
	if responses[0]["error"] == nil || responses[1]["result"] == nil || responses[3]["error"] == nil || responses[4]["error"] == nil {
		t.Fatalf("invalid MCP lifecycle responses: %+v", responses)
	}
	tools := responses[2]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools=%+v", tools)
	}
	if strings.Contains(output.String(), "Bearer ") || strings.Contains(output.String(), "fingerprint") {
		t.Fatal("private IPC material in MCP output")
	}
	for _, tool := range tools {
		typed := tool.(map[string]any)
		if typed["name"] == "bridge_execute" && typed["annotations"].(map[string]any)["readOnlyHint"] != false {
			t.Fatal("arbitrary commands falsely advertised as read-only")
		}
	}
}

func TestMCPNeverAcceptsPasswordParameter(t *testing.T) {
	initialized := true
	request := mcpRequest{JSONRPC: "2.0", Method: "tools/call", Params: json.RawMessage(`{"name":"bridge_execute","arguments":{"session_id":"rb-0123456789abcdef01234567","command":"Get-Date","password":"not-a-real-password"}}`)}
	_, rpcErr := handleMCP(request, &initialized)
	if rpcErr == nil {
		t.Fatal("password parameter was accepted")
	}
}
