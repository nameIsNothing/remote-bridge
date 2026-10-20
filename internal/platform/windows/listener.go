package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// WinRMStatus is the read-only local state needed by the target wizard to
// decide whether it should prepare a listener.  Known is false whenever the
// listener query could not be completed; callers must not treat that state as
// "listener missing" because doing so could trigger an unnecessary policy
// change.
type WinRMStatus struct {
	Known             bool     `json:"known"`
	ServicePresent    bool     `json:"service_present"`
	ServiceRunning    bool     `json:"service_running"`
	ListenerChecked   bool     `json:"listener_checked"`
	ListenerPresent   bool     `json:"listener_present"`
	HTTPListener      bool     `json:"http_listener"`
	HTTPSListener     bool     `json:"https_listener"`
	ListenerPorts     []int    `json:"listener_ports,omitempty"`
	ListenerProtocols []string `json:"listener_protocols,omitempty"`
	Error             string   `json:"error,omitempty"`
}

type winRMProbeResult struct {
	ServicePresent    bool     `json:"service_present"`
	ServiceRunning    bool     `json:"service_running"`
	ListenerChecked   bool     `json:"listener_checked"`
	ListenerError     string   `json:"listener_error"`
	ListenerPresent   bool     `json:"listener_present"`
	ListenerPorts     []int    `json:"listener_ports"`
	ListenerProtocols []string `json:"listener_protocols"`
}

// DetectWinRM performs one read-only PowerShell probe. It never starts a
// service, creates a listener, changes a firewall rule, or changes a policy.
// A caller may safely use a Known result to select ConfigureListener while
// retaining a final explicit confirmation before any mutation.
func DetectWinRM(ctx context.Context, runner Runner) (WinRMStatus, error) {
	status := WinRMStatus{}
	if runner == nil {
		return status, ErrNoRunner
	}
	result, runErr := runner.Run(ctx, psCommand(winRMDetectScript(), true))
	if runErr != nil {
		status.Error = runErr.Error()
		return status, runErr
	}
	if result.ExitCode != 0 {
		err := fmt.Errorf("WinRM detection exited with code %d", result.ExitCode)
		if strings.TrimSpace(result.Stderr) != "" {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(result.Stderr))
		}
		status.Error = err.Error()
		return status, err
	}
	var probe winRMProbeResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &probe); err != nil {
		err = fmt.Errorf("parse WinRM detection result: %w", err)
		status.Error = err.Error()
		return status, err
	}
	status = normalizeWinRMStatus(probe)
	if !status.ListenerChecked {
		message := strings.TrimSpace(probe.ListenerError)
		if message == "" {
			message = "WinRM listener state could not be inspected"
		}
		status.Error = message
		return status, errors.New(message)
	}
	status.Known = true
	return status, nil
}

func normalizeWinRMStatus(probe winRMProbeResult) WinRMStatus {
	status := WinRMStatus{
		ServicePresent:    probe.ServicePresent,
		ServiceRunning:    probe.ServiceRunning,
		ListenerChecked:   probe.ListenerChecked,
		ListenerPresent:   probe.ListenerPresent,
		ListenerPorts:     uniqueSortedInts(probe.ListenerPorts),
		ListenerProtocols: uniqueSortedStrings(probe.ListenerProtocols),
	}
	for _, port := range status.ListenerPorts {
		if port == DefaultHTTPPort {
			status.HTTPListener = true
		}
		if port == DefaultHTTPSPort {
			status.HTTPSListener = true
		}
	}
	return status
}

func uniqueSortedInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToUpper(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func winRMDetectScript() string {
	// Keep the output shape stable and deliberately small so the Go wizard does
	// not need to parse localized PowerShell objects. Listener errors are
	// represented as an unknown state, never as an absent listener.
	return `$ErrorActionPreference = 'Stop'; $service = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue; $servicePresent = $null -ne $service; $serviceRunning = $servicePresent -and ([string]$service.Status -eq 'Running'); $listenerChecked = $true; $listenerError = ''; $listeners = @(); try { $listeners = @(Get-WSManInstance -ResourceURI 'winrm/config/listener' -Enumerate -ErrorAction Stop) } catch { $listenerChecked = $false; $listenerError = $_.Exception.Message }; $ports = @(); $protocols = @(); if ($listenerChecked) { foreach ($listener in $listeners) { if ($null -ne $listener.Port) { $ports += [int]$listener.Port }; if ($null -ne $listener.Protocol) { $protocols += [string]$listener.Protocol } } }; [pscustomobject]@{ service_present = $servicePresent; service_running = $serviceRunning; listener_checked = $listenerChecked; listener_error = $listenerError; listener_present = ($listenerChecked -and $listeners.Count -gt 0); listener_ports = @($ports | Select-Object -Unique); listener_protocols = @($protocols | Select-Object -Unique) } | ConvertTo-Json -Compress`
}
