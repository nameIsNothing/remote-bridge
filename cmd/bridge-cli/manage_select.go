package main

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"remote-bridge/internal/discovery"
)

// Preserve the existing Windows-first default. A Unix target is selected
// only when no matching WinRM target exists; ambiguity never authorizes SSH.
func selectManagedAnnouncement(items []discovery.Announcement, target string) (discovery.Announcement, error) {
	want := strings.TrimSpace(target)
	var windowsTargets, unixTargets []discovery.Announcement
	for _, item := range items {
		if item.Expired(time.Now()) || len(item.Addresses) == 0 {
			continue
		}
		if want != "" && !strings.EqualFold(item.Hostname, want) && !containsFold(item.Addresses, want) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(item.Transport)) {
		case "winrm", "wsman", "winrm-http", "winrm-https", "http", "https":
			windowsTargets = append(windowsTargets, item)
		case "ssh":
			if item.Transport == "ssh" && item.Shell == "posix" {
				unixTargets = append(unixTargets, item)
			}
		}
	}
	if len(windowsTargets) > 0 {
		return selectWinRMAnnouncement(windowsTargets, target)
	}
	if len(unixTargets) > 0 {
		selected, _, err := selectSSHAnnouncement(unixTargets, target, "", discovery.DefaultPort)
		return selected, err
	}
	return discovery.Announcement{}, errors.New("未发现正在等待连接的电脑；请先在目标电脑开启入口并保持窗口打开，再重试")
}

func managedSSHStartupArguments(item discovery.Announcement, address, broadcast string, timeout time.Duration, port int) []string {
	return []string{"--target", address, "--instance", item.InstanceID, "--manage", "--broadcast", broadcast, "--timeout", timeout.String(), "--discovery-port", strconv.Itoa(port), "--pair-timeout", "300s"}
}
