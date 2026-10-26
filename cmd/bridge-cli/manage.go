package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/cliutil"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/managedsession"
	"remote-bridge/internal/model"
	"remote-bridge/internal/winrmlease"
)

//go:embed managed_worker.ps1
var managedWorkerScript string

//go:embed managed_command.ps1
var managedCommandScript string

//go:embed managed_ui.ps1
var managedUIScript string

func runManage(args []string) int {
	if hasArg(args, "--ssh") {
		sshArgs := []string{"--manage", "--discover"}
		for _, arg := range args {
			if arg != "--ssh" {
				sshArgs = append(sshArgs, arg)
			}
		}
		return runSSH(sshArgs)
	}
	fs := flag.NewFlagSet("bridge-cli manage", flag.ContinueOnError)
	target, broadcast := "", "255.255.255.255"
	duration := discovery.DefaultDiscoverTimeout
	port := discovery.DefaultPort
	discover := false
	fs.StringVar(&target, "target", "", "目标 IP 或主机名；多个目标时必须指定")
	fs.StringVar(&broadcast, "broadcast", broadcast, "局域网发现广播地址")
	fs.DurationVar(&duration, "timeout", duration, "发现等待时间")
	fs.IntVar(&port, "discovery-port", port, "UDP 发现端口")
	fs.BoolVar(&discover, "discover", false, "发现目标并建立托管会话（默认行为）")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	_ = discover
	if fs.NArg() != 0 || duration <= 0 || duration > 30*time.Second || port < 1 || port > 65535 {
		return fail(model.ExitUsage, errors.New("发现参数无效"))
	}
	if !managedWindowsAvailable() {
		return fail(model.ExitUsage, errors.New("托管 WinRM 管理端目前仅支持 Windows"))
	}
	fmt.Println("正在发现目标电脑…")
	items, err := discoverForWinRM(duration, broadcast, port)
	if err != nil {
		return fail(model.ExitConnection, err)
	}
	selected, err := selectManagedAnnouncement(items, target)
	if err != nil {
		return fail(model.ExitConnection, err)
	}
	if selected.Transport == "ssh" {
		address, err := chooseManagedAddress(selected, target)
		if err != nil {
			return fail(model.ExitConnection, err)
		}
		fmt.Printf("发现 Unix SSH 目标：%s (%s)，正在准备连接…\n", selected.Hostname, address)
		return runSSH(managedSSHStartupArguments(selected, address, broadcast, duration, port))
	}
	if err := selected.Validate(); err != nil || selected.Expired(time.Now()) || !winrmlease.InstancePattern.MatchString(selected.InstanceID) {
		return fail(model.ExitConnection, errors.New("目标实例信息无效或已过期"))
	}
	address := selected.Addresses[0]
	if netTarget, err := chooseManagedAddress(selected, target); err == nil {
		address = netTarget
	} else {
		return fail(model.ExitConnection, err)
	}
	fmt.Printf("目标：%s (%s)，账号：%s\n", selected.Hostname, address, selected.Username)
	if selected.Port == 5985 {
		if code := ensureManagedTrust(address); code != 0 {
			return code
		}
	}
	id, err := managedsession.RandomID("rb-", 12)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	info := managedsession.Info{ID: id, InstanceID: selected.InstanceID, Target: address, Hostname: selected.Hostname, Username: selected.Username, Port: selected.Port, ExpiresAt: selected.ExpiresAt}
	root, err := managedsession.DefaultRoot()
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	directory, err := managedsession.PrepareDirectory(root, id)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	// One local manager per target instance keeps feedback and credential
	// ownership unambiguous. OS handle release also covers process crashes.
	lock, err := trySSHSessionLock(filepath.Join(root, "winrm-"+selected.InstanceID+".lock"))
	if err != nil {
		return fail(model.ExitConnection, errors.New("此目标已有管理窗口或正在连接；请使用已有窗口复制交接指令，或先结束该连接"))
	}
	defer lock.Close()
	auditFunc := func(kind, command string, code int, success bool) error {
		metadata := map[string]string{"session_id": id, "target": address, "username": selected.Username, "instance_id": selected.InstanceID, "exit_code": fmt.Sprint(code)}
		if command != "" {
			metadata["command_hash"] = audit.Digest(command)
			metadata["command_length"] = fmt.Sprint(len(command))
		}
		return audit.Append(audit.DefaultPath(), model.AuditEvent{Type: kind, SessionID: id, Success: success, Metadata: metadata})
	}
	server, err := managedsession.NewServer(info, auditFunc)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	defer server.Shutdown()
	record := server.Record()
	config := struct {
		Endpoint      string              `json:"endpoint"`
		Token         string              `json:"token"`
		Fingerprint   string              `json:"fingerprint"`
		Session       managedsession.Info `json:"session"`
		LeaseScript   string              `json:"lease_script"`
		CommandScript string              `json:"command_script"`
		Handoff       string              `json:"handoff"`
	}{server.Endpoint(), server.WorkerToken(), record.Fingerprint, info, winrmlease.RemoteScript, managedCommandScript, managedsession.Handoff(info, mustExecutable())}
	configPath := filepath.Join(directory, "worker.json")
	defer func() {
		for _, name := range []string{"worker.json", "worker.ps1", "ui.ps1"} {
			_ = os.Remove(filepath.Join(directory, name))
		}
	}()
	data, _ := json.Marshal(config)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fail(model.ExitInternal, err)
	}
	for name, script := range map[string]string{"worker.ps1": managedWorkerScript, "ui.ps1": managedUIScript} {
		if err := os.WriteFile(filepath.Join(directory, name), append([]byte{0xef, 0xbb, 0xbf}, []byte(script)...), 0600); err != nil {
			return fail(model.ExitInternal, err)
		}
	}
	command := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-File", filepath.Join(directory, "worker.ps1"), "-ConfigPath", configPath)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		return fail(model.ExitConnection, err)
	}
	workerExited := make(chan struct{})
	var forced atomic.Bool
	go func() {
		err := command.Wait()
		missingScript := false
		for _, name := range []string{"worker.ps1", "ui.ps1"} {
			if _, statErr := os.Stat(filepath.Join(directory, name)); errors.Is(statErr, os.ErrNotExist) {
				missingScript = true
			}
		}
		if missingScript {
			server.Finish("连接脚本已被移除，可能被安全软件隔离；请查看安全软件的检测记录，不要关闭防护")
		} else if err != nil {
			server.Finish("本地连接进程已退出")
		} else {
			server.Finish("")
		}
		close(workerExited)
	}()
	go func() {
		select {
		case <-workerExited:
			return
		case <-server.Closing():
		}
		timer := time.NewTimer(7 * time.Second)
		defer timer.Stop()
		select {
		case <-workerExited:
		case <-timer.C:
			forced.Store(true)
			server.Finish("本地连接清理超时，已终止连接进程；远端回收结果需核对")
			_ = command.Process.Kill()
		}
	}()
	defer func() {
		server.BeginClose("管理端已关闭")
		clean := true
		select {
		case <-workerExited:
		case <-time.After(7 * time.Second):
			clean = false
			_ = command.Process.Kill()
			<-workerExited
		}
		closed := managedsession.Record{Info: server.Info()}
		closed.Info.State = "closed"
		if err := managedsession.WriteRecord(directory, closed); err != nil {
			fmt.Fprintln(os.Stderr, "保存结束状态失败：", err)
		}
		if err := auditFunc("manager.session.closed", "", 0, clean && !forced.Load()); err != nil {
			fmt.Fprintln(os.Stderr, "记录结束审计失败：", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := server.WaitReady(ctx); err != nil {
		if !strings.Contains(err.Error(), "取消") {
			reason := server.Info().Reason
			if reason == "" {
				reason = err.Error()
			}
			managedShowError(reason + "\n请保留完整错误信息，核对目标窗口及两端版本后重新连接。")
		}
		return fail(model.ExitConnection, fmt.Errorf("%w；托管模式需要更新后的目标程序提供活动入口校验", err))
	}
	if err := auditFunc("manager.session.connected", "", 0, true); err != nil {
		return fail(model.ExitInternal, err)
	}
	if err := managedsession.WriteRecord(directory, server.Record()); err != nil {
		return fail(model.ExitInternal, err)
	}
	fmt.Println("已连接。请在管理窗口点击“复制 Codex 交接指令”。")
	fmt.Println(managedsession.Handoff(server.Info(), mustExecutable()))
	<-server.Done()
	if reason := server.Info().Reason; reason != "" {
		fmt.Println("会话已结束：", reason)
	} else {
		fmt.Println("会话已结束。")
	}
	return int(model.ExitOK)
}
func ensureManagedTrust(address string) int {
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; $target=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s')); $value=[string](Get-Item -LiteralPath 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value; $present=@($value -split ',' | Where-Object { $_.Trim() -ieq $target -or $_.Trim() -eq '*' }).Count -gt 0; [pscustomobject]@{present=$present} | ConvertTo-Json -Compress`, encodeValue(address))
	result, err := cliutil.RunPowerShell(script, nil)
	var existing struct {
		Present bool `json:"present"`
	}
	if err == nil && json.Unmarshal([]byte(result.Stdout), &existing) == nil && existing.Present {
		return 0
	}
	fmt.Println("正在准备此目标的 WinRM 信任项；必要时会请求标准 Windows UAC。")
	return runTrust([]string{"--target", address})
}
func mustExecutable() string {
	path, err := os.Executable()
	if err != nil {
		return "bridge-cli.exe"
	}
	return path
}
func chooseManagedAddress(item discovery.Announcement, want string) (string, error) {
	if len(item.Addresses) == 0 {
		return "", errors.New("目标没有有效 IPv4 地址")
	}
	for _, address := range item.Addresses {
		if strings.EqualFold(strings.TrimSpace(want), address) {
			return address, nil
		}
	}
	return item.Addresses[0], nil
}
