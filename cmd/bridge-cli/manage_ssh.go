package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/diagnostic"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/managedsession"
	"remote-bridge/internal/model"
	"remote-bridge/internal/sshclient"
)

const managedSSHIdentityCommand = "printf '%s\\n' '__REMOTE_BRIDGE_IDENTITY_V1__'; hostname; id -un; id -u\n"

type managedSSHRunner func(context.Context, string) (sshclient.Result, error)

// runManagedSSH keeps the already approved, pinned SSH credentials under the
// caller's cache lock. Each request opens an independent remote shell; no
// password or persistent SSH control socket is added to the local catalog.
func runManagedSSH(selected discovery.Announcement, endpoint *net.UDPAddr, record sshSessionRecord, session *lockedSSHSession) int {
	if endpoint == nil || session == nil || endpoint.IP.To4() == nil || record.Shell != "posix" || selected.Shell != record.Shell ||
		record.InstanceID != selected.InstanceID || record.InstanceID != session.instance || record.Address != endpoint.IP.String() ||
		record.Port != selected.Port || record.Username != selected.Username || selected.Expired(time.Now()) || !time.Now().Before(record.ExpiresAt) {
		return fail(model.ExitUsage, errors.New("SSH 托管模式需要 Unix POSIX Shell 入口"))
	}
	id, err := managedsession.RandomID("rb-", 12)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	info := managedsession.Info{ID: id, InstanceID: record.InstanceID, Target: endpoint.IP.String(), Hostname: selected.Hostname,
		Username: record.Username, Port: record.Port, Transport: "ssh", Shell: record.Shell, ExpiresAt: record.ExpiresAt}
	auditFunc := managedSSHAudit(info)
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithDeadline(signalCtx, info.ExpiresAt)
	defer cancel()
	runner := func(ctx context.Context, command string) (sshclient.Result, error) {
		return sshclient.RunShell(ctx, info.Target, info.Port, info.Username, session.privatePath(), session.knownHostsPath(), info.Shell, command)
	}
	probeCtx, stopProbe := context.WithTimeout(ctx, 10*time.Second)
	verified, err := probeManagedSSH(probeCtx, runner, info, auditFunc)
	stopProbe()
	if err != nil {
		return fail(model.ExitConnection, fmt.Errorf("SSH 身份核对失败：%w", err))
	}
	info.UID = verified.UID
	auditFunc = managedSSHAudit(info)
	server, err := managedsession.NewServer(info, auditFunc)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	defer server.Shutdown()
	root, err := managedsession.DefaultRoot()
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	directory, err := managedsession.PrepareDirectory(root, id)
	if err != nil {
		return fail(model.ExitInternal, err)
	}
	defer func() {
		server.Finish("")
		closed := managedsession.Record{Info: server.Info()}
		if err := managedsession.WriteRecord(directory, closed); err != nil {
			fmt.Fprintln(os.Stderr, "保存 SSH 结束状态失败：", err)
		}
		if err := auditFunc("manager.session.closed", "", 0, true); err != nil {
			fmt.Fprintln(os.Stderr, "记录 SSH 结束审计失败：", err)
		}
	}()
	if err := server.Ready(info); err != nil {
		return fail(model.ExitConnection, err)
	}
	if err := auditFunc("manager.session.connected", "", 0, true); err != nil {
		return fail(model.ExitInternal, err)
	}
	if err := managedsession.WriteRecord(directory, server.Record()); err != nil {
		return fail(model.ExitInternal, err)
	}
	go func() {
		select {
		case <-server.Closing():
			cancel()
		case <-ctx.Done():
			server.BeginClose("管理端已关闭或会话已到期")
		}
	}()
	go serveManagedSSH(ctx, server, runner, info, auditFunc, 3*time.Second)
	fmt.Println("SSH 托管连接已就绪；保持本窗口打开。按回车或 Ctrl+C 结束。")
	fmt.Println(managedsession.Handoff(server.Info(), mustExecutable()))
	inputDone := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		close(inputDone)
	}()
	select {
	case <-inputDone:
		server.BeginClose("管理端已结束会话")
	case <-ctx.Done():
		server.BeginClose("管理端已关闭或会话已到期")
	case <-server.Done():
	}
	cancel()
	select {
	case <-server.Done():
	case <-time.After(6 * time.Second):
		server.Finish("本地 SSH 进程未及时结束，目标回收状态需核对")
		return fail(model.ExitConnection, errors.New(server.Info().Reason))
	}
	fmt.Println("SSH 托管会话已结束。目标端入口由目标窗口管理。")
	return int(model.ExitOK)
}

func managedSSHAudit(info managedsession.Info) managedsession.AuditFunc {
	return func(kind, command string, code int, success bool) error {
		metadata := map[string]string{"session_id": info.ID, "target": info.Target, "username": info.Username, "instance_id": info.InstanceID,
			"transport": "ssh", "shell": "posix", "exit_code": fmt.Sprint(code)}
		if info.UID != "" {
			metadata["uid"] = info.UID
		}
		if command != "" {
			metadata["command_hash"], metadata["command_length"] = audit.Digest(command), fmt.Sprint(len(command))
		}
		return audit.Append(audit.DefaultPath(), model.AuditEvent{Type: kind, SessionID: info.ID, Success: success, Metadata: metadata})
	}
}

func parseManagedSSHIdentity(output string, expected managedsession.Info) (managedsession.Info, error) {
	lines := strings.Split(strings.TrimSuffix(strings.ReplaceAll(output, "\r\n", "\n"), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "__REMOTE_BRIDGE_IDENTITY_V1__" || lines[1] != expected.Hostname ||
		lines[2] != expected.Username || !managedsession.ValidUnixUID(lines[3]) || (expected.UID != "" && lines[3] != expected.UID) {
		return managedsession.Info{}, errors.New("SSH 主机、账号或 UID 与已批准入口不一致")
	}
	expected.UID = lines[3]
	return expected, nil
}

func probeManagedSSH(ctx context.Context, runner managedSSHRunner, expected managedsession.Info, auditFunc managedsession.AuditFunc) (managedsession.Info, error) {
	if auditFunc != nil {
		if err := auditFunc("manager.session.probe.started", managedSSHIdentityCommand, 0, false); err != nil {
			return managedsession.Info{}, fmt.Errorf("无法记录身份检查审计，未连接：%w", err)
		}
	}
	result, err := runner(ctx, managedSSHIdentityCommand)
	var verified managedsession.Info
	if err == nil && result.ExitCode == 0 && !result.Truncated {
		verified, err = parseManagedSSHIdentity(result.Stdout, expected)
	} else if err == nil {
		err = errors.New("SSH 身份检查未成功完成")
	}
	if err != nil && strings.TrimSpace(result.Stderr) != "" {
		detail := diagnostic.Sanitize(strings.TrimSpace(result.Stderr))
		if runes := []rune(detail); len(runes) > 512 {
			detail = string(runes[:512])
		}
		err = fmt.Errorf("%w：%s", err, detail)
	}
	if auditFunc != nil {
		if auditErr := auditFunc("manager.session.probe.finished", managedSSHIdentityCommand, result.ExitCode, err == nil); auditErr != nil {
			err = fmt.Errorf("身份检查审计失败：%w", auditErr)
		}
	}
	return verified, err
}

func serveManagedSSH(ctx context.Context, server *managedsession.Server, runner managedSSHRunner, info managedsession.Info, auditFunc managedsession.AuditFunc, probeInterval time.Duration) {
	defer server.Finish("")
	for ctx.Err() == nil {
		pollCtx, cancel := context.WithTimeout(ctx, probeInterval)
		work := server.NextWork(pollCtx)
		cancel()
		switch work.Operation {
		case "close":
			return
		case "idle":
			if ctx.Err() != nil {
				return
			}
			probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			_, err := probeManagedSSH(probeCtx, runner, info, auditFunc)
			stop()
			if err != nil {
				server.BeginClose("目标 SSH 入口已停止或身份检查失败")
				return
			}
		case "exec":
			commandCtx, stop := context.WithTimeout(ctx, time.Duration(work.Timeout)*time.Second)
			result, err := runner(commandCtx, work.Command)
			contextErr := commandCtx.Err()
			stop()
			if contextErr != nil {
				server.CompleteWork(work.ID, nil, errors.New("SSH 命令已取消或超时，托管会话已结束；目标进程回收需核对"))
				server.BeginClose("SSH 命令已取消或超时")
				return
			}
			if err != nil && (result.ExitCode < 0 || result.ExitCode == 255) {
				server.CompleteWork(work.ID, nil, errors.New("SSH 连接已中断"))
				server.BeginClose("SSH 连接已中断")
				return
			}
			server.CompleteWork(work.ID, &managedsession.Result{Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, Truncated: result.Truncated}, nil)
		}
	}
}
