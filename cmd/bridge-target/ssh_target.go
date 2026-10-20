package main

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/cliutil"
	"remote-bridge/internal/diagnostic"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/model"
	"remote-bridge/internal/platform/windows"
	"remote-bridge/internal/sshclient"
)

const (
	// sshBridgePort is deliberately separate from the normal OpenSSH service
	// port.  A target may already have sshd listening on 22; the bridge must
	// not rewrite or stop that administrator-owned service.
	sshBridgePort = 2222
	sshPlanTTL    = 30 * time.Minute

	// Local user descriptions on supported Windows versions are limited to
	// 48 characters.  Keep the current marker comfortably below that limit
	// even when a valid plan ID reaches its maximum length.  The legacy prefix
	// is retained for cleanup and safe reuse of accounts created by older
	// bridge-target builds.
	sshAccountMarkerPrefix       = "RBSSH-"
	legacySSHAccountMarkerPrefix = "Remote Bridge SSH temporary account "
)

type sshTargetRuntime struct {
	id            string
	username      string
	port          int
	root          string
	configPath    string
	keyPath       string
	sshdPath      string
	hostKey       string
	statePath     string
	expiresAt     time.Time
	serviceName   string
	pid           int
	logPath       string
	done          chan error
	onEvent       func(guiEvent)
	confirm       func(context.Context, string) bool
	pairMu        sync.Mutex
	approved      map[string]string
	monitorCancel context.CancelFunc
	cleanupErr    error
	releaseLock   func()
	authMu        sync.Mutex
	authSerial    uint64
	cleanup       sync.Once
}

// runSSHInteractive is the USB target path.  It is intentionally explicit:
// the target user sees detection and installation choices, confirms the
// system changes, and then leaves a visible, short-lived SSH responder open.
func runSSHInteractive() (exitCode int) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Remote Bridge 目标机向导（Windows 局域网 SSH）")
	fmt.Println("将检测 OpenSSH；缺失时优先使用 U 盘 packages\\openssh\\manifest.json，否则使用 Windows 在线功能安装。")
	fmt.Println("所有系统修改都需要最后确认；直接按回车执行，输入其他内容只退出。")
	addresses := localIPv4Details()
	if len(addresses) == 0 {
		fmt.Println("错误：未发现活动的非回环 IPv4，无法生成局域网 SSH 地址。")
		return int(model.ExitConnection)
	}
	hostname := localHostname()
	fmt.Printf("目标机名称: %s\n", hostname)
	printLocalAddresses(addresses)
	targetAddress := firstAddress(addresses)
	fmt.Printf("自动选择目标地址: %s\n", targetAddress)

	status, detectErr := windows.DetectOpenSSH(context.Background(), windows.NewRunner())
	if detectErr != nil {
		fmt.Printf("OpenSSH 检测警告：%v\n", detectErr)
	}
	printOpenSSHStatus(status)
	if !targetIsAdministrator() {
		fmt.Println("当前程序不是管理员权限，无法创建本地账号、安装 OpenSSH 或写入防火墙。")
		fmt.Println("请在 U 盘上运行 bridge-target-admin.cmd（会弹出标准 Windows UAC），然后重试。")
		return int(model.ExitUnauthorized)
	}

	planID, err := newSSHPlanID()
	if err != nil {
		fmt.Printf("错误：生成计划 ID：%v\n", err)
		return int(model.ExitInternal)
	}
	packagePath, manifestPath := discoverUSBOpenSSHPackage()
	source := windows.OpenSSHSourceAuto
	if status.ServicePresent || strings.TrimSpace(status.ExecutablePath) != "" || strings.EqualFold(status.CapabilityState, "Installed") {
		source = windows.OpenSSHSourceExisting
	} else if packagePath != "" && manifestPath != "" {
		fmt.Printf("发现 U 盘 OpenSSH 包：%s\n", packagePath)
		source = windows.OpenSSHSourceUSB
	} else {
		fmt.Println("未发现可用 OpenSSH，将在确认后尝试 Windows 在线安装。")
		source = windows.OpenSSHSourceOnline
	}

	runtimeDir := sshRuntimeDirectory(planID)
	legacyStatePath := defaultStatePath()
	legacyPresent, legacyStateErr := stateFilePresent(legacyStatePath)
	fmt.Println("\n即将准备的连接：")
	fmt.Printf("  SSH 地址: %s / TCP %d\n", targetAddress, sshBridgePort)
	fmt.Printf("  账号: %s（固定名称；SSH 使用公钥，不需要输入密码）\n", windows.DefaultTemporaryUser)
	fmt.Printf("  防火墙来源: %s\n", simpleLANManagementAddress)
	fmt.Printf("  入口有效期: %s\n", sshPlanTTL)
	fmt.Printf("  OpenSSH 来源: %s\n", source)
	fmt.Println("  管理端：bridge-cli ssh --discover；配对时目标机弹窗确认公钥。")
	fmt.Println("  提示：本实验仅开放 LocalSubnet，关闭窗口或到期后会停止入口并清理计划资源。")
	if legacyStateErr != nil {
		fmt.Printf("  旧 WinRM 状态检查警告：%v\n", legacyStateErr)
	} else if legacyPresent {
		fmt.Println("  检测到旧 WinRM 计划；确认后会先清理其计划账号和防火墙规则。")
	}
	fmt.Print("确认执行配置？直接按回车执行，输入其他内容取消: ")
	if !interactiveApplyConfirmed(reader) {
		fmt.Println("未执行任何修改。")
		return int(model.ExitOK)
	}
	releaseLock, err := acquireTargetLock()
	if err != nil {
		fmt.Println(err)
		return int(model.ExitConnection)
	}
	defer releaseLock()
	if err := cleanupPreviousSSH(context.Background()); err != nil {
		fmt.Printf("清理旧 SSH 入口失败：%v\n", err)
		return int(model.ExitInternal)
	}
	if legacyPresent || legacyStateErr != nil {
		if err := cleanupPreviousWinRM(context.Background()); err != nil {
			fmt.Printf("清理旧 WinRM 计划失败：%v\n", err)
			fmt.Println("未启动 SSH；请先手动运行 bridge-target revoke --state 旧状态文件。")
			return int(model.ExitInternal)
		}
	}

	prepared, err := prepareSSHRuntime(context.Background(), sshTargetPrepareOptions{
		PlanID:       planID,
		Source:       source,
		PackagePath:  packagePath,
		ManifestPath: manifestPath,
		RuntimeDir:   runtimeDir,
		TTL:          sshPlanTTL,
	})
	if err != nil {
		fmt.Printf("SSH 准备失败：%v\n", err)
		fmt.Println("未启动 UDP 配对；请根据以上错误核对配置回收结果。")
		return int(model.ExitInternal)
	}
	statePath := defaultSSHStatePath()
	if err := writeSSHState(statePath, prepared); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		fmt.Printf("写入 SSH 状态失败：%v\n", errors.Join(err, prepared.Cleanup(cleanupCtx)))
		return int(model.ExitInternal)
	}
	announcement := discovery.Announcement{
		V:          discovery.Version,
		Type:       discovery.AnnouncementType,
		InstanceID: prepared.id,
		Hostname:   hostname,
		Addresses:  addressStrings(addresses),
		Port:       prepared.port,
		Transport:  "ssh",
		Username:   prepared.username,
		ExpiresAt:  prepared.expiresAt,
	}
	responder, err := startTargetDiscoveryResponderWithPairing(announcement, statePath, prepared.Pair)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		fmt.Printf("启动 UDP 配对失败：%v\n", errors.Join(err, prepared.Cleanup(cleanupCtx)))
		return int(model.ExitConnection)
	}
	defer func() {
		responder.Stop()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := prepared.Cleanup(cleanupCtx); err != nil {
			fmt.Printf("部分配置未清理：%v\n", err)
			exitCode = int(model.ExitInternal)
		}
	}()
	fmt.Printf("SSH 入口已开启：%s@%s:%d\n", prepared.username, targetAddress, prepared.port)
	fmt.Printf("管理机运行：bridge-cli ssh --discover --command \"Get-ComputerInfo\"\n")
	fmt.Printf("状态文件：%s\n", statePath)
	fmt.Println("等待管理机配对；同一管理端在本次有效期内只需确认一次。按回车或到期关闭入口。")

	// Do not leave a blocking ReadString goroutine holding the runtime open on
	// expiry.  The responder and the SSH process are both cleaned up when the
	// timer wins.
	inputDone := make(chan struct{})
	go func() {
		_, _ = reader.ReadString('\n')
		close(inputDone)
	}()
	timer := time.NewTimer(time.Until(prepared.expiresAt))
	defer timer.Stop()
	select {
	case <-inputDone:
		fmt.Println("正在关闭 SSH 入口并清理计划资源...")
	case <-timer.C:
		fmt.Println("SSH 入口已到期，正在清理计划资源...")
	case failure := <-prepared.done:
		if time.Now().Before(prepared.expiresAt) {
			fmt.Printf("SSH 入口已停止：%v\n", failure)
			return int(model.ExitConnection)
		}
		fmt.Println("SSH 入口已到期，正在清理计划资源...")
	}
	return int(model.ExitOK)
}

func printOpenSSHStatus(status windows.OpenSSHStatus) {
	if status.ServicePresent {
		state := "已停止"
		if status.ServiceRunning {
			state = "运行中"
		}
		fmt.Printf("OpenSSH 服务：%s（%s）\n", windows.DefaultOpenSSHServiceName, state)
	} else {
		fmt.Println("OpenSSH 服务：未发现")
	}
	if status.ExecutablePath != "" {
		fmt.Printf("OpenSSH 程序：%s\n", status.ExecutablePath)
	}
	if status.CapabilityState != "" {
		fmt.Printf("Windows 功能状态：%s\n", status.CapabilityState)
	}
}

func targetIsAdministrator() bool {
	return nativeTargetIsAdministrator()
}

type sshTargetPrepareOptions struct {
	PlanID       string
	Source       windows.OpenSSHSource
	PackagePath  string
	ManifestPath string
	RuntimeDir   string
	TTL          time.Duration
	OnEvent      func(guiEvent)
	Confirm      func(context.Context, string) bool
}

func prepareSSHRuntime(ctx context.Context, options sshTargetPrepareOptions) (result *sshTargetRuntime, returnedErr error) {
	if strings.TrimSpace(options.PlanID) == "" || strings.TrimSpace(options.RuntimeDir) == "" {
		return nil, errors.New("SSH 计划参数不完整")
	}
	if options.TTL <= 0 {
		return nil, errors.New("SSH 入口有效期无效")
	}
	if !validSSHPlanID(options.PlanID) || !samePath(options.RuntimeDir, sshRuntimeDirectory(options.PlanID)) || options.TTL > sshPlanTTL {
		return nil, errors.New("SSH 计划路径或有效期无效")
	}
	prepared := false
	pathProtected := false
	if err := validateSSHOwnedPath(options.RuntimeDir); err != nil {
		return nil, err
	}
	runtimeState := &sshTargetRuntime{id: options.PlanID, username: windows.DefaultTemporaryUser, port: sshBridgePort, root: options.RuntimeDir, statePath: defaultSSHStatePath(), expiresAt: time.Now().UTC().Add(options.TTL), done: make(chan error, 1), onEvent: options.OnEvent, confirm: options.Confirm, approved: make(map[string]string)}
	defer func() {
		if prepared || !pathProtected {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		returnedErr = errors.Join(returnedErr, runtimeState.Cleanup(cleanupCtx))
	}()
	if err := os.MkdirAll(options.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	if err := protectSSHRuntimeRoot(ctx, options.RuntimeDir); err != nil {
		return nil, err
	}
	pathProtected = true
	if err := writeSSHState(runtimeState.statePath, runtimeState); err != nil {
		return nil, err
	}
	runner := windows.NewRunner()
	status, _ := windows.DetectOpenSSH(ctx, runner)
	sshdPath := strings.TrimSpace(status.ExecutablePath)
	if !trustedInstalledSSHD(sshdPath) {
		sshdPath = ""
	}
	if sshdPath == "" {
		sshdPath = findOpenSSHExecutable()
	}
	if sshdPath == "" || !fileExists(sshdPath) {
		if options.Source == windows.OpenSSHSourceUSB {
			if err := validateUSBOpenSSHCompatibility(status, options.ManifestPath); err != nil {
				return nil, err
			}
			var err error
			sshdPath, err = installPortableOpenSSH(options.PackagePath, options.ManifestPath, options.PlanID)
			if err != nil {
				return nil, err
			}
		} else {
			if err := installOnlineOpenSSH(ctx, runner); err != nil {
				return nil, err
			}
			sshdPath = findOpenSSHExecutable()
			if sshdPath == "" {
				return nil, errors.New("OpenSSH 在线安装完成，但未找到 sshd.exe")
			}
		}
	}
	if !fileExists(sshdPath) {
		return nil, fmt.Errorf("sshd.exe 不存在：%s", sshdPath)
	}
	if err := os.MkdirAll(options.RuntimeDir, 0700); err != nil {
		return nil, fmt.Errorf("创建 SSH 计划目录：%w", err)
	}
	username := windows.DefaultTemporaryUser
	password, err := randomSecret(32)
	if err != nil {
		return nil, fmt.Errorf("生成 SSH 账号初始化密码：%w", err)
	}
	registerTargetDiagnosticSecret(password)
	if err := runSSHAccountScript(ctx, runner, username, options.PlanID, options.TTL, password); err != nil {
		return nil, err
	}
	if err := runSSHFirewallScript(ctx, runner, options.PlanID, sshBridgePort, simpleLANManagementAddress); err != nil {
		return nil, err
	}
	if err := runSSHDiscoveryFirewallScript(ctx, runner, options.PlanID, simpleLANManagementAddress); err != nil {
		return nil, err
	}
	hostKey := filepath.Join(options.RuntimeDir, "ssh_host_ed25519_key")
	if err := ensureSSHHostKey(ctx, sshdPath, hostKey); err != nil {
		return nil, err
	}
	publicHostKey, err := os.ReadFile(hostKey + ".pub")
	if err != nil {
		return nil, fmt.Errorf("读取 SSH 主机公钥：%w", err)
	}
	if err := sshclient.ValidatePublicKey(strings.TrimSpace(string(publicHostKey))); err != nil {
		return nil, fmt.Errorf("SSH 主机公钥无效：%w", err)
	}
	authorized := filepath.Join(options.RuntimeDir, "authorized_keys")
	if err := os.WriteFile(authorized, nil, 0600); err != nil {
		return nil, fmt.Errorf("创建 authorized_keys：%w", err)
	}
	configPath := filepath.Join(options.RuntimeDir, "sshd_config")
	config := buildSSHConfig(sshBridgePort, username, authorized, hostKey, filepath.Join(options.RuntimeDir, "sshd.pid"))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return nil, fmt.Errorf("写入 sshd_config：%w", err)
	}
	runtimeState.configPath, runtimeState.keyPath, runtimeState.sshdPath, runtimeState.hostKey, runtimeState.logPath = configPath, authorized, sshdPath, strings.TrimSpace(string(publicHostKey)), filepath.Join(options.RuntimeDir, sshRuntimeLogName)
	if err := protectSSHRuntimeFiles(ctx, runtimeState); err != nil {
		return nil, err
	}
	if err := runtimeState.start(ctx); err != nil {
		return nil, err
	}
	prepared = true
	return runtimeState, nil
}

func validateUSBOpenSSHCompatibility(status windows.OpenSSHStatus, manifestPath string) error {
	manifest, err := windows.ReadOpenSSHPackageManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("读取 OpenSSH manifest：%w", err)
	}
	if strings.TrimSpace(status.OSArchitecture) != "" {
		actual, archErr := windows.OpenSSHArchitecture(status.OSArchitecture)
		if archErr != nil {
			return archErr
		}
		wanted, archErr := windows.OpenSSHArchitecture(manifest.Architecture)
		if archErr != nil {
			return archErr
		}
		if actual != wanted {
			return fmt.Errorf("OpenSSH U 盘包架构 %s 与目标架构 %s 不匹配", wanted, actual)
		}
	}
	if strings.TrimSpace(status.OSBuild) != "" {
		inside, buildErr := windows.OpenSSHBuildInRange(status.OSBuild, manifest)
		if buildErr != nil {
			return buildErr
		}
		if !inside {
			return fmt.Errorf("OpenSSH U 盘包不支持 Windows build %s", status.OSBuild)
		}
	}
	return nil
}

func installOnlineOpenSSH(ctx context.Context, runner windows.Runner) error {
	command := windows.PowerShellCommand(`$ErrorActionPreference = 'Stop'; $name = 'OpenSSH.Server~~~~0.0.1.0'; $cap = Get-WindowsCapability -Online -Name $name -ErrorAction Stop; if ([string]$cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name $name -ErrorAction Stop | Out-Null }; $s = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue; [pscustomobject]@{ capability = [string](Get-WindowsCapability -Online -Name $name).State; service_present = ($null -ne $s) } | ConvertTo-Json -Compress`, false)
	result, err := runner.Run(ctx, command)
	if err != nil || result.ExitCode != 0 {
		if strings.TrimSpace(result.Stderr) != "" {
			return fmt.Errorf("Windows 在线安装 OpenSSH 失败：%s", strings.TrimSpace(result.Stderr))
		}
		return fmt.Errorf("Windows 在线安装 OpenSSH 失败：%v", err)
	}
	return nil
}

func installPortableOpenSSH(packagePath, manifestPath, planID string) (string, error) {
	manifest, err := windows.ReadOpenSSHPackageManifest(manifestPath)
	if err != nil {
		return "", fmt.Errorf("读取 OpenSSH U 盘 manifest：%w", err)
	}
	archivePath := filepath.Join(filepath.Dir(manifestPath), manifest.Archive)
	if !samePath(packagePath, archivePath) {
		return "", errors.New("OpenSSH manifest archive 与 package 路径不一致")
	}
	if err := windows.VerifyOpenSSHPackageDigest(archivePath, manifest); err != nil {
		return "", fmt.Errorf("校验 OpenSSH U 盘压缩包：%w", err)
	}
	root := sshRuntimeDirectory(planID) + string(os.PathSeparator) + "openssh"
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err := extractSafeZip(archivePath, root); err != nil {
		return "", err
	}
	var found string
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !info.IsDir() && strings.EqualFold(info.Name(), "sshd.exe") && found == "" {
			found = path
		}
		return nil
	})
	if err != nil || found == "" {
		return "", errors.New("OpenSSH U 盘压缩包中未找到 sshd.exe")
	}
	return found, nil
}

func extractSafeZip(archivePath, root string) error {
	archive, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("打开 OpenSSH ZIP：%w", err)
	}
	defer archive.Close()
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	var totalUncompressed uint64
	for _, item := range archive.File {
		name := filepath.Clean(filepath.FromSlash(item.Name))
		if name == "." || filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("ZIP 条目路径越界：%q", item.Name)
		}
		destination := filepath.Join(rootAbs, name)
		if !samePathOrChild(rootAbs, destination) {
			return fmt.Errorf("ZIP 条目路径越界：%q", item.Name)
		}
		if item.FileInfo().Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ZIP 不允许符号链接条目：%q", item.Name)
		}
		if item.UncompressedSize64 > 128<<20 {
			return fmt.Errorf("ZIP 单个条目过大：%q", item.Name)
		}
		totalUncompressed += item.UncompressedSize64
		if totalUncompressed > 512<<20 {
			return errors.New("OpenSSH ZIP 解压总大小超过 512 MiB")
		}
		if item.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		input, err := item.Open()
		if err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
		if err != nil {
			_ = input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, (128<<20)+1))
		closeErr := output.Close()
		_ = input.Close()
		if copyErr != nil {
			return copyErr
		}
		if written > 128<<20 {
			return fmt.Errorf("ZIP 条目实际大小超过 128 MiB：%q", item.Name)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func (r *sshTargetRuntime) start(ctx context.Context) error {
	if r == nil || strings.TrimSpace(r.sshdPath) == "" {
		return errors.New("SSH 运行时未准备 sshd.exe")
	}
	check := exec.CommandContext(ctx, r.sshdPath, "-t", "-f", r.configPath)
	hideTargetHelper(check)
	if output, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("校验 sshd_config：%v (%s)", err, strings.TrimSpace(string(output)))
	}
	if err := startSSHService(ctx, r); err != nil {
		captureSSHStartupFailure(r)
		return err
	}
	if err := waitSSHReady(ctx, r); err != nil {
		captureSSHStartupFailure(r)
		return err
	}
	monitorCtx, cancel := context.WithCancel(context.Background())
	r.monitorCancel = cancel
	go r.monitor(monitorCtx)
	r.emit(guiEvent{Kind: "progress", Detail: "SSH 服务已就绪（启动和协议检查通过）"})
	return nil
}

func (r *sshTargetRuntime) Cleanup(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.cleanup.Do(func() {
		if r.monitorCancel != nil {
			r.monitorCancel()
		}
		if r.releaseLock != nil {
			defer r.releaseLock()
		}
		if !validSSHPlanID(r.id) || !validSSHUsername(r.username) || !samePath(r.root, sshRuntimeDirectory(r.id)) || !samePath(r.statePath, defaultSSHStatePath()) {
			r.cleanupErr = errors.New("SSH 清理路径或资源所有权无效，未执行清理")
			return
		}
		if err := validateSSHOwnedPath(r.root); err != nil {
			r.cleanupErr = err
			return
		}
		if err := validateSSHOwnedPath(r.statePath); err != nil {
			r.cleanupErr = err
			return
		}
		var failures []error
		if r.serviceName != "" {
			if err := stopSSHService(ctx, r.serviceName, r.id, r.root); err != nil {
				failures = append(failures, err)
			}
			captureSSHHostDiagnostics(r)
		}
		if len(failures) == 0 {
			if err := cleanupSSHProcesses(ctx, r.id, r.root); err != nil {
				failures = append(failures, err)
			}
		}
		for _, err := range []error{removeSSHFirewall(ctx, r.id), removeSSHDiscoveryFirewall(ctx, r.id), removeSSHAccount(ctx, r.username, r.id)} {
			if err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) == 0 {
			if err := os.RemoveAll(r.root); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) == 0 && r.statePath != "" {
			if err := os.Remove(r.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, err)
			}
		}
		r.cleanupErr = errors.Join(failures...)
		entry := diagnostic.Event{Event: "ssh.cleanup.completed", Instance: r.id}
		if r.cleanupErr != nil {
			entry.Level, entry.Event, entry.Error = "error", "ssh.cleanup.failed", r.cleanupErr.Error()
		}
		targetDiagnostic(entry)
		r.audit("target.ssh.cleanup", r.cleanupErr == nil, "")
	})
	return r.cleanupErr
}

func (r *sshTargetRuntime) emit(event guiEvent) {
	if r.onEvent != nil {
		r.onEvent(event)
	}
}
func (r *sshTargetRuntime) audit(kind string, success bool, address string) {
	_ = audit.Append(audit.DefaultPath(), model.AuditEvent{Type: kind, Success: success, Metadata: map[string]string{"instance": r.id, "source": address}})
}

func runSSHAccountScript(ctx context.Context, runner windows.Runner, username, planID string, ttl time.Duration, password string) error {
	seconds := int64(ttl / time.Second)
	script := buildSSHAccountScript(username, planID, seconds)
	_, err := runSSHScript(ctx, cliutil.NewPasswordRunner(password, windows.DefaultPasswordEnv), "创建临时 SSH 账号", script)
	return err
}

func buildSSHAccountScript(username, planID string, seconds int64) string {
	marker := sshAccountMarker(planID)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $name = '%s'; $marker = '%s'; $raw = [Environment]::GetEnvironmentVariable('REMOTE_BRIDGE_TEMP_PASSWORD'); if ([string]::IsNullOrWhiteSpace($raw)) { throw 'missing temporary account password' }; $secure = ConvertTo-SecureString $raw -AsPlainText -Force; $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue; if ($null -eq $u) { New-LocalUser -Name $name -Password $secure -Description $marker -AccountExpires (Get-Date).AddSeconds(%d) -PasswordNeverExpires:$false -UserMayNotChangePassword:$true | Out-Null } elseif (-not (([string]$u.Description).StartsWith('%s', [System.StringComparison]::Ordinal) -or ([string]$u.Description).StartsWith('%s', [System.StringComparison]::Ordinal))) { throw 'existing RemoteBridge account is not owned by this SSH plan' } else { Enable-LocalUser -Name $name; Set-LocalUser -Name $name -Password $secure -AccountExpires (Get-Date).AddSeconds(%d) -Description $marker }; [pscustomobject]@{ name = $name; expires = (Get-LocalUser -Name $name).AccountExpires } | ConvertTo-Json -Compress`, username, marker, seconds, sshAccountMarkerPrefix, legacySSHAccountMarkerPrefix, seconds)
}

func runSSHFirewallScript(ctx context.Context, runner windows.Runner, planID string, port int, address string) error {
	name := "RemoteBridge-" + planID + "-SSH"
	marker := "Remote Bridge SSH plan " + planID
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $r = Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; if ($null -eq $r) { New-NetFirewallRule -DisplayName '%s' -Group 'Remote Bridge' -Description '%s' -Direction Inbound -Action Allow -Protocol TCP -LocalPort %d -RemoteAddress '%s' -Profile Any | Out-Null } elseif ([string]$r.Description -ne '%s') { throw 'same-name firewall rule is not owned by this plan' }; [pscustomobject]@{ display_name = '%s'; port = %d } | ConvertTo-Json -Compress`, name, name, marker, port, address, marker, name, port)
	_, err := runSSHScript(ctx, runner, "创建 SSH 防火墙规则", script)
	return err
}

func removeSSHFirewall(ctx context.Context, planID string) error {
	name := "RemoteBridge-" + planID + "-SSH"
	marker := "Remote Bridge SSH plan " + planID
	script := buildSSHFirewallCleanupScript(name, marker)
	_, err := runSSHSystemScript(ctx, "清理 SSH 防火墙规则", script)
	return err
}

func runSSHDiscoveryFirewallScript(ctx context.Context, runner windows.Runner, planID, address string) error {
	name := "RemoteBridge-" + planID + "-SSH-Discovery"
	marker := "Remote Bridge SSH discovery plan " + planID
	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'; $r = Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue; if ($null -eq $r) { New-NetFirewallRule -DisplayName '%s' -Group 'Remote Bridge' -Description '%s' -Direction Inbound -Action Allow -Protocol UDP -LocalPort %d -RemoteAddress '%s' -Profile Any | Out-Null } elseif ([string]$r.Description -ne '%s') { throw 'same-name discovery firewall rule is not owned by this plan' }; [pscustomobject]@{ display_name = '%s'; port = %d } | ConvertTo-Json -Compress`, name, name, marker, discovery.DefaultPort, address, marker, name, discovery.DefaultPort)
	_, err := runSSHScript(ctx, runner, "创建 SSH UDP 发现防火墙规则", script)
	return err
}

func removeSSHDiscoveryFirewall(ctx context.Context, planID string) error {
	name := "RemoteBridge-" + planID + "-SSH-Discovery"
	marker := "Remote Bridge SSH discovery plan " + planID
	script := buildSSHFirewallCleanupScript(name, marker)
	_, err := runSSHSystemScript(ctx, "清理 SSH UDP 发现规则", script)
	return err
}

func removeSSHAccount(ctx context.Context, username, planID string) error {
	marker := sshAccountMarker(planID)
	legacyMarker := legacySSHAccountMarker(planID)
	script := buildSSHAccountCleanupScript(username, marker, legacyMarker)
	_, err := runSSHSystemScript(ctx, "清理临时 SSH 账号", script)
	return err
}

func sshAccountMarker(planID string) string {
	return sshAccountMarkerPrefix + planID
}

func legacySSHAccountMarker(planID string) string {
	return legacySSHAccountMarkerPrefix + planID
}

func ensureSSHHostKey(ctx context.Context, sshdPath, hostKey string) error {
	public := hostKey + ".pub"
	if fileExists(hostKey) && fileExists(public) {
		return nil
	}
	keygen := filepath.Join(filepath.Dir(sshdPath), "ssh-keygen.exe")
	if !fileExists(keygen) {
		keygen = "ssh-keygen"
	}
	cmd := exec.CommandContext(ctx, keygen, "-q", "-t", "ed25519", "-N", "", "-C", "remote-bridge-host", "-f", hostKey)
	hideTargetHelper(cmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("生成 SSH 主机密钥：%v (%s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildSSHConfig(port int, username, authorized, hostKey, pidFile string) string {
	clean := func(value string) string { return filepath.ToSlash(value) }
	return fmt.Sprintf("Port %d\nListenAddress 0.0.0.0\nHostKey \"%s\"\nAuthorizedKeysFile \"%s\"\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitEmptyPasswords no\nAllowUsers %s\nStrictModes yes\nPidFile \"%s\"\nLogLevel VERBOSE\n", port, clean(hostKey), clean(authorized), strings.ToLower(username), clean(pidFile))
}

func findOpenSSHExecutable() string {
	for _, path := range installedSSHCandidates() {
		if fileExists(path) {
			return path
		}
	}
	return ""
}

func discoverUSBOpenSSHPackage() (string, string) {
	executable, err := os.Executable()
	if err != nil {
		return "", ""
	}
	base := filepath.Dir(executable)
	manifest := filepath.Join(base, "packages", "openssh", "manifest.json")
	parsed, err := windows.ReadOpenSSHPackageManifest(manifest)
	if err != nil {
		return "", ""
	}
	archive := filepath.Join(filepath.Dir(manifest), parsed.Archive)
	if !fileExists(archive) {
		return "", ""
	}
	return archive, manifest
}

func sshRuntimeDirectory(planID string) string {
	programData := sshProgramDataDirectory()
	if programData == "" {
		return ""
	}
	return filepath.Join(programData, "RemoteBridge", "ssh", planID)
}

func defaultSSHStatePath() string {
	programData := sshProgramDataDirectory()
	if programData == "" {
		return ""
	}
	return filepath.Join(programData, "RemoteBridge", "ssh", "active.json")
}

func writeSSHState(path string, runtimeState *sshTargetRuntime) error {
	if runtimeState == nil {
		return errors.New("SSH runtime 为空")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	pid := 0
	if runtimeState.pid > 0 {
		pid = runtimeState.pid
	}
	data, err := json.MarshalIndent(persistedSSHState{ID: runtimeState.id, Username: runtimeState.username, Port: runtimeState.port, PID: pid, Root: runtimeState.root, Service: runtimeState.serviceName, ExpiresAt: runtimeState.expiresAt}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type persistedSSHState struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Port      int       `json:"port"`
	PID       int       `json:"pid"`
	Root      string    `json:"root"`
	Service   string    `json:"service,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func readPreviousSSHState() (*persistedSSHState, error) {
	if err := validateSSHOwnedPath(defaultSSHStatePath()); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(defaultSSHStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state persistedSSHState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if !validSSHPlanID(state.ID) || !validSSHUsername(state.Username) || state.Port != sshBridgePort || !samePath(state.Root, sshRuntimeDirectory(state.ID)) || (state.Service != "" && state.Service != sshServiceName(state.ID)) {
		return nil, errors.New("旧 SSH 状态的所有权或路径无效，未执行清理")
	}
	if err := validateSSHOwnedPath(state.Root); err != nil {
		return nil, err
	}
	return &state, nil
}

// cleanupPreviousSSH makes repeated USB launches recoverable.  It only acts
// on the plan marker and processes whose image belongs to its validated root; it
// never stops the administrator's normal sshd service on port 22.
func cleanupPreviousSSH(ctx context.Context) error {
	path := defaultSSHStatePath()
	state, err := readPreviousSSHState()
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}
	if state.Service != "" {
		if err := stopSSHService(ctx, state.Service, state.ID, state.Root); err != nil {
			return err
		}
	}
	if err := cleanupSSHProcesses(ctx, state.ID, state.Root); err != nil {
		return err
	}
	var failures []error
	for _, err := range []error{removeSSHFirewall(ctx, state.ID), removeSSHDiscoveryFirewall(ctx, state.ID), removeSSHAccount(ctx, state.Username, state.ID)} {
		if err != nil {
			failures = append(failures, err)
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if err := os.RemoveAll(state.Root); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// cleanupPreviousWinRM removes a prior plan that owns the fixed RemoteBridge
// account before the SSH experiment reuses that account name.  It is called
// only after the interactive SSH confirmation, and it rebuilds revoke
// commands from validated state metadata rather than executing state-file
// command text.  The successfully revoked state is archived for audit so the
// next USB launch does not try to revoke it again after the account has been
// repurposed by SSH.
func cleanupPreviousWinRM(ctx context.Context) error {
	statePath := defaultStatePath()
	present, err := stateFilePresent(statePath)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	plan, err := loadState(statePath)
	if err != nil {
		return fmt.Errorf("读取旧 WinRM 状态：%w", err)
	}
	if plan.Options.TemporaryUser != windows.DefaultTemporaryUser {
		return nil
	}
	if err := invalidateWinRMLease(plan.ID); err != nil {
		return err
	}
	report, revokeErr := windows.Revoke(ctx, windows.NewRunner(), plan)
	appendExecutionAudit("target.ssh.cleanup-winrm", plan, report, revokeErr)
	if revokeErr != nil {
		return fmt.Errorf("撤销旧 WinRM 计划 %s：%w", plan.ID, revokeErr)
	}
	archive := statePath + ".revoked-" + plan.ID
	if err := os.Rename(statePath, archive); err != nil {
		return fmt.Errorf("归档旧 WinRM 状态：%w", err)
	}
	fmt.Printf("旧 WinRM 计划 %s 已清理并归档为 %s\n", plan.ID, archive)
	return nil
}

func validSSHPlanID(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func validSSHUsername(value string) bool {
	return value == windows.DefaultTemporaryUser
}

func validSSHRoot(value string) bool {
	value = filepath.Clean(strings.TrimSpace(value))
	return value != "." && !strings.ContainsAny(value, "\r\n\x00") && strings.Contains(strings.ToLower(filepath.ToSlash(value)), "/remotebridge/ssh/")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func samePathOrChild(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	if runtime.GOOS == "windows" {
		root = strings.ToLower(root)
		candidate = strings.ToLower(candidate)
	}
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}

func newSSHPlanID() (string, error) {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "ssh-" + hex.EncodeToString(raw[:]), nil
}
