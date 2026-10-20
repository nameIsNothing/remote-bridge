// bridge-target is the one-shot helper that runs on the Windows target.
//
// plan/inspect do not change system configuration; apply and the confirmed
// interactive wizards prepare temporary access. revoke/rollback remove only
// WinRM resources carrying the plan's ownership marker.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"remote-bridge/internal/audit"
	"remote-bridge/internal/cliutil"
	"remote-bridge/internal/discovery"
	"remote-bridge/internal/instructions"
	"remote-bridge/internal/model"
	"remote-bridge/internal/platform/windows"
)

const version = "0.2.9-test.1"

// simpleLANManagementAddress is the Windows firewall alias for all active
// local subnets.  The simple experiment mode deliberately uses this alias so
// the target wizard does not need to ask for a management-machine address.
// It is intentionally kept at the CLI boundary; strict mode continues to
// accept a concrete management IP/CIDR through --manager-ip.
const simpleLANManagementAddress = "LocalSubnet"

type targetFlags struct {
	managerAddress   string
	simpleLAN        bool
	transport        string
	allowHTTP        bool
	enableDiscovery  bool
	configure        bool
	id               string
	user             string
	currentUser      bool
	currentPrincipal string
	currentSID       string
	ttl              string
	state            string
	targetAddress    string
	jsonOutput       bool
	showSecret       bool
	replaceState     bool
	instructionsDir  string
}

// localAddress describes an address that a management machine can use to
// reach this target. Keeping the interface and mask alongside the address is
// useful when a target has both Ethernet and Wi-Fi adapters: the operator can
// distinguish the address that belongs to the LAN being tested instead of
// copying an arbitrary value from ipconfig.
type localAddress struct {
	Interface string
	Address   string
	CIDR      string
	Netmask   string
}

func main() {
	attachTargetConsole()
	os.Exit(runWithDiagnostics(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return runInteractive()
	}
	switch strings.ToLower(args[0]) {
	case "gui":
		return runGUI(args[1:])
	case "ssh-service":
		return runSSHServiceHost(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("bridge-target %s\n", version)
		return int(model.ExitOK)
	case "plan":
		return runPlan(args[1:])
	case "inspect", "check":
		return runInspect(args[1:])
	case "apply":
		return runApply(args[1:])
	case "ssh":
		return runSSHInteractive()
	case "winrm":
		return runWinRMInteractive()
	case "--apply":
		// Flag-shaped alias keeps the safety boundary obvious in scripts while
		// the subcommand form remains easier to discover interactively.
		return runApply(args[1:])
	case "revoke", "rollback":
		return runRevoke(strings.ToLower(args[0]), args[1:])
	case "help", "--help", "-h":
		printUsage()
		return int(model.ExitOK)
	default:
		fmt.Fprintf(os.Stderr, "未知命令 %q\n\n", args[0])
		printUsage()
		return int(model.ExitUsage)
	}
}

// Double-click opens the read-only desktop check. Configuration starts only
// after the visible button/confirmation; legacy CLI wizards stay explicit.
func runInteractive() int { return runGUI(nil) }

func runWinRMInteractive() int {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Remote Bridge 目标机向导（Windows 局域网 WinRM）")
	fmt.Println("简易局域网实验模式：自动检测并准备入口，不询问管理机 IP。")
	fmt.Println("所有系统修改都需要最后确认；直接按回车执行，输入其他内容只退出。")

	// Show the target endpoint before deciding anything about the local WinRM
	// state.  The first active address is selected automatically so a USB
	// launch never turns into a multi-question network wizard.
	hostname := localHostname()
	fmt.Printf("目标机名称: %s\n", hostname)
	addresses := localIPv4Details()
	printLocalAddresses(addresses)
	fmt.Printf("WinRM 端口: %d（HTTP，局域网实验默认）\n", windows.DefaultHTTPPort)
	targetAddress := firstAddress(addresses)
	if targetAddress != "" {
		fmt.Printf("自动选择目标地址: %s\n", targetAddress)
	} else {
		fmt.Println("错误：未发现活动的非回环 IPv4，无法生成可用的局域网连接地址。")
		fmt.Println("请先连接以太网或 Wi-Fi 后重新启动；未执行任何修改。")
		return int(model.ExitConnection)
	}
	fmt.Printf("防火墙来源范围: %s（当前局域网实验模式）\n", simpleLANManagementAddress)

	configure, detectionWarning := detectListenerPreparation()
	if detectionWarning != "" {
		fmt.Printf("WinRM 检测警告：%s\n", detectionWarning)
	}
	if configure {
		if detectionWarning == "" {
			fmt.Println("未发现可用 WinRM listener；确认后将自动准备 listener。")
		} else {
			fmt.Println("无法确认 listener 状态；按简易实验模式，确认后将尝试准备 listener。")
		}
	} else {
		fmt.Println("已发现 WinRM listener；确认时不会重复配置 listener。")
	}

	plan, err := windows.BuildPlan(windows.PlanOptions{ManagementAddress: simpleLANManagementAddress, Transport: windows.TransportHTTP, AllowHTTP: true, ConfigureListener: configure, AccountTTL: 30 * time.Minute, EnableDiscovery: true})
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	statePath := defaultStatePath()
	statePresent, stateProbeErr := stateFilePresent(statePath)
	if stateProbeErr != nil {
		fmt.Printf("状态文件检查警告：%v\n", stateProbeErr)
	} else if statePresent {
		fmt.Printf("检测到旧计划状态文件：%s\n", statePath)
		fmt.Println("确认后将先撤销旧计划，再覆盖状态文件创建新的连接入口。")
	}
	printInteractivePlanSummary(plan, targetAddress)
	fmt.Print("确认执行配置？直接按回车执行，输入其他内容取消: ")
	if !interactiveApplyConfirmed(reader) {
		fmt.Println("未执行任何修改。")
		return int(model.ExitOK)
	}
	if stateProbeErr != nil {
		fmt.Println("无法安全确认旧状态，本次未执行 apply。")
		fmt.Println("请检查状态文件路径和权限后重试；未覆盖任何文件。")
		_, _ = reader.ReadString('\n')
		return int(model.ExitInternal)
	}
	args := []string{"--simple-lan", "--allow-http", "--enable-discovery", "--ttl", "30m", "--id", plan.ID}
	if statePresent {
		fmt.Println("正在撤销旧计划，完成后继续创建新计划...")
		cleanupCode := runRevoke("revoke", []string{"--state", statePath, "--json"})
		if cleanupCode != int(model.ExitOK) {
			fmt.Println("旧计划撤销失败，本次未覆盖状态文件，也未创建新入口。")
			fmt.Println("请根据上面的清理报告处理后再重试；按回车关闭窗口。")
			_, _ = reader.ReadString('\n')
			return cleanupCode
		}
		args = append(args, "--replace-state")
	}
	if targetAddress != "" {
		args = append(args, "--target-address", targetAddress)
	}
	if configure {
		args = append(args, "--configure-listener")
	}
	exitCode := runApply(args)
	var responder *targetDiscoveryResponder
	if exitCode == int(model.ExitOK) {
		announcement := buildDiscoveryAnnouncement(plan, targetAddress, localIPv4Details(), time.Now().UTC())
		var responderErr error
		responder, responderErr = startTargetDiscoveryResponder(announcement, defaultStatePath())
		if responderErr != nil {
			fmt.Fprintf(os.Stderr, "提示：UDP 自动发现未启动（远程入口仍可直接连接）：%v\n", responderErr)
		} else {
			fmt.Printf("UDP 自动发现已开启：端口 %d；仅在本窗口和有效期内响应。\n", discovery.DefaultPort)
		}
	}
	fmt.Println()
	if exitCode == int(model.ExitOK) {
		fmt.Println("向导已完成；请记录上面的账号、密码和状态文件路径。按回车关闭窗口。")
	} else {
		fmt.Println("本次 apply 未完成；未启动 UDP 自动发现。按回车关闭窗口。")
	}
	_, _ = reader.ReadString('\n')
	if responder != nil {
		responder.Stop()
		fmt.Println("UDP 自动发现已停止。")
	}
	return exitCode
}

// buildDiscoveryAnnouncement deliberately contains connection metadata only.
// In particular, the one-time password is never included in a UDP packet.
func buildDiscoveryAnnouncement(plan windows.Plan, targetAddress string, addresses []localAddress, now time.Time) discovery.Announcement {
	allAddresses := addressStrings(addresses)
	preferred := strings.TrimSpace(targetAddress)
	if preferred == "" {
		preferred = firstAddress(addresses)
	}
	if preferred != "" {
		ordered := []string{preferred}
		for _, address := range allAddresses {
			if !strings.EqualFold(address, preferred) {
				ordered = append(ordered, address)
			}
		}
		allAddresses = ordered
	}
	return discovery.Announcement{
		V:          discovery.Version,
		Type:       discovery.AnnouncementType,
		InstanceID: plan.ID,
		Hostname:   localHostname(),
		Addresses:  allAddresses,
		Port:       plan.Options.Port,
		Transport:  string(plan.Options.Transport),
		Username:   planUsername(plan.Options),
		ExpiresAt:  now.Add(plan.Options.AccountTTL),
	}
}

type targetDiscoveryResponder struct {
	conn   *net.UDPConn
	cancel context.CancelFunc
	done   chan struct{}
	state  string
}

// startTargetDiscoveryResponder starts a visible, short-lived responder. It
// is intentionally called only by the interactive wizard; direct apply does
// not create a background listener. The expiry timer closes the socket even
// if the operator forgets to close the wizard window.
func startTargetDiscoveryResponder(announcement discovery.Announcement, statePath string) (*targetDiscoveryResponder, error) {
	return startTargetDiscoveryResponderWithPairing(announcement, statePath, nil)
}

func startTargetDiscoveryResponderWithPairing(announcement discovery.Announcement, statePath string, handler discovery.PairHandler) (*targetDiscoveryResponder, error) {
	if err := announcement.Validate(); err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: discovery.DefaultPort})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &targetDiscoveryResponder{conn: conn, cancel: cancel, done: make(chan struct{}), state: statePath}
	go func() {
		defer close(r.done)
		if err := discovery.ServeResponderWithPairing(ctx, conn, announcement, handler); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "UDP 自动发现已停止：%v\n", err)
		}
	}()
	go func() {
		timer := time.NewTimer(time.Until(announcement.ExpiresAt))
		defer timer.Stop()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-timer.C:
				r.Stop()
				return
			case <-ticker.C:
				if discoveryRevoked(statePath) {
					r.Stop()
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return r, nil
}

func discoveryRevocationMarker(statePath string) string {
	if strings.TrimSpace(statePath) == "" {
		return ""
	}
	return statePath + ".revoked"
}

func discoveryRevoked(statePath string) bool {
	marker := discoveryRevocationMarker(statePath)
	if marker == "" {
		return false
	}
	_, err := os.Stat(marker)
	return err == nil
}

func (r *targetDiscoveryResponder) Stop() {
	if r == nil {
		return
	}
	r.cancel()
	_ = r.conn.Close()
	select {
	case <-r.done:
	case <-time.After(time.Second):
	}
}

// interactiveApplyConfirmed accepts only a successfully read, complete blank
// line. EOF, other read errors, and non-empty input cancel both target wizards.
func interactiveApplyConfirmed(reader *bufio.Reader) bool {
	input, err := reader.ReadString('\n')
	return err == nil && strings.TrimSpace(input) == ""
}

// printInteractivePlanSummary keeps the double-click path readable.  The
// complete, secret-free plan remains available through `bridge-target plan`;
// the USB wizard only needs to show the values that affect this experiment.
func printInteractivePlanSummary(plan windows.Plan, targetAddress string) {
	fmt.Println("\n即将准备的连接：")
	if strings.TrimSpace(targetAddress) == "" {
		fmt.Println("  目标地址: 启动后从本机活动 IPv4 中自动选择")
	} else {
		fmt.Printf("  目标地址: %s\n", targetAddress)
	}
	fmt.Printf("  WinRM: %s / TCP %d\n", plan.Options.Transport, plan.Options.Port)
	fmt.Printf("  防火墙来源: %s\n", plan.Options.ManagementAddress)
	if plan.Options.CurrentUser {
		fmt.Printf("  当前账号: %s（仅校验身份，约 %s 后过期）\n", plan.Options.CurrentUserPrincipal, plan.Options.AccountTTL)
	} else {
		fmt.Printf("  临时账号: %s（约 %s 后过期）\n", plan.Options.TemporaryUser, plan.Options.AccountTTL)
	}
	if plan.Options.ConfigureListener {
		fmt.Println("  listener: 确认后自动准备（仅在缺失或无法确认时尝试）")
	} else {
		fmt.Println("  listener: 使用现有 listener，不重复配置")
	}
	if plan.Options.EnableDiscovery {
		fmt.Printf("  UDP 发现: 端口 %d，仅在本窗口和有效期内响应\n", discovery.DefaultPort)
	}
	for _, warning := range plan.Warnings {
		fmt.Printf("  提示: %s\n", warning)
	}
}

func detectListenerPreparation() (bool, string) {
	status, err := windows.DetectWinRM(context.Background(), windows.NewRunner())
	return listenerPreparationDecision(status, err)
}

func listenerPreparationDecision(status windows.WinRMStatus, detectErr error) (bool, string) {
	if detectErr != nil || !status.Known {
		message := "自动检测未能确认 listener 状态"
		if strings.TrimSpace(status.Error) != "" {
			message += "：" + strings.TrimSpace(status.Error)
		} else if detectErr != nil {
			message += "：" + detectErr.Error()
		}
		return true, message
	}
	if !status.ListenerPresent {
		return true, ""
	}
	if !status.HTTPListener {
		protocols := strings.Join(status.ListenerProtocols, ", ")
		ports := make([]string, 0, len(status.ListenerPorts))
		for _, port := range status.ListenerPorts {
			ports = append(ports, strconv.Itoa(port))
		}
		return false, fmt.Sprintf("检测到已有 listener（协议=%s，端口=%s），当前实验使用 HTTP/5985，未自动改动；如连接失败请改用匹配的 transport。", protocols, strings.Join(ports, ", "))
	}
	return false, ""
}

func newTargetFlagSet(name string) (*flag.FlagSet, *targetFlags) {
	values := &targetFlags{state: defaultStatePath()}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&values.managerAddress, "manager-ip", "", "管理机 IPv4/IPv6 地址或 CIDR（严格模式使用）")
	fs.BoolVar(&values.simpleLAN, "simple-lan", false, "简易局域网实验模式：省略管理机 IP，使用 LocalSubnet 和 HTTP/5985")
	fs.StringVar(&values.transport, "transport", "http", "WinRM 传输：http 或 https")
	fs.BoolVar(&values.allowHTTP, "allow-http", false, "明确确认仅在可信局域网使用 WinRM HTTP")
	fs.BoolVar(&values.enableDiscovery, "enable-discovery", false, "启用短期 UDP 局域网发现（仅建议简易实验模式）")
	fs.BoolVar(&values.configure, "configure-listener", false, "显式准备 WinRM listener（可能改变本机策略）")
	fs.StringVar(&values.id, "id", "", "计划 ID；留空自动生成")
	fs.StringVar(&values.user, "user", "", "临时本地账号名；留空自动生成")
	fs.BoolVar(&values.currentUser, "current-user", false, "使用启动向导的当前 Windows 账号，不创建临时账号")
	fs.StringVar(&values.currentPrincipal, "current-user-principal", "", "当前账号主体，例如 HOST\\user（与 --current-user 一起使用）")
	fs.StringVar(&values.currentSID, "current-user-sid", "", "当前账号 SID（可选，用于提升后身份校验）")
	fs.StringVar(&values.ttl, "ttl", "30m", "临时账号有效期，例如 30m 或 2h")
	fs.StringVar(&values.state, "state", values.state, "计划状态文件路径（不保存密码）")
	fs.StringVar(&values.targetAddress, "target-address", "", "目标地址；多网卡时指定给连接说明使用")
	fs.BoolVar(&values.jsonOutput, "json", false, "apply 时输出 JSON（默认不含一次性密码）")
	fs.BoolVar(&values.showSecret, "show-secret", false, "允许 JSON 输出一次性密码；仅用于明确的临时交接")
	fs.BoolVar(&values.replaceState, "replace-state", false, "覆盖已有状态文件（确认旧计划已 revoke 后再用）")
	fs.StringVar(&values.instructionsDir, "instructions-dir", defaultInstructionsDir(), "连接说明输出目录；默认写到 bridge-target 所在目录")
	return fs, values
}

func planOptions(values *targetFlags) (windows.PlanOptions, error) {
	transportText := strings.ToLower(strings.TrimSpace(values.transport))
	managerAddress := strings.TrimSpace(values.managerAddress)
	allowHTTP := values.allowHTTP
	if values.simpleLAN {
		// The simple mode is intentionally opinionated: it is a trusted-LAN
		// experiment, not a second way to select HTTPS or a custom port.
		transportText = string(windows.TransportHTTP)
		managerAddress = simpleLANManagementAddress
		allowHTTP = true
	}
	transport := windows.Transport(transportText)
	if transport != windows.TransportHTTP && transport != windows.TransportHTTPS {
		return windows.PlanOptions{}, fmt.Errorf("transport 必须是 http 或 https")
	}
	ttl, err := time.ParseDuration(strings.TrimSpace(values.ttl))
	if err != nil {
		return windows.PlanOptions{}, fmt.Errorf("ttl 无效：%w", err)
	}
	return windows.PlanOptions{
		ID:                   strings.TrimSpace(values.id),
		ManagementAddress:    managerAddress,
		Transport:            transport,
		TemporaryUser:        strings.TrimSpace(values.user),
		AccountTTL:           ttl,
		ConfigureListener:    values.configure,
		AllowHTTP:            allowHTTP,
		EnableDiscovery:      values.enableDiscovery,
		CurrentUser:          values.currentUser,
		CurrentUserPrincipal: strings.TrimSpace(values.currentPrincipal),
		CurrentUserSID:       strings.TrimSpace(values.currentSID),
	}, nil
}

func runPlan(args []string) int {
	fs, values := newTargetFlagSet("bridge-target plan")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	options, err := planOptions(values)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	plan, err := windows.BuildPlan(options)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	if err := printJSON(plan); err != nil {
		return fail(model.ExitInternal, err)
	}
	return int(model.ExitOK)
}

func runInspect(args []string) int {
	fs, values := newTargetFlagSet("bridge-target inspect")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	options, err := planOptions(values)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	report, inspectErr := windows.Inspect(context.Background(), windows.NewRunner(), options)
	appendInspectionAudit(report, inspectErr)
	if err := printJSON(report); err != nil {
		return fail(model.ExitInternal, err)
	}
	if inspectErr != nil {
		if errors.Is(inspectErr, windows.ErrUnsupported) {
			return int(model.ExitConnection)
		}
		return int(model.ExitCheckFailed)
	}
	return int(model.ExitOK)
}

func runApply(args []string) int {
	fs, values := newTargetFlagSet("bridge-target apply")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	if values.simpleLAN && !values.configure {
		// Keep the non-interactive simple-lan form useful as well. The target
		// wizard has already made this decision before displaying confirmation, while a
		// direct `apply --simple-lan` invocation needs to make it here.
		configure, detectionWarning := detectListenerPreparation()
		if detectionWarning != "" {
			fmt.Fprintf(os.Stderr, "WinRM 检测警告：%s\n", detectionWarning)
		}
		values.configure = configure
	}
	options, err := planOptions(values)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	if options.Transport == windows.TransportHTTP && !options.AllowHTTP {
		return fail(model.ExitUsage, errors.New("使用 HTTP 必须显式加 --allow-http；局域网实验请确认网络可信"))
	}
	plan, err := windows.BuildPlan(options)
	if err != nil {
		return fail(model.ExitUsage, err)
	}
	// Write the secret-free plan before making any change. If apply is partial,
	// the same state file is immediately available for revoke/rollback.
	if err := writeState(values.state, plan, values.replaceState); err != nil {
		return fail(model.ExitInternal, fmt.Errorf("写入状态文件：%w", err))
	}
	// A successful replacement starts a fresh lifecycle. Remove the marker
	// left by a prior revoke so an interactive responder can run again.
	_ = os.Remove(discoveryRevocationMarker(values.state))
	var secret string
	var runner windows.Runner = windows.NewRunner()
	if !plan.Options.CurrentUser {
		secret, err = randomSecret(24)
		if err != nil {
			return fail(model.ExitInternal, fmt.Errorf("生成一次性密码：%w", err))
		}
		runner = cliutil.NewPasswordRunner(secret, plan.Options.PasswordEnv)
	}
	report, applyErr := windows.Apply(context.Background(), runner, plan)
	appendExecutionAudit("target.apply", plan, report, applyErr)
	if applyErr != nil {
		_ = printJSON(report)
		fmt.Fprintln(os.Stderr, "应用未完成；状态文件已保留，请检查报告后运行 revoke/rollback 清理已完成步骤。")
		return int(model.ExitCheckFailed)
	}
	addresses := localIPv4Details()
	instructionResult, instructionsErr := exportInstructions(plan, values, addresses)
	if instructionsErr != nil {
		// The Windows changes are already complete. Do not turn an instruction
		// file permission problem (for example a read-only USB drive) into a
		// failed apply or attempt a rollback; surface it clearly so the operator
		// can retry with --instructions-dir.
		fmt.Fprintf(os.Stderr, "警告：连接说明导出失败（远程入口已准备完成）：%v\n", instructionsErr)
	}
	if values.jsonOutput {
		selectedAddress := values.targetAddress
		if strings.TrimSpace(selectedAddress) == "" {
			selectedAddress = firstAddress(addresses)
		}
		output := map[string]any{
			"plan_id":               plan.ID,
			"simple_lan":            values.simpleLAN,
			"management_address":    plan.Options.ManagementAddress,
			"configure_listener":    plan.Options.ConfigureListener,
			"target_addresses":      addressStrings(addresses),
			"target_address":        selectedAddress,
			"transport":             string(plan.Options.Transport),
			"port":                  plan.Options.Port,
			"username":              planUsername(plan.Options),
			"current_user":          plan.Options.CurrentUser,
			"expires_at":            time.Now().UTC().Add(plan.Options.AccountTTL),
			"state":                 values.state,
			"instructions_dir":      values.instructionsDir,
			"instructions_exported": instructionsErr == nil,
			"instructions": map[string]any{
				"markdown": instructionResult.MarkdownPath,
				"json":     instructionResult.JSONPath,
			},
			"report":  report,
			"warning": "默认不输出一次性密码；人机交互模式会显示一次，请勿写入日志或提交到仓库",
		}
		if instructionsErr != nil {
			output["instructions_error"] = instructionsErr.Error()
			output["warning"] = "远程入口已准备，但连接说明未写入；请检查 instructions_dir 或使用 --instructions-dir 重试"
		}
		if values.showSecret && !plan.Options.CurrentUser {
			output["pairing_password"] = secret
			output["warning"] = "pairing_password 仅因 --show-secret 显示；请勿写入日志或提交到仓库"
		}
		if err := printJSON(output); err != nil {
			return fail(model.ExitInternal, err)
		}
		return int(model.ExitOK)
	}
	printApplyResult(plan, values, secret, report, instructionResult)
	return int(model.ExitOK)
}

func runRevoke(command string, args []string) int {
	fs := flag.NewFlagSet("bridge-target "+command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	state := defaultStatePath()
	jsonOutput := false
	fs.StringVar(&state, "state", state, "计划状态文件路径")
	fs.BoolVar(&jsonOutput, "json", false, "输出 JSON")
	if err := fs.Parse(args); err != nil {
		return int(model.ExitUsage)
	}
	plan, err := loadState(state)
	if err != nil {
		return fail(model.ExitNotFound, err)
	}
	if err := invalidateWinRMLease(plan.ID); err != nil {
		return fail(model.ExitCheckFailed, err)
	}
	var report windows.ExecutionReport
	if command == "rollback" {
		report, err = windows.Rollback(context.Background(), windows.NewRunner(), plan)
	} else {
		report, err = windows.Revoke(context.Background(), windows.NewRunner(), plan)
	}
	appendExecutionAudit("target."+command, plan, report, err)
	// Revoke reports are always JSON so they can be retained as an audit
	// record; --json is accepted for symmetry with apply.
	_ = jsonOutput
	if printErr := printJSON(report); printErr != nil {
		return fail(model.ExitInternal, printErr)
	}
	if err != nil {
		return int(model.ExitCheckFailed)
	}
	// The interactive target process may still be displaying its hand-off
	// window. A small sidecar marker lets that process stop its UDP responder
	// without requiring a hidden service or an IPC endpoint.
	if marker := discoveryRevocationMarker(state); marker != "" {
		_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0600)
	}
	fmt.Fprintln(os.Stderr, "清理完成；状态文件保留用于审计。")
	return int(model.ExitOK)
}

func appendInspectionAudit(report windows.InspectionReport, runErr error) {
	metadata := map[string]string{
		"plan_id":   report.PlanID,
		"steps":     fmt.Sprintf("%d", len(report.Steps)),
		"supported": fmt.Sprintf("%t", report.Supported),
	}
	if runErr != nil {
		metadata["failed"] = "true"
	}
	_ = audit.Append(audit.DefaultPath(), model.AuditEvent{Type: "target.inspect", Success: runErr == nil, Metadata: metadata})
}

func appendExecutionAudit(eventType string, plan windows.Plan, report windows.ExecutionReport, runErr error) {
	metadata := map[string]string{
		"plan_id": plan.ID,
		"steps":   fmt.Sprintf("%d", len(report.Steps)),
	}
	for _, step := range report.Steps {
		if step.Error != "" {
			metadata["failed_step"] = step.ActionID
			break
		}
	}
	_ = audit.Append(audit.DefaultPath(), model.AuditEvent{Type: eventType, Success: runErr == nil, Metadata: metadata})
}

func loadState(path string) (windows.Plan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return windows.Plan{}, err
	}
	var stored windows.Plan
	if err := json.Unmarshal(data, &stored); err != nil {
		return windows.Plan{}, fmt.Errorf("解析状态文件：%w", err)
	}
	if stored.Version != 1 || strings.TrimSpace(stored.ID) == "" || stored.Options.ID != stored.ID {
		return windows.Plan{}, errors.New("状态文件版本或计划 ID 无效")
	}
	// Do not execute PowerShell text read from a file. Rebuild the commands
	// from validated scalar options, then use only the fresh plan's revoke
	// steps. This keeps the state file metadata-only and tamper-resistant.
	options := windows.PlanOptions{
		ID:                   stored.Options.ID,
		ManagementAddress:    stored.Options.ManagementAddress,
		Transport:            stored.Options.Transport,
		Port:                 stored.Options.Port,
		FirewallProfile:      stored.Options.FirewallProfile,
		FirewallGroup:        stored.Options.FirewallGroup,
		FirewallRule:         stored.Options.FirewallRule,
		TemporaryUser:        stored.Options.TemporaryUser,
		PasswordEnv:          stored.Options.PasswordEnv,
		AccountTTL:           stored.Options.AccountTTL,
		ConfigureListener:    stored.Options.ConfigureListener,
		AllowHTTP:            stored.Options.AllowHTTP,
		EnableDiscovery:      stored.Options.EnableDiscovery,
		CurrentUser:          stored.Options.CurrentUser,
		CurrentUserPrincipal: stored.Options.CurrentUserPrincipal,
		CurrentUserSID:       stored.Options.CurrentUserSID,
	}
	plan, err := windows.BuildPlan(options)
	if err != nil {
		return windows.Plan{}, fmt.Errorf("状态选项无效：%w", err)
	}
	if plan.ID != stored.ID {
		return windows.Plan{}, errors.New("状态文件计划 ID 不匹配")
	}
	return plan, nil
}

func writeState(path string, plan windows.Plan, replace bool) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("状态文件路径不能为空")
	}
	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}
	if _, err := os.Stat(path); err == nil && !replace {
		return errors.New("状态文件已存在；先 revoke 旧计划，或明确使用 --replace-state")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return err
	}
	return nil
}

// stateFilePresent probes the metadata-only plan path without opening or
// mutating it. The interactive wizard uses this to decide whether an explicit
// confirmation should first revoke an older plan before replacing the file.
func stateFilePresent(path string) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, errors.New("状态文件路径不能为空")
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return true, fmt.Errorf("状态文件路径是目录：%s", path)
	}
	return true, nil
}

func printApplyResult(plan windows.Plan, values *targetFlags, secret string, report windows.ExecutionReport, instructionResult instructions.Result) {
	fmt.Println("Remote Bridge 局域网 WinRM 已准备")
	fmt.Printf("计划 ID: %s\n", plan.ID)
	fmt.Printf("传输: %s / TCP %d\n", plan.Options.Transport, plan.Options.Port)
	addresses := addressStrings(localIPv4Details())
	selectedAddress := strings.TrimSpace(values.targetAddress)
	if selectedAddress == "" {
		selectedAddress = firstString(addresses)
	}
	if selectedAddress == "" {
		selectedAddress = "未发现"
	}
	fmt.Printf("目标地址: %s\n", selectedAddress)
	if len(addresses) > 1 && strings.TrimSpace(values.targetAddress) == "" {
		fmt.Printf("其他本机地址: %s\n", strings.Join(addresses[1:], ", "))
	}
	if values.targetAddress == "" && len(addresses) > 1 {
		fmt.Fprintln(os.Stderr, "提示：检测到多个网卡；说明文件默认使用第一个地址，如需指定请重新运行时加 --target-address <地址>")
	}
	if plan.Options.CurrentUser {
		fmt.Printf("当前账号: %s\n", plan.Options.CurrentUserPrincipal)
		fmt.Println("管理端会在连接时提示输入该账号密码；目标机不会创建或修改账号。")
	} else {
		fmt.Printf("临时账号: %s\n", plan.Options.TemporaryUser)
		fmt.Printf("一次性连接密码（只显示本次）: %s\n", secret)
	}
	fmt.Printf("有效期约: %s\n", plan.Options.AccountTTL)
	fmt.Printf("状态文件: %s\n", values.state)
	qualifiedUser := "目标主机名\\" + planUsername(plan.Options)
	fmt.Println("管理机运行：bridge-cli exec --target <目标地址> --port", plan.Options.Port, "--username", qualifiedUser, "--command <命令>")
	fmt.Printf("AI 连接说明目录: %s\n", values.instructionsDir)
	if instructionResult.MarkdownPath != "" {
		fmt.Printf("AI 连接说明: %s\n", instructionResult.MarkdownPath)
		fmt.Printf("机器可读连接信息: %s\n", instructionResult.JSONPath)
	}
	fmt.Printf("完成后在目标机运行：bridge-target revoke --state %q\n", values.state)
	if len(report.Steps) == 0 {
		fmt.Fprintln(os.Stderr, "警告：没有执行步骤")
	}
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return "未知"
	}
	return strings.TrimSpace(hostname)
}

func printLocalAddresses(addresses []localAddress) {
	if len(addresses) == 0 {
		fmt.Println("本机可连接 IPv4: 未发现活动的非回环 IPv4 地址")
		return
	}
	fmt.Println("本机可连接 IPv4:")
	for index, address := range addresses {
		label := address.Interface
		if strings.TrimSpace(label) == "" {
			label = "未知网卡"
		}
		if address.CIDR != "" && address.Netmask != "" {
			fmt.Printf("  %d. %s  (%s, 掩码 %s)\n", index+1, address.Address, label, address.Netmask)
		} else if address.CIDR != "" {
			fmt.Printf("  %d. %s  (%s)\n", index+1, address.CIDR, label)
		} else {
			fmt.Printf("  %d. %s  (%s)\n", index+1, address.Address, label)
		}
	}
}

func chooseTargetAddress(reader *bufio.Reader, addresses []localAddress) (string, bool) {
	if len(addresses) == 0 {
		return "", true
	}
	if len(addresses) == 1 {
		return addresses[0].Address, true
	}
	fmt.Print("选择目标地址编号 [1]（直接回车使用第一个）: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", false
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return addresses[0].Address, true
	}
	index, err := strconv.Atoi(text)
	if err != nil || index < 1 || index > len(addresses) {
		fmt.Printf("目标地址编号无效，应为 1-%d。\n", len(addresses))
		return "", false
	}
	return addresses[index-1].Address, true
}

func localIPv4Details() []localAddress {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	addresses := make([]localAddress, 0)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		items, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, item := range items {
			ip, network, ok := parseLocalIPv4(item)
			if !ok || ip.IsLoopback() {
				continue
			}
			entry := localAddress{Interface: iface.Name, Address: ip.String()}
			if network != nil {
				entry.CIDR = network.String()
				mask := network.Mask
				if len(mask) == net.IPv4len {
					entry.Netmask = net.IP(mask).String()
				} else if mask4 := maskToIPv4(mask); mask4 != nil {
					entry.Netmask = mask4.String()
				}
			}
			addresses = append(addresses, entry)
		}
	}
	return addresses
}

func parseLocalIPv4(address net.Addr) (net.IP, *net.IPNet, bool) {
	switch value := address.(type) {
	case *net.IPNet:
		ip := value.IP.To4()
		if ip == nil {
			return nil, nil, false
		}
		return ip, &net.IPNet{IP: ip, Mask: value.Mask}, true
	case *net.IPAddr:
		ip := value.IP.To4()
		if ip == nil {
			return nil, nil, false
		}
		return ip, nil, true
	default:
		return nil, nil, false
	}
}

func maskToIPv4(mask net.IPMask) net.IP {
	if len(mask) == net.IPv4len {
		return net.IPv4(mask[0], mask[1], mask[2], mask[3]).To4()
	}
	return nil
}

func addressStrings(addresses []localAddress) []string {
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if strings.TrimSpace(address.Address) != "" {
			result = append(result, address.Address)
		}
	}
	return result
}

func firstAddress(addresses []localAddress) string {
	best := ""
	bestScore := -1 << 30
	for index, address := range addresses {
		value := strings.TrimSpace(address.Address)
		if value == "" {
			continue
		}
		score := addressPriority(address)
		// Keep interface enumeration order as the final tie breaker so output
		// remains stable on machines with equally suitable adapters.
		score -= index
		if best == "" || score > bestScore {
			best, bestScore = value, score
		}
	}
	return best
}

func addressPriority(address localAddress) int {
	score := 0
	name := strings.ToLower(strings.TrimSpace(address.Interface))
	for _, marker := range []string{"vmware", "vethernet", "wsl", "virtual", "hyper-v", "loopback"} {
		if strings.Contains(name, marker) {
			score -= 100
			break
		}
	}
	for _, marker := range []string{"ethernet", "wi-fi", "wifi", "wlan", "wireless"} {
		if strings.Contains(name, marker) {
			score += 20
			break
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(address.Address)).To4(); ip != nil {
		if ip[0] == 169 && ip[1] == 254 {
			score -= 50
		}
		if ip[0] == 192 && ip[1] == 168 {
			score += 5
		} else if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
			score += 3
		}
	}
	return score
}

func firstString(values []string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}

func planUsername(options windows.NormalizedOptions) string {
	if options.CurrentUser {
		return strings.TrimSpace(options.CurrentUserPrincipal)
	}
	return strings.TrimSpace(options.TemporaryUser)
}

// localIPv4Addresses remains the compact form used by the JSON compatibility
// output and by callers that only need a list of target endpoints.
func localIPv4Addresses() []string {
	return addressStrings(localIPv4Details())
}

func defaultInstructionsDir() string {
	if executable, err := os.Executable(); err == nil {
		if directory := strings.TrimSpace(filepath.Dir(executable)); directory != "" && directory != "." {
			return directory
		}
	}
	return "."
}

func exportInstructions(plan windows.Plan, values *targetFlags, addresses []localAddress) (instructions.Result, error) {
	if values == nil {
		return instructions.Result{}, errors.New("目标机参数不能为空")
	}
	hostname := localHostname()
	allAddresses := addressStrings(addresses)
	address := strings.TrimSpace(values.targetAddress)
	if address == "" && len(allAddresses) > 0 {
		address = allAddresses[0]
	}
	targetBinary := "bridge-target.exe"
	if executable, err := os.Executable(); err == nil && strings.TrimSpace(executable) != "" {
		targetBinary = filepath.Base(executable)
	}
	cliPath := "bridge-cli.exe"
	if strings.TrimSpace(values.instructionsDir) == "" {
		values.instructionsDir = defaultInstructionsDir()
	}
	qualifiedUser := planUsername(plan.Options)
	if !plan.Options.CurrentUser && hostname != "" && hostname != "未知" {
		qualifiedUser = hostname + "\\" + plan.Options.TemporaryUser
	}
	request := instructions.Request{
		PlanID:    plan.ID,
		Hostname:  hostname,
		Address:   address,
		Addresses: allAddresses,
		Port:      plan.Options.Port,
		Transport: string(plan.Options.Transport),
		Username:  qualifiedUser,
		ExpiresAt: time.Now().UTC().Add(plan.Options.AccountTTL),
		StatePath: values.state,
		// The target and management machines can assign different drive letters
		// to the same USB stick. Export portable basenames rather than an
		// absolute target-side path; the generated instructions resolve them
		// relative to their own directory.
		TargetBinary: filepath.Base(targetBinary),
		CLIPath:      filepath.Base(cliPath),
		OutputDir:    values.instructionsDir,
	}
	result, exportErr := instructions.Export(request)
	if exportErr == nil {
		return result, nil
	}
	// A removable drive may be read-only.  Retry in the per-user cache so the
	// completed remote setup still leaves the operator with a usable hand-off.
	fallback := defaultFallbackInstructionsDir()
	if samePath(request.OutputDir, fallback) {
		return result, exportErr
	}
	request.OutputDir = fallback
	fallbackResult, fallbackErr := instructions.Export(request)
	if fallbackErr != nil {
		return result, fmt.Errorf("写入连接说明失败：%v；回退目录 %q 也失败：%w", exportErr, fallback, fallbackErr)
	}
	values.instructionsDir = fallback
	fmt.Fprintf(os.Stderr, "提示：原连接说明目录不可写，已回退到用户缓存目录：%s\n", fallback)
	return fallbackResult, nil
}

func defaultFallbackInstructionsDir() string {
	if cache, err := os.UserCacheDir(); err == nil && strings.TrimSpace(cache) != "" {
		return filepath.Join(cache, "RemoteBridge", "instructions")
	}
	return filepath.Join(filepath.Dir(defaultStatePath()), "instructions")
}

func samePath(first, second string) bool {
	first = filepath.Clean(strings.TrimSpace(first))
	second = filepath.Clean(strings.TrimSpace(second))
	return strings.EqualFold(first, second)
}

func randomSecret(length int) (string, error) {
	if length < 16 {
		return "", errors.New("secret length must be at least 16")
	}
	// Keep the alphabet PowerShell/WinRM friendly while satisfying the usual
	// Windows local-password complexity policy.
	alphabet := "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%+="
	result := make([]byte, length)
	// Seed one character from each common complexity class, then shuffle with
	// crypto/rand so a rare all-lowercase/all-digit result cannot be rejected by
	// the local account policy.
	for i, required := range []byte{'A', 'a', '2', '!'} {
		result[i] = required
	}
	for i := 4; i < len(result); i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		result[i] = alphabet[n.Int64()]
	}
	for i := len(result) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := int(n.Int64())
		result[i], result[j] = result[j], result[i]
	}
	return string(result), nil
}

func defaultStatePath() string {
	// A USB drive can be read-only. Keep the metadata-only state file in the
	// current user's cache by default; --state remains available when an
	// operator needs a removable/auditable copy.
	if cache, err := os.UserCacheDir(); err == nil && strings.TrimSpace(cache) != "" {
		return filepath.Join(cache, "RemoteBridge", "bridge-plan.json")
	}
	if executable, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(executable), "bridge-plan.json")
	}
	return "bridge-plan.json"
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func fail(code model.ExitCode, err error) int {
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
	}
	return int(code)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `用法：
  bridge-target                  （默认：“检查 / 连接”桌面窗口）
  bridge-target gui              （打开桌面窗口，只读检查后确认配置）
  bridge-target ssh              （SSH 检测/安装/公钥配对向导）
  bridge-target winrm            （旧版 WinRM 局域网向导）
  bridge-target plan     --manager-ip <管理机IP> [选项]
  bridge-target inspect  --manager-ip <管理机IP> [选项]
  bridge-target apply    --manager-ip <管理机IP> --allow-http [--configure-listener]
  bridge-target apply    --simple-lan [--configure-listener] [--enable-discovery]
  bridge-target revoke   --state <bridge-plan.json>
  bridge-target rollback --state <bridge-plan.json>

plan/inspect 默认只读。只有 apply 会创建临时账号/防火墙规则；revoke/rollback 只清理本计划拥有的资源。
SSH 向导使用固定账号 RemoteBridge、一次性 Ed25519 公钥和临时 TCP 2222 入口；不会要求管理机输入密码。
首次实验建议在“以管理员身份运行”的 PowerShell 中执行，并让管理机与目标机处于同一可信局域网。
apply --json 默认隐藏密码；只有明确加 --show-secret 才会把一次性密码放进 JSON。
apply 成功后默认在目标 exe 所在目录生成 REMOTE-BRIDGE.md 和 remote-bridge-connection.json；可用 --instructions-dir 指定输出目录。`)
}
