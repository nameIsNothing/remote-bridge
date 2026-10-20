//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"remote-bridge/internal/diagnostic"
)

var (
	guiUser32        = syscall.NewLazyDLL("user32.dll")
	guiKernel32      = syscall.NewLazyDLL("kernel32.dll")
	guiGDI32         = syscall.NewLazyDLL("gdi32.dll")
	guiComctl32      = syscall.NewLazyDLL("comctl32.dll")
	guiCreateWindow  = guiUser32.NewProc("CreateWindowExW")
	guiDefWindow     = guiUser32.NewProc("DefWindowProcW")
	guiSendMessage   = guiUser32.NewProc("SendMessageW")
	guiPostMessage   = guiUser32.NewProc("PostMessageW")
	guiDestroyWindow = guiUser32.NewProc("DestroyWindow")
	guiSetText       = guiUser32.NewProc("SetWindowTextW")
	guiEnableWindow  = guiUser32.NewProc("EnableWindow")
	guiMoveWindow    = guiUser32.NewProc("MoveWindow")
	guiMoveMemory    = guiKernel32.NewProc("RtlMoveMemory")
	guiShowWindow    = guiUser32.NewProc("ShowWindow")
	guiSetFocus      = guiUser32.NewProc("SetFocus")
	guiMainProc      = syscall.NewCallback(guiWindowProc)
	guiModalProc     = syscall.NewCallback(guiDialogProc)
	guiActive        *nativeGUI
)

const (
	guiUpdate  = 0x8001
	guiInvoke  = 0x8002
	guiCheckID = 101
	guiStartID = 102
	guiStopID  = 103
	guiCopyID  = 104
	guiYesID   = 201
	guiNoID    = 202
)

// The desktop adapter owns all Win32 controls and mutates them only on its
// locked message-loop thread. Backend workers communicate through messages.
type nativeGUI struct {
	hwnd, instance                                                                   uintptr
	header, subtitle, checkTitle, checks, connectionTitle, status, details, progress uintptr
	checkButton, startButton, stopButton, copyButton, footer                         uintptr
	font, titleFont, monoFont, brush                                                 uintptr
	textColor, mutedColor                                                            uintptr
	statusColor                                                                      uintptr
	highContrast                                                                     bool
	dpi                                                                              int
	controller                                                                       *guiController
	queue                                                                            chan func()
	modal                                                                            uintptr
	modalOwner                                                                       *uint64
	autoStart, closeAfterStop                                                        bool
	winrmMode                                                                        bool
}

type guiWindowClass struct {
	Size, Style                        uint32
	Proc                               uintptr
	ClassExtra, WindowExtra            int32
	Instance, Icon, Cursor, Background uintptr
	Menu, Name                         *uint16
	SmallIcon                          uintptr
}

type guiPoint struct{ X, Y int32 }
type guiMessage struct {
	Window         uintptr
	Message        uint32
	WParam, LParam uintptr
	Time           uint32
	Point          guiPoint
	Private        uint32
}
type guiRect struct{ Left, Top, Right, Bottom int32 }
type guiMinMax struct{ Reserved, MaxSize, MaxPosition, MinTrack, MaxTrack guiPoint }
type guiColumn struct {
	Mask                                                               uint32
	Format, Width                                                      int32
	Text                                                               *uint16
	TextMax, Subitem, Image, Order, MinWidth, DefaultWidth, IdealWidth int32
}
type guiItem struct {
	Mask                    uint32
	Item, Subitem           int32
	State, StateMask        uint32
	Text                    *uint16
	TextMax, Image          int32
	Param                   uintptr
	Indent, GroupID         int32
	Columns                 uint32
	ColumnPtr, ColumnFormat uintptr
	Group                   int32
}

func guiUTF16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(strings.ReplaceAll(s, "\x00", ""))
	return p
}
func guiBool(v bool) uintptr {
	if v {
		return 1
	}
	return 0
}
func (g *nativeGUI) px(v int) int { return v * g.dpi / 96 }
func guiText(hwnd uintptr, value string) {
	guiSetText.Call(hwnd, uintptr(unsafe.Pointer(guiUTF16(value))))
}

func runGUI(args []string) int {
	auto := false
	winrmMode := true
	for _, arg := range args {
		switch arg {
		case "--configure":
			auto = true
		case "--ssh":
			winrmMode = false
		case "--winrm":
			winrmMode = true
		default:
			fmt.Fprintln(os.Stderr, "gui 接受 --configure、--winrm 或 --ssh")
			return 2
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	releaseTheme := activateGUITheme()
	defer releaseTheme()
	// Per-monitor v2 avoids blurry Chinese text and scales all native controls.
	if p := guiUser32.NewProc("SetProcessDpiAwarenessContext"); p.Find() == nil {
		p.Call(^uintptr(3))
	}
	instance, _, _ := guiKernel32.NewProc("GetModuleHandleW").Call(0)
	dpi := 96
	if p := guiUser32.NewProc("GetDpiForSystem"); p.Find() == nil {
		d, _, _ := p.Call()
		if d >= 96 {
			dpi = int(d)
		}
	}
	g := &nativeGUI{instance: instance, dpi: dpi, autoStart: auto, queue: make(chan func(), 32), winrmMode: winrmMode}
	guiActive = g
	defer func() { guiActive = nil }()
	common := struct{ Size, Classes uint32 }{8, 0x00004021}
	guiComctl32.NewProc("InitCommonControlsEx").Call(uintptr(unsafe.Pointer(&common)))
	g.textColor, g.mutedColor = guiColorText, guiColorMuted
	background := uintptr(guiColorBackground)
	contrast := struct {
		Size, Flags uint32
		Scheme      *uint16
	}{}
	contrast.Size = uint32(unsafe.Sizeof(contrast))
	guiUser32.NewProc("SystemParametersInfoW").Call(0x0042, uintptr(contrast.Size), uintptr(unsafe.Pointer(&contrast)), 0)
	if contrast.Flags&1 != 0 {
		g.highContrast = true
		background, _, _ = guiUser32.NewProc("GetSysColor").Call(5)
		g.textColor, _, _ = guiUser32.NewProc("GetSysColor").Call(8)
		g.mutedColor = g.textColor
	}
	g.brush, _, _ = guiGDI32.NewProc("CreateSolidBrush").Call(background)
	defer guiGDI32.NewProc("DeleteObject").Call(g.brush)
	for name, proc := range map[string]uintptr{"RemoteBridgeWindow": guiMainProc, "RemoteBridgeConfirmation": guiModalProc} {
		cursor, _, _ := guiUser32.NewProc("LoadCursorW").Call(0, 32512)
		icon, _, _ := guiUser32.NewProc("LoadIconW").Call(0, 32516)
		wc := guiWindowClass{Size: uint32(unsafe.Sizeof(guiWindowClass{})), Proc: proc, Instance: instance, Cursor: cursor, Icon: icon, Background: g.brush, Name: guiUTF16(name)}
		if ok, _, err := guiUser32.NewProc("RegisterClassExW").Call(uintptr(unsafe.Pointer(&wc))); ok == 0 {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "gui.create.failed", Step: "注册窗口", Error: err.Error()})
			fmt.Fprintln(os.Stderr, "创建窗口失败：", err)
			return 50
		}
	}
	w, h := g.px(940), g.px(760)
	var work guiRect
	guiUser32.NewProc("SystemParametersInfoW").Call(48, 0, uintptr(unsafe.Pointer(&work)), 0)
	if work.Right > work.Left && w > int(work.Right-work.Left)-24 {
		w = int(work.Right-work.Left) - 24
	}
	if work.Bottom > work.Top && h > int(work.Bottom-work.Top)-24 {
		h = int(work.Bottom-work.Top) - 24
	}
	hwnd, _, err := guiCreateWindow.Call(0x00010000, uintptr(unsafe.Pointer(guiUTF16("RemoteBridgeWindow"))), uintptr(unsafe.Pointer(guiUTF16("Remote Bridge · 临时远程连接"))), 0x00CF0000|0x02000000, uintptr(int(work.Left)+(int(work.Right-work.Left)-w)/2), uintptr(int(work.Top)+(int(work.Bottom-work.Top)-h)/2), uintptr(w), uintptr(h), 0, 0, instance, 0)
	if hwnd == 0 {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "gui.create.failed", Step: "打开窗口", Error: err.Error()})
		fmt.Fprintln(os.Stderr, "打开界面失败：", err)
		return 50
	}
	g.hwnd = hwnd
	g.createControls()
	var backend guiBackend = &winrmDesktopBackend{}
	if !winrmMode {
		backend = &desktopBackend{}
	}
	g.controller = newGUIController(backend, func() { guiPostMessage.Call(hwnd, guiUpdate, 0, 0) }, g.confirmPair)
	defer g.releaseFonts()
	guiShowWindow.Call(hwnd, 5)
	g.render()
	g.controller.Check()
	var msg guiMessage
	for {
		value, _, _ := guiUser32.NewProc("GetMessageW").Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(value) <= 0 {
			break
		}
		dialog := g.hwnd
		if g.modal != 0 {
			dialog = g.modal
		}
		if handled, _, _ := guiUser32.NewProc("IsDialogMessageW").Call(dialog, uintptr(unsafe.Pointer(&msg))); handled != 0 {
			continue
		}
		guiUser32.NewProc("TranslateMessage").Call(uintptr(unsafe.Pointer(&msg)))
		guiUser32.NewProc("DispatchMessageW").Call(uintptr(unsafe.Pointer(&msg)))
	}
	return 0
}

func (g *nativeGUI) control(class, text string, style uint32, id int) uintptr {
	window, _, _ := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16(class))), uintptr(unsafe.Pointer(guiUTF16(text))), uintptr(style)|0x50000000, 0, 0, 10, 10, g.hwnd, uintptr(id), g.instance, 0)
	guiSendMessage.Call(window, 0x0030, g.font, 1)
	return window
}

func (g *nativeGUI) createFont(size, weight int, family string) uintptr {
	height := -g.px(size)
	f, _, _ := guiGDI32.NewProc("CreateFontW").Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(guiUTF16(family))))
	return f
}

func (g *nativeGUI) releaseFonts() {
	for _, f := range []uintptr{g.font, g.titleFont, g.monoFont} {
		if f != 0 {
			guiGDI32.NewProc("DeleteObject").Call(f)
		}
	}
}
func (g *nativeGUI) createControls() {
	g.font = g.createFont(15, 400, guiFontBody)
	g.titleFont = g.createFont(25, 600, guiFontDisplay)
	g.monoFont = g.createFont(14, 400, guiFontUtility)
	g.header = g.control("STATIC", "Remote Bridge", 0, 0)
	guiSendMessage.Call(g.header, 0x0030, g.titleFont, 1)
	g.subtitle = g.control("STATIC", "让管理端连接这台电脑 · 局域网临时连接", 0x4000, 0)
	guiSendMessage.Call(g.subtitle, 0x0030, g.monoFont, 1)
	g.checkTitle = g.control("STATIC", "检查", 0, 0)
	g.checks = g.control("SysListView32", "配置检查结果", 0x0001|0x0004|0x0008|0x10000|0x00800000, 0)
	guiSendMessage.Call(g.checks, 0x1036, 0, 0x0020|0x00010000|0x00004000)
	for i, name := range []string{"检查项目", "结果", "说明 / 自动处理方式"} {
		column := guiColumn{Mask: 7, Width: int32(g.px([]int{120, 105, 620}[i])), Text: guiUTF16(name), Subitem: int32(i)}
		guiSendMessage.Call(g.checks, 0x1061, uintptr(i), uintptr(unsafe.Pointer(&column)))
	}
	g.connectionTitle = g.control("STATIC", "连接", 0, 0)
	g.status = g.control("STATIC", "正在检查这台电脑", 0, 0)
	g.progress = g.control("msctls_progress32", "连接进度", 0, 0)
	guiSendMessage.Call(g.progress, 0x0409, 0, guiColorPrimary)
	g.details = g.control("EDIT", "", 0x0004|0x0040|0x0800|0x200000|0x10000, 0)
	g.checkButton = g.control("BUTTON", "重新检查(&R)", 0x10000, guiCheckID)
	g.startButton = g.control("BUTTON", "配置并开始连接(&S)", 0x10000|1, guiStartID)
	g.stopButton = g.control("BUTTON", "结束连接(&E)", 0x10000, guiStopID)
	g.copyButton = g.control("BUTTON", "复制诊断信息(&D)", 0x10000, guiCopyID)
	footer := "30 分钟有效 · 仅局域网 · 确认一次后自动连接"
	if g.winrmMode {
		footer = winrmLifetimeText() + "有效 · 仅局域网 · 确认一次后自动连接"
	}
	g.footer = g.control("STATIC", footer, 0, 0)
	g.layout()
}

func (g *nativeGUI) place(hwnd uintptr, x, y, w, h int) {
	guiMoveWindow.Call(hwnd, uintptr(g.px(x)), uintptr(g.px(y)), uintptr(g.px(w)), uintptr(g.px(h)), 1)
}
func (g *nativeGUI) layout() {
	if g.header == 0 {
		return
	}
	var rect guiRect
	guiUser32.NewProc("GetClientRect").Call(g.hwnd, uintptr(unsafe.Pointer(&rect)))
	w, h := int(rect.Right)*96/g.dpi, int(rect.Bottom)*96/g.dpi
	margin, inner := 24, w-48
	g.place(g.header, margin, 22, inner, 34)
	g.place(g.subtitle, margin, 63, inner, 25)
	g.place(g.checkTitle, margin, 108, inner, 26)
	checkH := 200
	if h < 660 {
		checkH = h - 440
		if checkH < 100 {
			checkH = 100
		}
	}
	g.place(g.checks, margin, 139, inner, checkH)
	guiSendMessage.Call(g.checks, 0x101E, 2, uintptr(g.px(inner-255)))
	connectionY := 139 + checkH + 20
	g.place(g.connectionTitle, margin, connectionY, inner, 25)
	g.place(g.status, margin, connectionY+31, inner, 28)
	g.place(g.progress, margin, connectionY+66, inner, 7)
	bottom := h - 82
	detailY := connectionY + 86
	detailH := bottom - detailY - 12
	if detailH < 26 {
		detailH = 26
	}
	g.place(g.details, margin, detailY, inner, detailH)
	if w < 680 {
		g.place(g.startButton, margin, bottom, 166, 38)
		g.place(g.stopButton, margin+178, bottom, 100, 38)
		g.place(g.checkButton, w-272, bottom, 100, 38)
		g.place(g.copyButton, w-160, bottom, 136, 38)
	} else {
		g.place(g.startButton, margin, bottom, 184, 38)
		g.place(g.stopButton, margin+196, bottom, 112, 38)
		g.place(g.checkButton, w-304, bottom, 112, 38)
		g.place(g.copyButton, w-180, bottom, 156, 38)
	}
	g.place(g.footer, margin, h-32, inner, 23)
}

func (g *nativeGUI) render() {
	if g.controller == nil {
		return
	}
	s := g.controller.Snapshot()
	guiText(g.subtitle, s.Hostname+"  ·  "+s.Addresses)
	guiSendMessage.Call(g.checks, 0x1009, 0, 0)
	for i, check := range s.Checks {
		item := guiItem{Mask: 1, Item: int32(i), Text: guiUTF16(check.Name)}
		guiSendMessage.Call(g.checks, 0x104D, 0, uintptr(unsafe.Pointer(&item)))
		for j, value := range []string{check.Status, check.Detail} {
			item.Subitem, item.Text = int32(j+1), guiUTF16(value)
			guiSendMessage.Call(g.checks, 0x1074, uintptr(i), uintptr(unsafe.Pointer(&item)))
		}
	}
	guiText(g.status, s.Title)
	g.statusColor = g.textColor
	if !g.highContrast {
		switch {
		case s.Phase == "error":
			g.statusColor = guiColorError
		case s.Phase == "connected":
			g.statusColor = guiColorPrimary
		case s.Phase == "confirming" || strings.Contains(s.Title, "需要处理") || s.Phase == "waiting" && s.ConnectedAt.IsZero():
			g.statusColor = guiColorWarning
		}
	}
	detail := s.Detail
	if s.Endpoint != "" {
		detail += "\r\n入口：" + s.Endpoint + "    有效期至：" + s.ExpiresAt.Local().Format("15:04:05")
	}
	if s.Manager != "" {
		detail += "\r\n管理端：" + s.Manager
	}
	if !s.ConnectedAt.IsZero() {
		detail += "\r\n最近连接成功：" + s.ConnectedAt.Local().Format("15:04:05")
	}
	if s.Error != "" {
		detail += "\r\n\r\n原因：" + s.Error
	}
	if s.LogPath != "" {
		detail += "\r\n\r\n日志：" + s.LogPath
	}
	if s.LogError != "" {
		detail += "\r\n日志写入异常：" + s.LogError
	}
	guiText(g.details, detail)
	progress := map[string]uintptr{"checking": 8, "ready": 20, "preparing": 40, "waiting": 60, "confirming": 70, "connecting": 85, "connected": 100}[s.Phase]
	guiSendMessage.Call(g.progress, 0x0402, progress, 0)
	guiEnableWindow.Call(g.startButton, guiBool(s.CanStart && !s.Busy && !s.Active))
	guiEnableWindow.Call(g.checkButton, guiBool(!s.Busy && !s.Active))
	guiEnableWindow.Call(g.stopButton, guiBool(s.Active && s.Phase != "stopping"))
	if g.autoStart && !s.Busy && (s.Phase == "ready" || s.Phase == "error") {
		g.autoStart = false
		if s.CanStart {
			g.controller.Start()
		}
	}
	if g.closeAfterStop && !s.Active && !s.Busy {
		g.closeAfterStop = false
		if s.Error == "" {
			guiDestroyWindow.Call(g.hwnd)
		}
	}
}

func (g *nativeGUI) invoke(fn func()) {
	g.queue <- fn
	guiPostMessage.Call(g.hwnd, guiInvoke, 0, 0)
}

func (g *nativeGUI) configuration() {
	if !g.controller.Snapshot().CanStart {
		return
	}
	title, message := "准备当前账号 WinRM 连接", "程序将准备 WinRM 服务、仅局域网可访问的规则，并广播当前 Windows 账号。管理端会在连接时提示输入该账号密码；目标机不会创建或修改账号。\r\n\r\n入口有效期为 "+winrmLifetimeText()+"。结束连接或正常关闭窗口后会清理本次临时规则。需要管理员权限时会弹出 Windows UAC。"
	if !g.winrmMode {
		title, message = "准备临时 SSH 连接", "程序将创建临时 RemoteBridge 账号、仅局域网可访问的连接规则和本次专用 SSH 服务，并开始广播。\r\n\r\n入口有效期为 30 分钟。结束连接或正常关闭窗口后会清理本次配置。需要管理员权限时会弹出 Windows UAC。"
	}
	g.openDialog(title, message, "配置并开始", func(accepted bool) {
		if !accepted {
			targetDiagnostic(diagnostic.Event{Event: "configuration.cancelled", Message: "用户取消配置确认"})
			return
		}
		targetDiagnostic(diagnostic.Event{Event: "configuration.confirmed", Message: "用户已确认准备临时连接"})
		if !targetIsAdministrator() {
			exe, err := os.Executable()
			if err == nil {
				targetDiagnostic(diagnostic.Event{Event: "elevation.started", Message: "通过标准 Windows UAC 请求配置权限"})
				shell := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
				args := "gui --configure --winrm"
				if !g.winrmMode {
					args = "gui --configure --ssh"
				}
				code, _, launchErr := shell.Call(g.hwnd, uintptr(unsafe.Pointer(guiUTF16("runas"))), uintptr(unsafe.Pointer(guiUTF16(exe))), uintptr(unsafe.Pointer(guiUTF16(args))), uintptr(unsafe.Pointer(guiUTF16(""))), 1)
				if code > 32 {
					targetDiagnostic(diagnostic.Event{Event: "elevation.launched", Message: "已启动管理员窗口，交接本次配置"})
					guiDestroyWindow.Call(g.hwnd)
					return
				}
				err = fmt.Errorf("管理员启动未完成（UAC 已取消或启动失败，代码 %d）：%v", code, launchErr)
			}
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "elevation.failed", Error: err.Error()})
			guiText(g.status, "管理员启动未完成")
			guiText(g.details, err.Error()+"\r\n可再次点击“配置并开始连接”重试。")
			return
		}
		g.controller.Start()
	})
}

// A modal has one result channel; context cancellation posts its dismissal to
// the UI thread. A late click cannot authorize a cancelled or expired request.
func (g *nativeGUI) confirmPair(ctx context.Context, text string) bool {
	if ctx.Err() != nil {
		return false
	}
	result := make(chan bool, 1)
	owner := new(uint64)
	g.invoke(func() {
		if ctx.Err() != nil {
			result <- false
			return
		}
		if g.modal != 0 {
			result <- false
			return
		}
		g.openDialog("允许管理端连接？", text, "允许连接", func(accepted bool) { result <- accepted && ctx.Err() == nil })
		g.modalOwner = owner
	})
	select {
	case value := <-result:
		return value && ctx.Err() == nil
	case <-ctx.Done():
		g.invoke(func() {
			if g.modal != 0 && g.modalOwner == owner {
				g.closeDialog(false)
			}
		})
		return false
	}
}

var guiDialogCallback func(bool)

func (g *nativeGUI) openDialog(title, text, accept string, callback func(bool)) {
	if g.modal != 0 {
		callback(false)
		return
	}
	var parent guiRect
	guiUser32.NewProc("GetWindowRect").Call(g.hwnd, uintptr(unsafe.Pointer(&parent)))
	w, h := g.px(580), g.px(310)
	modal, _, _ := guiCreateWindow.Call(1, uintptr(unsafe.Pointer(guiUTF16("RemoteBridgeConfirmation"))), uintptr(unsafe.Pointer(guiUTF16(title))), 0x00C80000, uintptr(int(parent.Left)+(int(parent.Right-parent.Left)-w)/2), uintptr(int(parent.Top)+(int(parent.Bottom-parent.Top)-h)/2), uintptr(w), uintptr(h), g.hwnd, 0, g.instance, 0)
	if modal == 0 {
		callback(false)
		return
	}
	g.modal, guiDialogCallback = modal, callback
	guiEnableWindow.Call(g.hwnd, 0)
	label, _, _ := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("STATIC"))), uintptr(unsafe.Pointer(guiUTF16(text))), 0x50000000, uintptr(g.px(24)), uintptr(g.px(20)), uintptr(g.px(520)), uintptr(g.px(180)), modal, 0, g.instance, 0)
	guiSendMessage.Call(label, 0x0030, g.font, 1)
	var cancelButton uintptr
	for i, entry := range []struct {
		text string
		id   int
	}{{accept, guiYesID}, {"取消", guiNoID}} {
		style := uintptr(0x50010000)
		if entry.id == guiNoID {
			style |= 1
		}
		button, _, _ := guiCreateWindow.Call(0, uintptr(unsafe.Pointer(guiUTF16("BUTTON"))), uintptr(unsafe.Pointer(guiUTF16(entry.text))), style, uintptr(g.px(280+i*132)), uintptr(g.px(220)), uintptr(g.px(120)), uintptr(g.px(36)), modal, uintptr(entry.id), g.instance, 0)
		guiSendMessage.Call(button, 0x0030, g.font, 1)
		if entry.id == guiNoID {
			cancelButton = button
		}
	}
	guiShowWindow.Call(modal, 5)
	guiUser32.NewProc("SetForegroundWindow").Call(modal)
	guiSetFocus.Call(cancelButton)
}

func (g *nativeGUI) closeDialog(accepted bool) {
	if g.modal == 0 {
		return
	}
	window, callback := g.modal, guiDialogCallback
	g.modal, guiDialogCallback = 0, nil
	g.modalOwner = nil
	guiDestroyWindow.Call(window)
	guiEnableWindow.Call(g.hwnd, 1)
	focus := g.startButton
	if g.controller != nil && g.controller.Snapshot().Active {
		focus = g.stopButton
	}
	guiSetFocus.Call(focus)
	if callback != nil {
		callback(accepted)
	}
}

func guiDialogProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	g := guiActive
	if g != nil {
		switch msg {
		case 0x0010:
			g.closeDialog(false)
			return 0
		case 0x0111:
			if int(wParam&0xffff) == guiYesID {
				g.closeDialog(true)
				return 0
			}
			if int(wParam&0xffff) == guiNoID || int(wParam&0xffff) == 2 {
				g.closeDialog(false)
				return 0
			}
		case 0x0138:
			guiGDI32.NewProc("SetBkMode").Call(wParam, 1)
			guiGDI32.NewProc("SetTextColor").Call(wParam, g.textColor)
			return g.brush
		}
	}
	ret, _, _ := guiDefWindow.Call(hwnd, msg, wParam, lParam)
	return ret
}

func guiWindowProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	g := guiActive
	if g != nil {
		switch msg {
		case guiUpdate:
			g.render()
			return 0
		case guiInvoke:
			for {
				select {
				case fn := <-g.queue:
					fn()
				default:
					return 0
				}
			}
		case 0x0005:
			g.layout()
			return 0
		case 0x0024:
			var limits guiMinMax
			guiMoveMemory.Call(uintptr(unsafe.Pointer(&limits)), lParam, unsafe.Sizeof(limits))
			limits.MinTrack = guiPoint{int32(g.px(640)), int32(g.px(500))}
			guiMoveMemory.Call(lParam, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits))
			return 0
		case 0x0111:
			if g.controller == nil {
				break
			}
			switch int(wParam & 0xffff) {
			case guiCheckID:
				g.controller.Check()
			case guiStartID:
				g.configuration()
			case guiStopID:
				g.controller.Stop()
			case guiCopyID:
				if err := guiClipboard(hwnd, g.controller.Snapshot().Diagnostics()); err != nil {
					guiText(g.status, "复制失败 · 可选中下方文字复制")
				}
			}
			return 0
		case 0x0010:
			if g.modal != 0 {
				g.closeDialog(false)
			}
			if g.controller != nil {
				s := g.controller.Snapshot()
				if s.Active {
					g.closeAfterStop = true
					g.controller.Stop()
					return 0
				}
				if s.Busy {
					g.closeAfterStop = true
					g.controller.CancelCheck()
					return 0
				}
			}
			guiDestroyWindow.Call(hwnd)
			return 0
		case 0x0002:
			guiUser32.NewProc("PostQuitMessage").Call(0)
			return 0
		case 0x0138:
			guiGDI32.NewProc("SetBkMode").Call(wParam, 1)
			color := g.textColor
			if lParam == g.subtitle || lParam == g.footer {
				color = g.mutedColor
			} else if lParam == g.status {
				color = g.statusColor
			}
			guiGDI32.NewProc("SetTextColor").Call(wParam, color)
			return g.brush
		case 0x02E0:
			g.dpi = int(wParam & 0xffff)
			g.releaseFonts()
			g.font = g.createFont(15, 400, guiFontBody)
			g.titleFont = g.createFont(25, 600, guiFontDisplay)
			g.monoFont = g.createFont(14, 400, guiFontUtility)
			for _, control := range []uintptr{g.checkTitle, g.checks, g.connectionTitle, g.status, g.details, g.checkButton, g.startButton, g.stopButton, g.copyButton, g.footer} {
				guiSendMessage.Call(control, 0x0030, g.font, 1)
			}
			guiSendMessage.Call(g.header, 0x0030, g.titleFont, 1)
			guiSendMessage.Call(g.subtitle, 0x0030, g.monoFont, 1)
			var rect guiRect
			guiMoveMemory.Call(uintptr(unsafe.Pointer(&rect)), lParam, unsafe.Sizeof(rect))
			guiUser32.NewProc("SetWindowPos").Call(hwnd, 0, uintptr(rect.Left), uintptr(rect.Top), uintptr(rect.Right-rect.Left), uintptr(rect.Bottom-rect.Top), 0x0014)
			g.layout()
			return 0
		}
	}
	ret, _, _ := guiDefWindow.Call(hwnd, msg, wParam, lParam)
	return ret
}

func guiClipboard(hwnd uintptr, value string) error {
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	if open, _, _ := guiUser32.NewProc("OpenClipboard").Call(hwnd); open == 0 {
		return fmt.Errorf("剪贴板暂时不可用")
	}
	defer guiUser32.NewProc("CloseClipboard").Call()
	guiUser32.NewProc("EmptyClipboard").Call()
	memory, _, _ := guiKernel32.NewProc("GlobalAlloc").Call(2, uintptr(len(data)*2))
	if memory == 0 {
		return fmt.Errorf("无法分配剪贴板内存")
	}
	address, _, _ := guiKernel32.NewProc("GlobalLock").Call(memory)
	if address == 0 {
		guiKernel32.NewProc("GlobalFree").Call(memory)
		return fmt.Errorf("无法写入剪贴板")
	}
	guiMoveMemory.Call(address, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	guiKernel32.NewProc("GlobalUnlock").Call(memory)
	if ok, _, _ := guiUser32.NewProc("SetClipboardData").Call(13, memory); ok == 0 {
		guiKernel32.NewProc("GlobalFree").Call(memory)
		return fmt.Errorf("复制未完成")
	}
	return nil
}

func attachTargetConsole() {
	if len(os.Args) > 1 && os.Args[1] != "gui" && os.Args[1] != "ssh-service" {
		_, outErr := os.Stdout.Stat()
		_, inErr := os.Stdin.Stat()
		guiKernel32.NewProc("AttachConsole").Call(0xffffffff)
		if outErr != nil {
			if output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
				os.Stdout, os.Stderr = output, output
			}
		}
		if inErr != nil {
			if input, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
				os.Stdin = input
			}
		}
	}
}
