package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/diagnostic"
)

// GUI state is independent of Win32. Only the backend may change the system;
// constructing a controller or checking it never opens a remote entry point.
type guiCheck struct {
	Name, Status, Detail string
	Blocked              bool
}

type guiSnapshot struct {
	Hostname, Addresses, Phase, Title, Detail, Endpoint, Manager, Error string
	LogPath, LogError                                                   string
	Checks                                                              []guiCheck
	Busy, CanStart, Active                                              bool
	ExpiresAt, ConnectedAt                                              time.Time
}

type guiEvent struct{ Kind, Detail, Manager string }

type guiSession interface {
	Endpoint() string
	Expiry() time.Time
	Done() <-chan error
	Close(context.Context) error
}

type guiBackend interface {
	Check(context.Context) ([]guiCheck, error)
	Start(context.Context, func(guiEvent), func(context.Context, string) bool) (guiSession, error)
}

type guiController struct {
	mu      sync.Mutex
	backend guiBackend
	state   guiSnapshot
	notify  func()
	confirm func(context.Context, string) bool
	cancel  context.CancelFunc
	session guiSession
	serial  uint64
}

func newGUIController(backend guiBackend, notify func(), confirm func(context.Context, string) bool) *guiController {
	logPath, logError := targetDiagnosticLocation()
	detail := "检查只读取配置。完成后可准备临时连接。"
	if _, ok := backend.(*winrmDesktopBackend); ok {
		detail = "检查只读取配置。完成后可准备当前账号 WinRM 连接。"
	}
	return &guiController{backend: backend, notify: notify, confirm: confirm, state: guiSnapshot{
		Hostname: localHostname(), Addresses: strings.Join(addressStrings(localIPv4Details()), " / "),
		Phase: "idle", Title: "正在检查这台电脑", Detail: detail,
		LogPath: logPath, LogError: logError,
	}}
}

func (c *guiController) Snapshot() guiSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.LogPath, s.LogError = targetDiagnosticLocation()
	s.Error = safeTargetDiagnosticText(s.Error)
	s.Checks = append([]guiCheck(nil), s.Checks...)
	return s
}

func (c *guiController) changed() {
	if c.notify != nil {
		c.notify()
	}
}

func (c *guiController) Check() {
	c.mu.Lock()
	if c.state.Busy || c.state.Active {
		c.mu.Unlock()
		return
	}
	c.serial++
	id := c.serial
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	c.cancel = cancel
	c.state.Busy, c.state.CanStart = true, false
	c.state.Phase, c.state.Title = "checking", "正在检查这台电脑"
	c.state.Detail, c.state.Error = "正在检查权限、网络、离线包和连接端口…", ""
	c.mu.Unlock()
	targetDiagnostic(diagnostic.Event{Event: "check.started", Phase: "checking"})
	c.changed()
	go func() {
		defer cancel()
		checks, err := c.backend.Check(ctx)
		for _, check := range checks {
			targetDiagnostic(diagnostic.Event{Event: "check.result", Step: check.Name, Phase: check.Status, Message: check.Detail})
		}
		if err != nil {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "check.failed", Error: err.Error()})
		} else {
			targetDiagnostic(diagnostic.Event{Event: "check.completed"})
		}
		c.mu.Lock()
		if id != c.serial {
			c.mu.Unlock()
			return
		}
		c.state.Checks = checks
		c.state.Hostname, c.state.Addresses = localHostname(), strings.Join(addressStrings(localIPv4Details()), " / ")
		c.state.Busy = false
		c.state.CanStart = err == nil
		issues := 0
		for _, check := range checks {
			if check.Blocked {
				c.state.CanStart = false
			}
			if check.Status != "正常" {
				issues++
			}
		}
		c.state.Phase, c.state.Title = "ready", "检查完成 · 可以准备连接"
		c.state.Detail = "点击“配置并开始连接”。程序会说明修改内容，确认后自动配置并广播。"
		if issues > 0 {
			c.state.Title = fmt.Sprintf("检查完成 · %d 项需要处理", issues)
			c.state.Detail = "标为“待配置”的项目会在确认后自动处理；异常项请按说明修正后重新检查。"
		}
		if !c.state.CanStart {
			c.state.Phase, c.state.Title = "error", "暂时无法开始连接"
		}
		if err != nil {
			c.state.Error, c.state.Detail = err.Error(), "检查失败。点击“重新检查”重试。"
		}
		c.mu.Unlock()
		c.changed()
	}()
}

// Start is called only after the window's configuration confirmation (or
// the explicit elevated GUI handoff). Duplicate clicks cannot apply twice.
func (c *guiController) Start() {
	c.mu.Lock()
	if c.state.Busy || c.state.Active || !c.state.CanStart {
		c.mu.Unlock()
		return
	}
	c.serial++
	id := c.serial
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.state.Busy, c.state.CanStart, c.state.Active = true, false, true
	c.state.Phase, c.state.Title, c.state.Detail, c.state.Error = "preparing", "正在配置连接", "正在准备连接组件…", ""
	if _, ok := c.backend.(*winrmDesktopBackend); ok {
		c.state.Title, c.state.Detail = "正在配置 WinRM", "正在准备 WinRM 服务和局域网规则…"
	}
	c.state.Endpoint, c.state.Manager, c.state.ConnectedAt, c.state.ExpiresAt = "", "", time.Time{}, time.Time{}
	c.mu.Unlock()
	targetDiagnostic(diagnostic.Event{Event: "configuration.started", Phase: "preparing"})
	c.changed()
	go func() {
		session, err := c.backend.Start(ctx, func(event guiEvent) { c.event(id, event) }, c.confirm)
		c.mu.Lock()
		if id != c.serial {
			c.mu.Unlock()
			if session != nil {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
				_ = session.Close(cleanupCtx)
				cleanupCancel()
			}
			return
		}
		if err != nil {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "configuration.failed", Error: err.Error()})
			cancel()
			c.state.Busy, c.state.Active, c.state.CanStart = false, false, true
			c.state.Phase, c.state.Title, c.state.Error = "error", "配置未完成", err.Error()
			c.state.Detail = "查看下方原因。修正后可重新检查并重试。"
			if ctx.Err() != nil && cancellationOnly(err) {
				c.state.Phase, c.state.Title, c.state.Detail, c.state.Error = "stopped", "配置已取消", "本次准备已取消并清理。可重新检查或再次开始。", ""
			}
			c.mu.Unlock()
			c.changed()
			return
		}
		c.session = session
		targetDiagnostic(diagnostic.Event{Event: "configuration.completed", Phase: "waiting", Message: session.Endpoint()})
		c.state.Busy = false
		c.state.Endpoint, c.state.ExpiresAt = session.Endpoint(), session.Expiry()
		for i := range c.state.Checks {
			check := &c.state.Checks[i]
			switch check.Name {
			case "管理员权限":
				check.Status, check.Detail = "正常", "本次配置已获得管理员授权"
			case "连接组件":
				check.Status, check.Detail = "正常", "SSH 服务已通过启动和协议检查"
			case "连接端口":
				check.Status, check.Detail = "正常", "本次入口正在使用 TCP 2222 和 UDP 37020"
				if _, ok := c.backend.(*winrmDesktopBackend); ok {
					check.Detail = "本次入口正在使用 WinRM TCP 5985 和 UDP 37020"
				}
			case "局域网访问":
				check.Status, check.Detail = "正常", "本次临时规则已配置，仅允许 LocalSubnet"
			case "临时配置":
				check.Status, check.Detail = "正常", "临时账号和专用服务已准备，有效期至 "+session.Expiry().Local().Format("15:04:05")
			case "WinRM 服务":
				check.Status, check.Detail = "正常", "WinRM 服务和监听器已准备"
			case "当前账号直连":
				check.Status, check.Detail = "正常", "使用已确认的当前 Windows 账号，不修改账号"
			}
		}
		if c.state.Phase == "preparing" {
			c.state.Phase, c.state.Title, c.state.Detail = "waiting", "正在广播 · 等待管理端连接", "管理端会收到当前账号名并在连接时输入密码。"
			if _, ok := c.backend.(*winrmDesktopBackend); !ok {
				c.state.Detail = "有连接请求时会弹窗确认。同一管理端在本次有效期内只需确认一次。"
			}
		}
		c.mu.Unlock()
		c.changed()
		timer := time.NewTimer(time.Until(session.Expiry()))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			c.finish(id, session, "连接已结束", nil)
		case <-timer.C:
			cancel()
			c.finish(id, session, "连接入口已到期", nil)
		case failure := <-session.Done():
			if !session.Expiry().After(time.Now()) {
				cancel()
				c.finish(id, session, "连接入口已到期", nil)
				return
			}
			if ctx.Err() != nil {
				c.finish(id, session, "连接已结束", nil)
				return
			}
			cancel()
			if failure == nil {
				failure = fmt.Errorf("SSH 服务或广播已停止")
			}
			c.finish(id, session, "连接入口意外停止", failure)
		}
	}()
}

func cancellationOnly(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, item := range joined.Unwrap() {
			if !cancellationOnly(item) {
				return false
			}
		}
		return true
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (c *guiController) event(id uint64, event guiEvent) {
	c.mu.Lock()
	if id != c.serial || !c.state.Active || c.state.Phase == "stopping" {
		c.mu.Unlock()
		return
	}
	if event.Manager != "" {
		c.state.Manager = event.Manager
	}
	switch event.Kind {
	case "progress":
		c.state.Detail = event.Detail
	case "request":
		c.state.Phase, c.state.Title, c.state.Detail = "confirming", "收到连接请求 · 等待你的确认", event.Detail
	case "approved":
		if c.state.ConnectedAt.IsZero() {
			c.state.Phase, c.state.Title, c.state.Detail = "connecting", "已允许 · 正在等待 SSH 登录", "管理端正在建立加密连接，无需继续点击。"
		}
	case "rejected":
		c.state.Phase, c.state.Title, c.state.Detail = "waiting", "正在广播 · 等待管理端连接", event.Detail
	case "connected":
		c.state.Phase, c.state.Title, c.state.Detail = "connected", "连接成功 · 已完成身份验证", "管理端现在可以执行命令。同一管理端后续命令会自动连接，无需再次确认。"
		if _, ok := c.backend.(*winrmDesktopBackend); ok {
			c.state.Detail = "管理端已建立托管会话。结束连接后，该会话不能继续执行命令。"
		}
		c.state.ConnectedAt = time.Now()
	case "connection-error":
		c.state.Phase, c.state.Title, c.state.Detail = "waiting", "本次连接未完成 · 入口仍可重试", event.Detail
	case "disconnected":
		c.state.ConnectedAt = time.Time{}
		c.state.Phase, c.state.Title, c.state.Detail = "waiting", "管理端已断开 · 等待新的连接", "本次托管会话已结束；可以重新连接，或结束此入口。"
	}
	c.mu.Unlock()
	targetDiagnostic(diagnostic.Event{Event: "connection." + event.Kind, Message: event.Detail})
	c.changed()
}

func (c *guiController) Stop() {
	c.mu.Lock()
	if !c.state.Active || c.state.Phase == "stopping" {
		c.mu.Unlock()
		return
	}
	c.state.Busy, c.state.Phase, c.state.Title, c.state.Detail = true, "stopping", "正在结束连接", "正在停止广播、SSH 服务并清理本次配置…"
	if _, ok := c.backend.(*winrmDesktopBackend); ok {
		c.state.Detail = "正在撤销托管会话入口、停止广播并清理本次规则…"
	}
	cancel := c.cancel
	c.mu.Unlock()
	targetDiagnostic(diagnostic.Event{Event: "cleanup.requested"})
	c.changed()
	if cancel != nil {
		cancel()
	}
}

func (c *guiController) CancelCheck() {
	c.mu.Lock()
	if c.state.Active || !c.state.Busy {
		c.mu.Unlock()
		return
	}
	c.serial++
	c.state.Busy, c.state.Error = false, ""
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	c.changed()
}

func (c *guiController) finish(id uint64, session guiSession, title string, failure error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cleanupErr := session.Close(ctx)
	entry := diagnostic.Event{Event: "cleanup.completed", Message: title}
	if failure != nil || cleanupErr != nil {
		entry.Level, entry.Event, entry.Error = "error", "cleanup.failed", errors.Join(failure, cleanupErr).Error()
	}
	targetDiagnostic(entry)
	c.mu.Lock()
	if c.serial != id {
		c.mu.Unlock()
		return
	}
	c.session = nil
	c.state.Active, c.state.Busy, c.state.CanStart = false, false, cleanupErr == nil
	c.state.Phase, c.state.Title, c.state.Detail = "stopped", title, "本次临时连接已清理。可重新检查或再次开始连接。"
	c.state.Error = ""
	for i := range c.state.Checks {
		check := &c.state.Checks[i]
		switch check.Name {
		case "连接组件":
			check.Status, check.Detail = "待检查", "本次连接已结束；重新检查可确认组件状态"
		case "连接端口", "局域网访问", "临时配置", "WinRM 服务", "当前账号直连":
			check.Status, check.Detail = "已清理", "本次临时资源已回收"
			if cleanupErr != nil {
				check.Status, check.Detail = "需检查", "回收未全部完成，请查看下方原因"
			}
		}
	}
	if failure != nil {
		c.state.Phase, c.state.Error = "error", failure.Error()
	}
	if cleanupErr != nil {
		c.state.Phase, c.state.Title, c.state.Error = "error", "部分配置未清理 · 请查看原因", cleanupErr.Error()
		c.state.Detail = "请复制诊断信息。保留了恢复状态，下次确认配置时会重试清理。"
	}
	c.mu.Unlock()
	c.changed()
}

func (s guiSnapshot) Diagnostics() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Remote Bridge %s\r\n电脑：%s\r\n地址：%s\r\n状态：%s\r\n%s\r\n", version, s.Hostname, s.Addresses, s.Title, s.Detail)
	if s.LogPath != "" {
		fmt.Fprintf(&b, "日志：%s\r\n", s.LogPath)
	}
	if s.LogError != "" {
		fmt.Fprintf(&b, "日志写入异常：%s\r\n", s.LogError)
	}
	for _, check := range s.Checks {
		fmt.Fprintf(&b, "%s [%s] %s\r\n", check.Name, check.Status, check.Detail)
	}
	if s.Endpoint != "" {
		fmt.Fprintf(&b, "入口：%s\r\n有效期至：%s\r\n", s.Endpoint, s.ExpiresAt.Local().Format("2006-01-02 15:04:05"))
	}
	if s.Manager != "" {
		fmt.Fprintf(&b, "管理端：%s\r\n", s.Manager)
	}
	if s.Error != "" {
		fmt.Fprintf(&b, "原因：%s\r\n", s.Error)
	}
	return safeTargetDiagnosticText(b.String())
}
