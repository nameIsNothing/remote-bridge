package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type guiFakeBackend struct {
	check  func(context.Context) ([]guiCheck, error)
	start  func(context.Context, func(guiEvent)) (guiSession, error)
	starts atomic.Int32
}

func (b *guiFakeBackend) Check(ctx context.Context) ([]guiCheck, error) {
	if b.check != nil {
		return b.check(ctx)
	}
	return []guiCheck{{Name: "网络", Status: "正常"}}, nil
}
func (b *guiFakeBackend) Start(ctx context.Context, event func(guiEvent), confirm func(context.Context, string) bool) (guiSession, error) {
	b.starts.Add(1)
	return b.start(ctx, event)
}

type guiFakeSession struct {
	expires time.Time
	done    chan error
	closed  atomic.Int32
	err     error
}

func newGUIFakeSession() *guiFakeSession {
	return &guiFakeSession{expires: time.Now().Add(time.Minute), done: make(chan error, 1)}
}
func (s *guiFakeSession) Endpoint() string                { return "RemoteBridge@192.0.2.2:2222" }
func (s *guiFakeSession) Expiry() time.Time               { return s.expires }
func (s *guiFakeSession) Done() <-chan error              { return s.done }
func (s *guiFakeSession) Close(ctx context.Context) error { s.closed.Add(1); return s.err }

func guiTestController(t *testing.T, backend guiBackend) (*guiController, func(func(guiSnapshot) bool) guiSnapshot) {
	t.Helper()
	notifications := make(chan struct{}, 64)
	c := newGUIController(backend, func() {
		select {
		case notifications <- struct{}{}:
		default:
		}
	}, func(context.Context, string) bool { return false })
	wait := func(match func(guiSnapshot) bool) guiSnapshot {
		t.Helper()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			s := c.Snapshot()
			if match(s) {
				return s
			}
			select {
			case <-notifications:
			case <-timer.C:
				t.Fatalf("state timed out: %#v", s)
			}
		}
	}
	return c, wait
}

func TestGUICheckNeverConfiguresAndBlockedStart(t *testing.T) {
	b := &guiFakeBackend{check: func(context.Context) ([]guiCheck, error) {
		return []guiCheck{{Name: "端口", Status: "异常", Detail: "被使用", Blocked: true}}, nil
	}}
	c, wait := guiTestController(t, b)
	c.Check()
	s := wait(func(s guiSnapshot) bool { return !s.Busy && s.Phase == "error" })
	c.Start()
	if s.CanStart || b.starts.Load() != 0 {
		t.Fatal("read-only check opened an entry")
	}
}

func TestGUIWaitingIsNotConnectedAndOnlyOneStart(t *testing.T) {
	session := newGUIFakeSession()
	b := &guiFakeBackend{start: func(context.Context, func(guiEvent)) (guiSession, error) { return session, nil }}
	b.check = func(context.Context) ([]guiCheck, error) {
		return []guiCheck{{Name: "临时配置", Status: "待配置"}}, nil
	}
	c, wait := guiTestController(t, b)
	c.Check()
	wait(func(s guiSnapshot) bool { return s.CanStart })
	c.Start()
	c.Start()
	s := wait(func(s guiSnapshot) bool { return s.Phase == "waiting" })
	if !s.ConnectedAt.IsZero() || b.starts.Load() != 1 {
		t.Fatal("opening the entry was treated as connection success")
	}
	if len(s.Checks) != 1 || s.Checks[0].Status != "正常" {
		t.Fatal("completed configuration still displayed as pending")
	}
	c.mu.Lock()
	id := c.serial
	c.mu.Unlock()
	c.event(id, guiEvent{Kind: "approved", Manager: "管理机"})
	if s := c.Snapshot(); s.Phase != "connecting" || !s.ConnectedAt.IsZero() {
		t.Fatal("approval was treated as authentication")
	}
	c.event(id, guiEvent{Kind: "connected"})
	c.event(id, guiEvent{Kind: "approved"})
	if s := c.Snapshot(); s.Phase != "connected" || s.ConnectedAt.IsZero() {
		t.Fatal("reuse lost authenticated state")
	}
	c.Stop()
	s = wait(func(s guiSnapshot) bool { return !s.Active && !s.Busy })
	if s.Checks[0].Status != "已清理" {
		t.Fatal("closed entry still displayed as configured")
	}
	if session.closed.Load() != 1 {
		t.Fatal("session cleanup must run exactly once")
	}
}

func TestGUIEarlyAuthenticationAndRestartState(t *testing.T) {
	var current *guiFakeSession
	b := &guiFakeBackend{start: func(ctx context.Context, event func(guiEvent)) (guiSession, error) {
		current = newGUIFakeSession()
		event(guiEvent{Kind: "connected", Manager: "旧管理端"})
		return current, nil
	}}
	c, wait := guiTestController(t, b)
	c.Check()
	wait(func(s guiSnapshot) bool { return s.CanStart })
	c.Start()
	wait(func(s guiSnapshot) bool { return !s.Busy && s.Phase == "connected" })
	c.Stop()
	wait(func(s guiSnapshot) bool { return !s.Active && !s.Busy })
	b.start = func(context.Context, func(guiEvent)) (guiSession, error) { return newGUIFakeSession(), nil }
	c.Start()
	s := wait(func(s guiSnapshot) bool { return !s.Busy && s.Phase == "waiting" })
	if !s.ConnectedAt.IsZero() || s.Manager != "" {
		t.Fatal("new instance inherited old approval/success")
	}
	c.Stop()
	wait(func(s guiSnapshot) bool { return !s.Active && !s.Busy })
}

func TestGUIExpiryReportsCleanupFailure(t *testing.T) {
	session := newGUIFakeSession()
	session.expires = time.Now().Add(50 * time.Millisecond)
	session.err = errors.New("防火墙清理被拒绝")
	b := &guiFakeBackend{start: func(context.Context, func(guiEvent)) (guiSession, error) { return session, nil }}
	c, wait := guiTestController(t, b)
	c.Check()
	wait(func(s guiSnapshot) bool { return s.CanStart })
	c.Start()
	s := wait(func(s guiSnapshot) bool { return !s.Active && s.Phase == "error" })
	if s.CanStart || !strings.Contains(s.Title, "未清理") || s.Error != session.err.Error() {
		t.Fatal("partial cleanup incorrectly shown as complete")
	}
}

func TestGUICancelDuringPreparation(t *testing.T) {
	b := &guiFakeBackend{start: func(ctx context.Context, _ func(guiEvent)) (guiSession, error) { <-ctx.Done(); return nil, ctx.Err() }}
	c, wait := guiTestController(t, b)
	c.Check()
	wait(func(s guiSnapshot) bool { return s.CanStart })
	c.Start()
	c.Stop()
	s := wait(func(s guiSnapshot) bool { return !s.Active && !s.Busy })
	if s.Phase != "stopped" || s.Error != "" {
		t.Fatalf("cancelled preparation: %#v", s)
	}
}

func TestGUICancelledCheckCannotOverwriteLaterState(t *testing.T) {
	release := make(chan struct{})
	b := &guiFakeBackend{check: func(ctx context.Context) ([]guiCheck, error) { <-release; return nil, errors.New("old failure") }}
	c, wait := guiTestController(t, b)
	c.Check()
	c.CancelCheck()
	close(release)
	s := wait(func(s guiSnapshot) bool { return !s.Busy })
	if s.Error != "" {
		t.Fatal("cancelled check overwrote newer state")
	}
}
