package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"remote-bridge/internal/diagnostic"
)

type sshRecoveryCandidate struct {
	pid  uint32
	name string
}

// Image, termination and wait belong to an opened process object, not a PID
// that could have been recycled since the snapshot was taken.
type sshRecoveryProcess interface {
	Image() (string, error)
	Terminate() error
	Wait(context.Context) error
	Close()
}

type sshRecoveryOperations interface {
	Candidates() ([]sshRecoveryCandidate, error)
	Open(uint32, bool) (sshRecoveryProcess, error)
}

func sshRecoveryName(name string) bool {
	switch strings.ToLower(name) {
	case "sshd.exe", "sshd-session.exe", "sshd-auth.exe", "bridge-service.exe":
		return true
	}
	return false
}

func sshRecoveryOwnsImage(root, image string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(image) || strings.ContainsAny(image, "\r\n\x00\"") {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(image), "/") {
		if strings.TrimRight(part, ". ") != part {
			return false
		}
	}
	name := filepath.Base(image)
	if !sshRecoveryName(name) {
		return false
	}
	if strings.EqualFold(name, "bridge-service.exe") {
		return samePath(image, filepath.Join(root, "bridge-service.exe"))
	}
	return samePathOrChild(filepath.Join(root, "openssh"), image)
}

func cleanupSSHProcesses(ctx context.Context, id, root string) error {
	if !validSSHPlanID(id) || !samePath(root, sshRuntimeDirectory(id)) {
		return errors.New("SSH 进程回收目录不属于指定实例")
	}
	if err := validateSSHOwnedPath(root); err != nil {
		return err
	}
	return recoverSSHProcesses(ctx, id, root, nativeSSHRecoveryOperations{})
}

func recoverSSHProcesses(ctx context.Context, id, root string, ops sshRecoveryOperations) error {
	// Rescan after each pass: a child may have been created just before its
	// parent was stopped. Failure to reach an empty owned set preserves state.
	for pass := 0; pass < 4; pass++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidates, err := ops.Candidates()
		if err != nil {
			return fmt.Errorf("枚举旧 SSH 进程：%w", err)
		}
		owned := 0
		for _, candidate := range candidates {
			if !sshRecoveryName(candidate.name) {
				continue
			}
			query, err := ops.Open(candidate.pid, false)
			if errors.Is(err, os.ErrProcessDone) {
				continue
			}
			if err != nil {
				return fmt.Errorf("核对 SSH 进程 %d：%w", candidate.pid, err)
			}
			image, err := query.Image()
			if err != nil {
				query.Close()
				if errors.Is(err, os.ErrProcessDone) {
					continue
				}
				return fmt.Errorf("读取 SSH 进程 %d 的程序路径：%w", candidate.pid, err)
			}
			if !sshRecoveryOwnsImage(root, image) {
				query.Close()
				continue
			}
			owned++
			err = stopRecoveryProcess(ctx, candidate.pid, id, root, image, ops)
			// Hold the first process object until the second handle has been
			// checked and closed, preventing PID reuse between the two opens.
			query.Close()
			if err != nil {
				return err
			}
		}
		if owned == 0 {
			return nil
		}
	}
	return errors.New("旧 SSH 子进程持续产生，运行目录和状态已保留")
}

func stopRecoveryProcess(ctx context.Context, pid uint32, id, root, expected string, ops sshRecoveryOperations) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	process, err := ops.Open(pid, true)
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("打开旧 SSH 进程 %d 的结束权限：%w", pid, err)
	}
	defer process.Close()
	actual, err := process.Image()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	if err != nil {
		return err
	}
	if !sshRecoveryOwnsImage(root, actual) || !samePath(actual, expected) {
		return fmt.Errorf("SSH 进程 %d 的程序路径发生变化，未结束进程", pid)
	}
	if err := validateSSHOwnedPath(actual); err != nil {
		return err
	}
	targetDiagnostic(diagnostic.Event{Event: "ssh.recovery.process.identified", Instance: id, Message: fmt.Sprintf("pid=%d; executable=%s", pid, actual)})
	if err := process.Terminate(); err != nil {
		return fmt.Errorf("结束旧 SSH 进程 %d：%w", pid, err)
	}
	if err := process.Wait(ctx); err != nil {
		return fmt.Errorf("等待旧 SSH 进程 %d 退出：%w", pid, err)
	}
	targetDiagnostic(diagnostic.Event{Event: "ssh.recovery.process.stopped", Instance: id, Message: fmt.Sprintf("pid=%d; executable=%s", pid, actual)})
	return nil
}
