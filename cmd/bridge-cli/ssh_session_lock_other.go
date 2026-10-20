//go:build !windows && !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package main

import (
	"errors"
	"os"
)

func trySSHSessionLock(string) (*os.File, error) {
	return nil, errors.New("当前平台尚不支持安全的 SSH 会话缓存锁")
}
