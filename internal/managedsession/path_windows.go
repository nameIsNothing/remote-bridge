//go:build windows

package managedsession

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func validateLocalPath(path string) error {
	if err := checkLocalParents(path); err != nil {
		return err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		wide, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		flags, err := syscall.GetFileAttributes(wide)
		if err == nil && flags&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("会话路径包含重解析点")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}
