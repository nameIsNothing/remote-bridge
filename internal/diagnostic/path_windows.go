//go:build windows

package diagnostic

import (
	"os"
	"syscall"
)

func pathIsLink(path string, info os.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := syscall.GetFileAttributes(name)
	return err != nil || attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
