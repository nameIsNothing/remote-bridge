//go:build !windows

package diagnostic

import "os"

func pathIsLink(_ string, info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }
