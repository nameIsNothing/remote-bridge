//go:build darwin || linux

package unixssh

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type ownedInfo struct {
	mode os.FileMode
	uid  uint32
}

func (i ownedInfo) Name() string       { return "fixture" }
func (i ownedInfo) Size() int64        { return 0 }
func (i ownedInfo) Mode() os.FileMode  { return i.mode }
func (i ownedInfo) ModTime() time.Time { return time.Time{} }
func (i ownedInfo) IsDir() bool        { return i.mode.IsDir() }
func (i ownedInfo) Sys() any           { return &syscall.Stat_t{Uid: i.uid} }

func TestRootDirectoryChainEnforcesEveryAncestor(t *testing.T) {
	leaf := "/private/var/RemoteBridge-usb-0123456789abcdef01234567"
	for name, change := range map[string]func(map[string]ownedInfo){
		"protected":               func(map[string]ownedInfo) {},
		"sticky parent":           func(m map[string]ownedInfo) { m["/private/var"] = ownedInfo{os.ModeDir | os.ModeSticky | 0777, 0} },
		"group writable ancestor": func(m map[string]ownedInfo) { m["/private"] = ownedInfo{os.ModeDir | 0775, 0} },
		"not traversable":         func(m map[string]ownedInfo) { m["/private/var"] = ownedInfo{os.ModeDir | 0700, 0} },
		"foreign owner":           func(m map[string]ownedInfo) { m["/private/var"] = ownedInfo{os.ModeDir | 0755, 501} },
		"symlink":                 func(m map[string]ownedInfo) { m["/private"] = ownedInfo{os.ModeDir | os.ModeSymlink | 0755, 0} },
		"not a directory":         func(m map[string]ownedInfo) { m["/private"] = ownedInfo{0644, 0} },
		"missing ancestor":        func(m map[string]ownedInfo) { delete(m, "/private") },
	} {
		t.Run(name, func(t *testing.T) {
			dirs := map[string]ownedInfo{}
			for p := leaf; ; p = filepath.Dir(p) {
				dirs[p] = ownedInfo{os.ModeDir | 0755, 0}
				if p == "/" {
					break
				}
			}
			change(dirs)
			seen := map[string]bool{}
			err := checkRootDirectoryChain(leaf, func(p string) (os.FileInfo, error) {
				seen[p] = true
				i, ok := dirs[p]
				if !ok {
					return nil, os.ErrNotExist
				}
				return i, nil
			})
			if (err == nil) != (name == "protected") {
				t.Fatalf("unsafe chain result: %v", err)
			}
			if name == "protected" && len(seen) != 4 {
				t.Fatalf("only checked %d ancestors", len(seen))
			}
		})
	}
	if err := checkRootDirectoryChain("relative", func(string) (os.FileInfo, error) { return nil, errors.New("should not read") }); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestRuntimeBaseRejectsSharedTemporaryDirectories(t *testing.T) {
	if runtimeBase() == "/var/tmp" || runtimeBase() == "/private/var/tmp" || runtimeBase() == "/tmp" {
		t.Fatal("StrictModes-incompatible base selected")
	}
}

func TestAutomaticStartRejectsPipeAndNullAsTerminal(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if interactiveTerminal(read) {
		t.Fatal("pipe accepted as interactive launch")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if interactiveTerminal(null) {
		t.Fatal("null character device accepted as interactive launch")
	}
	if interactiveTerminal(nil) {
		t.Fatal("nil input accepted")
	}
}
