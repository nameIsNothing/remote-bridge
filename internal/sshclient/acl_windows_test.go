//go:build windows

package sshclient

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestManagerDirectoryAndPrivateKeyHaveUserOnlyProtectedDACL(t *testing.T) {
	directory := t.TempDir()
	if err := ProtectDirectory(directory); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "fixture")
	if err := os.WriteFile(file, []byte("synthetic fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := protectPrivateKey(file); err != nil {
		t.Fatal(err)
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, file} {
		sddl := readDACLForSSHTest(t, path)
		// Windows serializes built-in Administrator as LA rather than the
		// numeric SID. Compare the native ACE identity, not its SDDL spelling.
		actualSID, mask := readOnlyGrantForSSHTest(t, path)
		if !strings.HasPrefix(sddl, "D:P") || strings.Count(sddl, "(A;") != 1 || actualSID != sid || mask != 0x1f01ff {
			t.Fatalf("cache DACL must be protected with exactly one current-user full-control grant: %s", sddl)
		}
	}
}

func readOnlyGrantForSSHTest(t *testing.T, path string) (string, uint32) {
	t.Helper()
	advapi := syscall.NewLazyDLL("advapi32.dll")
	widePath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor uintptr
	var dacl unsafe.Pointer
	if code, _, _ := advapi.NewProc("GetNamedSecurityInfoW").Call(uintptr(unsafe.Pointer(widePath)), 1, 4, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor))); code != 0 {
		t.Fatalf("read ACL: %v", syscall.Errno(code))
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if dacl == nil {
		t.Fatal("null DACL")
	}
	header := (*struct {
		Revision, Reserved     byte
		Size, Count, Reserved2 uint16
	})(dacl)
	if header.Count != 1 {
		t.Fatalf("unexpected ACE count: %d", header.Count)
	}
	var ace unsafe.Pointer
	if ok, _, err := advapi.NewProc("GetAce").Call(uintptr(dacl), 0, uintptr(unsafe.Pointer(&ace))); ok == 0 {
		t.Fatal(err)
	}
	if *(*byte)(ace) != 0 {
		t.Fatal("expected access-allowed ACE")
	}
	mask := *(*uint32)(unsafe.Add(ace, 4))
	identity, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
	if err != nil {
		t.Fatal(err)
	}
	return identity, mask
}

func readDACLForSSHTest(t *testing.T, path string) string {
	t.Helper()
	advapi := syscall.NewLazyDLL("advapi32.dll")
	getSecurity := advapi.NewProc("GetNamedSecurityInfoW")
	convert := advapi.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	widePath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var descriptor uintptr
	if code, _, _ := getSecurity.Call(uintptr(unsafe.Pointer(widePath)), 1, 4, 0, 0, 0, 0, uintptr(unsafe.Pointer(&descriptor))); code != 0 {
		t.Fatalf("read DACL: %v", syscall.Errno(code))
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var wideSDDL *uint16
	var length uint32
	if ok, _, err := convert.Call(descriptor, 1, 4, uintptr(unsafe.Pointer(&wideSDDL)), uintptr(unsafe.Pointer(&length))); ok == 0 {
		t.Fatal(err)
	}
	defer syscall.LocalFree(syscall.Handle(uintptr(unsafe.Pointer(wideSDDL))))
	if length == 0 || length > 4096 {
		t.Fatal("invalid test ACL string length")
	}
	values := unsafe.Slice(wideSDDL, length)
	for i, value := range values {
		if value == 0 {
			return syscall.UTF16ToString(values[:i])
		}
	}
	t.Fatal("oversized test ACL string")
	return ""
}
