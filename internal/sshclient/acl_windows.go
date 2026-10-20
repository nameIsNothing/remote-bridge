//go:build windows

package sshclient

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// protectPrivateKey applies a user-only ACL before ssh.exe consumes the key.
// Windows ignores Unix chmod bits for most files, while OpenSSH does inspect
// the ACL and may reject a key inherited by broad principals.
func protectPrivateKey(path string) error {
	return protectPath(path, false)
}

// ProtectDirectory makes a manager session directory accessible only to the
// current process user. Children inherit that restriction from creation;
// private keys never briefly inherit a broad parent directory ACL.
func ProtectDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("SSH directory is not a regular directory")
	}
	return protectPath(path, true)
}

func protectPath(path string, directory bool) error {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	// Replace the entire DACL, including explicit broad grants. Environment
	// variables are never used to choose the identity receiving key access.
	sddl, err := syscall.UTF16PtrFromString("D:P(A;" + inheritance + ";FA;;;" + sid + ")")
	if err != nil {
		return err
	}
	widePath, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	advapi := syscall.NewLazyDLL("advapi32.dll")
	convert := advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getDACL := advapi.NewProc("GetSecurityDescriptorDacl")
	setSecurity := advapi.NewProc("SetNamedSecurityInfoW")
	var descriptor uintptr
	if ok, _, callErr := convert.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0); ok == 0 {
		return fmt.Errorf("create SSH file ACL: %w", callErr)
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	var present, defaulted uint32
	var dacl uintptr
	if ok, _, callErr := getDACL.Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); ok == 0 || present == 0 || dacl == 0 {
		return fmt.Errorf("read SSH file ACL: %w", callErr)
	}
	const protectedDACL = 0x80000004
	const fileObject = 1
	if code, _, _ := setSecurity.Call(uintptr(unsafe.Pointer(widePath)), fileObject, protectedDACL, 0, 0, dacl, 0); code != 0 {
		return fmt.Errorf("set SSH file ACL: %w", syscall.Errno(code))
	}
	return nil
}
