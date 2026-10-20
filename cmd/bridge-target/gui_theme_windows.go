//go:build windows

package main

import (
	"os"
	"path/filepath"
	"unsafe"
)

// Activate only Windows' built-in common-control theme. The manifest is
// embedded in the program and temporary; no browser/runtime download or
// registry preference is needed for a portable GUI.
func activateGUITheme() func() {
	directory, err := os.MkdirTemp("", "remote-bridge-ui-")
	if err != nil {
		return func() {}
	}
	path := filepath.Join(directory, "controls.manifest")
	const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0"><assemblyIdentity type="win32" name="RemoteBridge.Desktop" version="0.2.6.0"/><dependency><dependentAssembly><assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/></dependentAssembly></dependency></assembly>`
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		_ = os.Remove(directory)
		return func() {}
	}
	context := struct {
		Size, Flags                     uint32
		Source                          *uint16
		Architecture, Language          uint16
		Assembly, Resource, Application *uint16
		Module                          uintptr
	}{Source: guiUTF16(path)}
	context.Size = uint32(unsafe.Sizeof(context))
	handle, _, _ := guiKernel32.NewProc("CreateActCtxW").Call(uintptr(unsafe.Pointer(&context)))
	if handle == ^uintptr(0) {
		_ = os.Remove(path)
		_ = os.Remove(directory)
		return func() {}
	}
	var cookie uintptr
	if ok, _, _ := guiKernel32.NewProc("ActivateActCtx").Call(handle, uintptr(unsafe.Pointer(&cookie))); ok == 0 {
		guiKernel32.NewProc("ReleaseActCtx").Call(handle)
		_ = os.Remove(path)
		_ = os.Remove(directory)
		return func() {}
	}
	return func() {
		guiKernel32.NewProc("DeactivateActCtx").Call(0, cookie)
		guiKernel32.NewProc("ReleaseActCtx").Call(handle)
		_ = os.Remove(path)
		_ = os.Remove(directory)
	}
}
