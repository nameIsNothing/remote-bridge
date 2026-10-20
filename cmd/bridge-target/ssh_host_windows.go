//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"remote-bridge/internal/diagnostic"
)

const (
	sshHostServiceOwnProcess = 0x10
	sshHostStopped           = 1
	sshHostStartPending      = 2
	sshHostStopPending       = 3
	sshHostRunning           = 4
	sshHostAcceptStop        = 0x1
	sshHostAcceptShutdown    = 0x4
	sshHostControlStop       = 1
	sshHostControlQuery      = 4
	sshHostControlShutdown   = 5
	sshHostSpecificError     = 1066
	sshHostNotImplemented    = 120

	// Stable service-specific errors, also available in the SCM System log.
	sshHostIdentityError   = 1
	sshHostFilesError      = 2
	sshHostControllerError = 3
	sshHostCreateError     = 4
	sshHostJobError        = 5
	sshHostResumeError     = 6
	sshHostChildError      = 7
	sshHostCleanupError    = 8
	sshHostStatusError     = 9
	sshHostPanicError      = 10
)

var (
	sshHostAdvapi32        = syscall.NewLazyDLL("advapi32.dll")
	sshHostStartDispatcher = sshHostAdvapi32.NewProc("StartServiceCtrlDispatcherW")
	sshHostRegisterHandler = sshHostAdvapi32.NewProc("RegisterServiceCtrlHandlerExW")
	sshHostSetStatus       = sshHostAdvapi32.NewProc("SetServiceStatus")
	sshHostResumeThread    = syscall.NewLazyDLL("kernel32.dll").NewProc("ResumeThread")
)

type sshHostOptions struct {
	instance        string
	root            string
	sshd            string
	controller      uint32
	controllerStart int64
	expires         time.Time
}

// Parsing has no process, service, account or firewall side effects. A creation
// timestamp is required so a recycled PID cannot be accepted during SCM start.
func parseSSHHostOptions(args []string, now time.Time) (sshHostOptions, error) {
	var options sshHostOptions
	var controller uint64
	var expires string
	flags := flag.NewFlagSet("ssh-service", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.instance, "instance", "", "")
	flags.StringVar(&options.root, "root", "", "")
	flags.StringVar(&options.sshd, "sshd", "", "")
	flags.Uint64Var(&controller, "controller", 0, "")
	flags.Int64Var(&options.controllerStart, "controller-start", 0, "")
	flags.StringVar(&expires, "expires", "", "")
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() != 0 || !validSSHPlanID(options.instance) {
		return options, errors.New("invalid SSH service instance or extra arguments")
	}
	expected := sshRuntimeDirectory(options.instance)
	if expected == "" || !sshHostAbsolutePath(options.root) || !samePath(options.root, expected) {
		return options, errors.New("SSH service root does not belong to its instance")
	}
	options.root = filepath.Clean(options.root)
	if !sshHostAbsolutePath(options.sshd) || !strings.EqualFold(filepath.Base(options.sshd), "sshd.exe") {
		return options, errors.New("invalid SSH service executable path")
	}
	options.sshd = filepath.Clean(options.sshd)
	if !samePathOrChild(filepath.Join(options.root, "openssh"), options.sshd) && !trustedInstalledSSHD(options.sshd) {
		return options, errors.New("SSH executable is outside the owned package or installed locations")
	}
	if controller == 0 || controller > uint64(^uint32(0)) || options.controllerStart <= 0 || options.controllerStart > now.UnixMilli() {
		return options, errors.New("invalid controller PID or creation timestamp")
	}
	options.controller = uint32(controller)
	var err error
	options.expires, err = time.Parse(time.RFC3339, expires)
	if err != nil || !options.expires.After(now) || options.expires.After(now.Add(sshPlanTTL)) {
		return options, errors.New("SSH service expiry must be within the current 30-minute lifetime")
	}
	return options, nil
}

func sshHostAbsolutePath(path string) bool {
	if path != strings.TrimSpace(path) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00\"") {
		return false
	}
	// Win32 strips trailing spaces/dots from path components. Do not let that
	// normalization reinterpret a lexically owned path during SYSTEM launch.
	for _, component := range strings.Split(filepath.ToSlash(path), "/") {
		if component != "" && strings.TrimRight(component, ". ") != component {
			return false
		}
	}
	return true
}

// All filesystem validation is read-only. Recheck in ServiceMain immediately
// before CreateProcess; the caller protects these directories and files first.
func validateSSHHostFiles(options sshHostOptions) error {
	if err := validateSSHOwnedPath(options.root); err != nil {
		return err
	}
	root, err := os.Lstat(options.root)
	if err != nil || !root.IsDir() {
		return errors.New("SSH service root is not an existing directory")
	}
	program, err := os.Executable()
	if err != nil || !samePath(program, filepath.Join(options.root, "bridge-service.exe")) {
		return errors.New("SSH service must run from its protected instance copy")
	}
	for _, path := range []string{program, options.sshd, filepath.Join(options.root, "sshd_config")} {
		if err := validateSSHOwnedPath(path); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("SSH service requires a regular owned file: %s", path)
		}
	}
	logPath := filepath.Join(options.root, sshRuntimeLogName)
	if err := validateSSHOwnedPath(logPath); err != nil {
		return err
	}
	if info, err := os.Lstat(logPath); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil && !info.Mode().IsRegular() {
		return errors.New("SSH service log path is not a regular file")
	}
	return nil
}

type sshHostServiceStatus struct {
	serviceType, currentState, controlsAccepted uint32
	win32ExitCode, specificExitCode             uint32
	checkPoint, waitHint                        uint32
}

// Only ServiceMain updates status. The control callback merely cancels its
// context and returns, so it cannot race a final STOPPED notification.
func nextSSHHostStatus(previous sshHostServiceStatus, state, failure uint32) (sshHostServiceStatus, bool) {
	if previous.currentState == sshHostStopped {
		return previous, false
	}
	if previous.currentState == 0 && state != sshHostStartPending && state != sshHostStopped {
		return previous, false
	}
	if state != sshHostStartPending && state != sshHostRunning && state != sshHostStopPending && state != sshHostStopped {
		return previous, false
	}
	if previous.currentState == sshHostStopPending && state != sshHostStopped && state != sshHostStopPending {
		return previous, false
	}
	if previous.currentState == sshHostRunning && state == sshHostStartPending {
		return previous, false
	}
	next := sshHostServiceStatus{serviceType: sshHostServiceOwnProcess, currentState: state}
	switch state {
	case sshHostStartPending, sshHostStopPending:
		next.checkPoint = 1
		if previous.currentState == state {
			next.checkPoint = previous.checkPoint + 1
		}
		next.waitHint = 15000
	case sshHostRunning:
		next.controlsAccepted = sshHostAcceptStop | sshHostAcceptShutdown
	case sshHostStopped:
		if failure != 0 {
			next.win32ExitCode, next.specificExitCode = sshHostSpecificError, failure
		}
	}
	return next, true
}

type sshServiceHost struct {
	options      sshHostOptions
	ctx          context.Context
	cancel       context.CancelFunc
	status       sshHostServiceStatus
	statusHandle uintptr
	failure      atomic.Uint32
	mainCalled   atomic.Bool
}

func (host *sshServiceHost) report(state, failure uint32) error {
	next, changed := nextSSHHostStatus(host.status, state, failure)
	if !changed {
		return errors.New("invalid SSH service state transition")
	}
	host.status = next
	if ok, _, err := sshHostSetStatus.Call(host.statusHandle, uintptr(unsafe.Pointer(&next))); ok == 0 {
		return err
	}
	return nil
}

func (host *sshServiceHost) control(control, eventType, eventData, context uintptr) uintptr {
	switch control {
	case sshHostControlStop, sshHostControlShutdown:
		host.cancel()
		return 0
	case sshHostControlQuery:
		return 0
	default:
		return sshHostNotImplemented
	}
}

// Called only by the SCM dispatcher. Launching `ssh-service` interactively
// never reaches this callback, and therefore cannot create any child process.
func (host *sshServiceHost) serviceMain(argc, argv uintptr) uintptr {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	host.mainCalled.Store(true)
	name, _ := syscall.UTF16PtrFromString(sshServiceName(host.options.instance))
	handler := syscall.NewCallback(host.control)
	handle, _, _ := sshHostRegisterHandler.Call(uintptr(unsafe.Pointer(name)), handler, 0)
	if handle == 0 {
		host.failure.Store(sshHostStatusError)
		return 0
	}
	host.statusHandle = handle
	// This deferred notification is last: run owns all handles and waits for the
	// child before returning. STOPPED is sent exactly once, never by HandlerEx.
	defer func() {
		if failure := recover(); failure != nil {
			host.failure.Store(sshHostPanicError)
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.panic", Instance: host.options.instance, Error: fmt.Sprint(failure)})
		}
		_ = host.report(sshHostStopped, host.failure.Load())
	}()
	if err := host.report(sshHostStartPending, 0); err != nil {
		host.failure.Store(sshHostStatusError)
		return 0
	}
	host.failure.Store(host.run())
	return 0
}

func (host *sshServiceHost) run() (failure uint32) {
	if !sshHostSystemSession() {
		return sshHostIdentityError
	}
	if err := validateSSHHostFiles(host.options); err != nil {
		return sshHostFilesError
	}
	_ = openTargetDiagnostic(filepath.Join(host.options.root, "logs"), "ssh-service")
	targetDiagnostic(diagnostic.Event{Event: "service.started", Instance: host.options.instance})
	defer func() {
		code := int(failure)
		entry := diagnostic.Event{Event: "service.stopped", Instance: host.options.instance, ExitCode: &code}
		if failure != 0 {
			entry.Level, entry.Error = "error", fmt.Sprintf("SSH 服务宿主失败，分类代码 %d", failure)
		}
		targetDiagnostic(entry)
	}()
	controller, err := openSSHHostController(host.options.controller, host.options.controllerStart)
	if err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.controller.failed", Step: "核对控制窗口", Instance: host.options.instance, Error: err.Error()})
		return sshHostControllerError
	}
	defer syscall.CloseHandle(controller)
	if host.ctx.Err() != nil || !host.options.expires.After(time.Now()) {
		return 0
	}
	child, err := createSuspendedSSHD(host.options)
	if err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.child.failed", Step: "创建 SSH 进程", Instance: host.options.instance, Error: err.Error()})
		return sshHostCreateError
	}
	var job uintptr
	defer func() {
		_ = host.report(sshHostStopPending, 0)
		if err := stopSSHHostChild(child, job); err != nil {
			targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.cleanup.failed", Instance: host.options.instance, Error: err.Error()})
			failure = sshHostCleanupError
		}
	}()
	job, err = assignSSHJob(int(child.ProcessId))
	if err != nil {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.job.failed", Step: "约束 SSH 子进程", Instance: host.options.instance, Error: err.Error()})
		return sshHostJobError
	}
	// No instruction in sshd has executed yet. Check the controller again before
	// resuming, including expiry or STOP arriving during process initialization.
	if host.ctx.Err() != nil || !sshHostHandleAlive(controller) || !host.options.expires.After(time.Now()) {
		return 0
	}
	if previous, _, err := sshHostResumeThread.Call(uintptr(child.Thread)); uint32(previous) == ^uint32(0) {
		targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.resume.failed", Instance: host.options.instance, Error: err.Error()})
		return sshHostResumeError
	}
	_ = syscall.CloseHandle(child.Thread)
	child.Thread = 0
	if err := host.report(sshHostRunning, 0); err != nil {
		return sshHostStatusError
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-host.ctx.Done():
			return 0
		case <-ticker.C:
			if !sshHostHandleAlive(controller) || !host.options.expires.After(time.Now()) {
				return 0
			}
			if !sshHostHandleAlive(child.Process) {
				var exitCode uint32
				_ = syscall.GetExitCodeProcess(child.Process, &exitCode)
				code := int(exitCode)
				targetDiagnostic(diagnostic.Event{Level: "error", Event: "service.child.exited", Instance: host.options.instance, ExitCode: &code, Message: "SSH 进程意外退出"})
				return sshHostChildError
			}
		}
	}
}

func sshHostSystemSession() bool {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var token syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY, &token); err != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	sid, err := user.User.Sid.String()
	if err != nil || sid != "S-1-5-18" {
		return false
	}
	var session uint32
	ok, _, _ := syscall.NewLazyDLL("kernel32.dll").NewProc("ProcessIdToSessionId").Call(uintptr(os.Getpid()), uintptr(unsafe.Pointer(&session)))
	return ok != 0 && session == 0
}

// Parent passes this value when registering the protected service copy. The
// service rechecks it on the same handle it holds for its entire lifetime.
func sshControllerStartMillis(pid int) (int64, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return 0, errors.New("invalid controller PID")
	}
	handle, err := syscall.OpenProcess(0x1000, false, uint32(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(handle)
	return sshHostProcessStartMillis(handle)
}

func sshHostProcessStartMillis(handle syscall.Handle) (int64, error) {
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds() / int64(time.Millisecond), nil
}

func openSSHHostController(pid uint32, expectedStart int64) (syscall.Handle, error) {
	if pid == 0 || pid == uint32(os.Getpid()) || expectedStart <= 0 {
		return 0, errors.New("invalid controller identity")
	}
	handle, err := syscall.OpenProcess(0x00100000|0x1000, false, pid) // SYNCHRONIZE | QUERY_LIMITED_INFORMATION
	if err != nil {
		return 0, err
	}
	if !matchesSSHHostController(handle, expectedStart) {
		_ = syscall.CloseHandle(handle)
		return 0, errors.New("controller exited or its PID was reused")
	}
	return handle, nil
}

func matchesSSHHostController(handle syscall.Handle, expectedStart int64) bool {
	start, err := sshHostProcessStartMillis(handle)
	return err == nil && expectedStart > 0 && start == expectedStart && sshHostHandleAlive(handle)
}

func sshHostHandleAlive(handle syscall.Handle) bool {
	state, err := syscall.WaitForSingleObject(handle, 0)
	return err == nil && state == syscall.WAIT_TIMEOUT
}

func createSuspendedSSHD(options sshHostOptions) (syscall.ProcessInformation, error) {
	var child syscall.ProcessInformation
	application, err := syscall.UTF16PtrFromString(options.sshd)
	if err != nil {
		return child, err
	}
	// Win32 OpenSSH opens -E files without FILE_SHARE_READ. Route logs to
	// our explicitly inherited, share-readable stderr handle instead.
	arguments := []string{options.sshd, "-D", "-f", filepath.Join(options.root, "sshd_config"), "-e"}
	for i := range arguments {
		arguments[i] = syscall.EscapeArg(arguments[i])
	}
	command, err := syscall.UTF16FromString(strings.Join(arguments, " "))
	if err != nil || len(command) > 32767 {
		return child, errors.New("invalid SSH child command line")
	}
	directory, err := syscall.UTF16PtrFromString(options.root)
	if err != nil {
		return child, err
	}
	startup, err := newSSHChildStartup(options.root)
	if err != nil {
		return child, err
	}
	defer startup.Close()
	// CREATE_SUSPENDED prevents child/grandchild escape before job assignment.
	// Only the two explicitly listed standard-I/O handles are inherited.
	err = syscall.CreateProcess(application, &command[0], nil, nil, true, 0x00000004|0x08000000|0x00080000, nil, directory, &startup.startup.info, &child)
	runtime.KeepAlive(startup)
	return child, err
}

func stopSSHHostChild(child syscall.ProcessInformation, job uintptr) error {
	if child.Thread != 0 {
		_ = syscall.CloseHandle(child.Thread)
	}
	defer syscall.CloseHandle(child.Process)
	if job != 0 {
		closeSSHJob(job)
	} else {
		// Assignment failed while the child was still suspended.
		_ = syscall.TerminateProcess(child.Process, 1)
	}
	state, err := syscall.WaitForSingleObject(child.Process, 10000)
	if err == nil && state == syscall.WAIT_OBJECT_0 {
		return nil
	}
	if err := syscall.TerminateProcess(child.Process, 1); err != nil {
		return err
	}
	state, err = syscall.WaitForSingleObject(child.Process, 5000)
	if err != nil {
		return err
	}
	if state != syscall.WAIT_OBJECT_0 {
		return errors.New("SSH child did not stop within the service shutdown deadline")
	}
	return nil
}

func runSSHServiceHost(args []string) int {
	options, err := parseSSHHostOptions(args, time.Now())
	if err != nil || validateSSHHostFiles(options) != nil {
		return 2
	}
	ctx, cancel := context.WithDeadline(context.Background(), options.expires)
	defer cancel()
	host := &sshServiceHost{options: options, ctx: ctx, cancel: cancel}
	name, _ := syscall.UTF16PtrFromString(sshServiceName(options.instance))
	entry := struct {
		name     *uint16
		callback uintptr
	}{name, syscall.NewCallback(host.serviceMain)}
	table := [2]struct {
		name     *uint16
		callback uintptr
	}{entry, {}}
	// This call fails with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT for an
	// interactive launch. Child/system work exists only in the SCM callback.
	ok, _, _ := sshHostStartDispatcher.Call(uintptr(unsafe.Pointer(&table[0])))
	runtime.KeepAlive(host)
	runtime.KeepAlive(table)
	if ok == 0 || !host.mainCalled.Load() || host.failure.Load() != 0 {
		return 1
	}
	return 0
}
