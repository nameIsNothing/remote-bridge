// Package winrmlease binds managed commands to a visible target instance.
// Metadata is administrator-owned. The authenticated account can write only
// the pre-created feedback file, never the lease or its parent directory.
package winrmlease

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"remote-bridge/internal/platform/windows"
)

const RootName = "RemoteBridge-WinRM"

// MaxLifetime is the target-issued lifetime of a managed WinRM entry.
// Reusing a connection never extends this deadline.
const MaxLifetime = 3 * time.Hour

var InstancePattern = regexp.MustCompile(`^ssh-[a-f0-9]{12}$`)
var sidPattern = regexp.MustCompile(`^S-1-(?:[0-9]+-)*[0-9]+$`)

//go:embed remote.ps1
var RemoteScript string

type Lease struct {
	Version         int       `json:"version"`
	InstanceID      string    `json:"instance_id"`
	Username        string    `json:"username"`
	SID             string    `json:"sid"`
	Hostname        string    `json:"hostname"`
	ExpiresAt       time.Time `json:"expires_at"`
	ControllerPID   int       `json:"controller_pid"`
	ControllerStart string    `json:"controller_start_ticks"`
	HeartbeatAt     time.Time `json:"controller_heartbeat_utc,omitempty"`
	Active          bool      `json:"active"`
}
type Feedback struct {
	State      string `json:"state"`
	InstanceID string `json:"instance_id"`
	SessionID  string `json:"session_id"`
	Username   string `json:"username"`
	SID        string `json:"sid"`
}
type Runtime struct {
	Lease            Lease
	Path, SignalPath string
	mu               sync.Mutex
}

func quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func Prepare(ctx context.Context, runner windows.Runner, programData string, lease Lease) (*Runtime, error) {
	now := time.Now()
	if !InstancePattern.MatchString(lease.InstanceID) || !sidPattern.MatchString(lease.SID) || lease.Username == "" || lease.Hostname == "" || lease.ControllerPID <= 0 ||
		!lease.ExpiresAt.After(now) || lease.ExpiresAt.After(now.Add(MaxLifetime)) || !filepath.IsAbs(programData) {
		return nil, errors.New("WinRM 会话入口参数无效")
	}
	root := filepath.Join(programData, RootName)
	directory := filepath.Join(root, lease.InstanceID)
	script := PrepareScript(root, directory, lease.SID, lease.ControllerPID)
	result, err := runner.Run(ctx, windows.PowerShellCommand(script, false))
	if err != nil || result.ExitCode != 0 {
		return nil, fmt.Errorf("保护 WinRM 会话入口失败：%v %s", err, strings.TrimSpace(result.Stderr))
	}
	var identity struct {
		Start string `json:"start"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &identity); err != nil || identity.Start == "" {
		return nil, errors.New("无法保存目标窗口进程身份")
	}
	lease.Version, lease.Active, lease.ControllerStart = 2, true, identity.Start
	lease.HeartbeatAt = time.Now().UTC()
	lease.ExpiresAt = lease.ExpiresAt.UTC().Truncate(time.Second)
	runtime := &Runtime{Lease: lease, Path: filepath.Join(directory, "lease.json"), SignalPath: filepath.Join(directory, "feedback.json")}
	if err := runtime.save(); err != nil {
		return nil, err
	}
	return runtime, nil
}
func PrepareScript(root, directory, sid string, pid int) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop'
$root=%s; $directory=%s; $sid=%s
foreach($path in @($root,$directory)) {
  for($p=$path; $p; $p=[IO.Path]::GetDirectoryName($p)) {
    if(Test-Path -LiteralPath $p) { if(((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0) { throw 'WinRM lease path is a reparse point' } }
  }
  if(-not(Test-Path -LiteralPath $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
  $acl=New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true,$false)
  $owner=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
  $acl.SetOwner($owner)
  foreach($identity in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  $reader=if($path -eq $root){'S-1-5-32-545'}else{$sid}
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($reader),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
  Set-Acl -LiteralPath $path -AclObject $acl
}
$feedback=Join-Path $directory 'feedback.json'
if(Test-Path -LiteralPath $feedback) { throw 'WinRM feedback already exists' }
[IO.File]::WriteAllText($feedback,'{}',[Text.UTF8Encoding]::new($false))
$fileAcl=New-Object Security.AccessControl.FileSecurity
$fileAcl.SetAccessRuleProtection($true,$false); $fileAcl.SetOwner($owner)
foreach($identity in @('S-1-5-18','S-1-5-32-544')) {
  $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),'FullControl','Allow'))
}
$fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'Read,Write,Synchronize','Allow'))
Set-Acl -LiteralPath $feedback -AclObject $fileAcl
$controller=[Diagnostics.Process]::GetProcessById(%d)
[pscustomobject]@{start=$controller.StartTime.ToUniversalTime().Ticks.ToString()} | ConvertTo-Json -Compress
`, quote(root), quote(directory), quote(sid), pid)
}
func (r *Runtime) save() error {
	data, err := json.Marshal(r.Lease)
	if err != nil {
		return err
	}
	temp := r.Path + ".tmp"
	if err := os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	return os.Rename(temp, r.Path)
}
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Lease.Active = false
	return r.save()
}

// Maintain runs inside the target window process. A remote filtered token
// cannot refresh the administrator-owned lease. If the process dies, this
// proof of liveness becomes stale even when Windows reuses its PID.
func (r *Runtime) Maintain(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			active, err := r.heartbeat(time.Now())
			if err != nil {
				return fmt.Errorf("目标窗口状态更新失败：%w", err)
			}
			if !active {
				return nil
			}
		}
	}
}

func (r *Runtime) heartbeat(now time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.Lease.Active || !now.Before(r.Lease.ExpiresAt) {
		return false, nil
	}
	r.Lease.HeartbeatAt = now.UTC()
	return true, r.save()
}
func RevokeFile(path, instance string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return errors.New("WinRM 会话入口文件异常")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var lease Lease
	if err := json.Unmarshal(data, &lease); err != nil || lease.InstanceID != instance || (lease.Version != 1 && lease.Version != 2) {
		return errors.New("WinRM 会话入口归属不匹配")
	}
	runtime := &Runtime{Lease: lease, Path: path}
	return runtime.Close()
}
func (r *Runtime) Feedback() (Feedback, error) {
	var feedback Feedback
	file, err := os.Open(r.SignalPath)
	if err != nil {
		return feedback, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil || len(data) > 8192 {
		return feedback, errors.New("WinRM 反馈过长或无法读取")
	}
	if err := json.Unmarshal(data, &feedback); err != nil {
		return feedback, err
	}
	if feedback.InstanceID != r.Lease.InstanceID || feedback.SID != r.Lease.SID || !strings.EqualFold(feedback.Username, r.Lease.Username) ||
		!regexp.MustCompile(`^rb-[a-f0-9]{24}$`).MatchString(feedback.SessionID) || (feedback.State != "connected" && feedback.State != "disconnected") {
		return Feedback{}, errors.New("WinRM 反馈身份不匹配")
	}
	return feedback, nil
}
