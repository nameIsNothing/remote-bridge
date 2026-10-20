//go:build windows

package winrmlease

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Restrict only a new test-owned child process to reproduce the filtered
// WinRM token's inability to inspect an elevated controller.
// No existing process, account, service, firewall or system policy is changed.
func TestHeartbeatLeaseWithUnqueryableController(t *testing.T) {
	root := t.TempDir()
	script := `param($Root)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
` + RemoteScript + `
Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public sealed class LimitedControllerFixture:IDisposable {
    Process child; IntPtr handle,originalDescriptor,originalDacl;
    [StructLayout(LayoutKind.Sequential)] struct FileTime {public uint Low,High;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl,uint revision,out IntPtr descriptor,out uint size);
    [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorDacl(IntPtr descriptor,out bool present,out IntPtr dacl,out bool defaulted);
    [DllImport("advapi32.dll")] static extern uint GetSecurityInfo(IntPtr handle,int kind,uint info,IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
    [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(IntPtr handle,int kind,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr handle,out FileTime created,out FileTime exited,out FileTime kernel,out FileTime user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr handle,uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
    public int Id {get {return child.Id;}}
    public string ExpectedTicks {get;private set;}
    void SetDacl(string sddl) {
        IntPtr descriptor; uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl,1,out descriptor,out size)) throw new Exception("fixture SDDL failed");
        try {
            bool present,defaulted;IntPtr dacl;
            if(!GetSecurityDescriptorDacl(descriptor,out present,out dacl,out defaulted)||!present) throw new Exception("fixture DACL absent");
            uint status=SetSecurityInfo(handle,6,0x80000004,IntPtr.Zero,IntPtr.Zero,dacl,IntPtr.Zero);
            if(status!=0) throw new Exception("fixture DACL failed: "+status);
        } finally {LocalFree(descriptor);}
    }
    public LimitedControllerFixture(string sid) {
        try {
            child=new Process();
            child.StartInfo=new ProcessStartInfo("powershell.exe","-NoLogo -NoProfile -NonInteractive -Command Start-Sleep -Seconds 60");
            child.StartInfo.UseShellExecute=false;child.StartInfo.CreateNoWindow=true;
            child.Start();handle=child.Handle;
            FileTime created,exited,kernel,user;
            if(!GetProcessTimes(handle,out created,out exited,out kernel,out user)) throw new Exception("fixture timing failed");
            ExpectedTicks=DateTime.FromFileTimeUtc(((long)created.High<<32)|created.Low).Ticks.ToString();
            uint status=GetSecurityInfo(handle,6,4,IntPtr.Zero,IntPtr.Zero,out originalDacl,IntPtr.Zero,out originalDescriptor);
            if(status!=0) throw new Exception("fixture security read failed: "+status);
            SetDacl("D:P(A;;0x1000;;;"+sid+")");
        } catch {Dispose();throw;}
    }
    public void DenyQueries() { SetDacl("D:P"); }
    public void Stop() {
        if(handle!=IntPtr.Zero) {
            if(originalDescriptor!=IntPtr.Zero) SetSecurityInfo(handle,6,4,IntPtr.Zero,IntPtr.Zero,originalDacl,IntPtr.Zero);
            TerminateProcess(handle,0);WaitForSingleObject(handle,5000);
        }
    }
    public void Dispose() {
        Stop();
        if(originalDescriptor!=IntPtr.Zero) {LocalFree(originalDescriptor);originalDescriptor=IntPtr.Zero;}
        if(child!=null) {child.Dispose();child=null;handle=IntPtr.Zero;}
    }
}
'@
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$fixture=[LimitedControllerFixture]::new($identity.User.Value)
$legacy=$null
try {
 $fixture.DenyQueries()
 $legacy=[Diagnostics.Process]::GetProcessById($fixture.Id)
 $oldWasNull=$false
 try {$null=($legacy.HasExited -or $legacy.StartTime.ToUniversalTime().Ticks.ToString() -cne $fixture.ExpectedTicks)} catch {$oldWasNull=$true}
 if(-not $oldWasNull) {throw 'Fixture did not reproduce the old null method failure'}
 $ticks=$fixture.ExpectedTicks
 $script:fixtureRoot=$Root
 function Get-BridgeLeaseRoot {return $script:fixtureRoot}
 $instance='ssh-0123456789ab'
 $directory=Join-Path $Root $instance
 $null=[IO.Directory]::CreateDirectory($directory)
 $path=Join-Path $directory 'lease.json'
 $lease=@{version=2;instance_id=$instance;sid=$identity.User.Value;username=$identity.Name;hostname=$env:COMPUTERNAME;active=$true;expires_at=[DateTimeOffset]::UtcNow.AddMinutes(1).ToString('o');controller_pid=$fixture.Id;controller_start_ticks=$ticks;controller_heartbeat_utc=[DateTimeOffset]::UtcNow.ToString('o')}
 function Save-Lease {[IO.File]::WriteAllText($path,($lease|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}
 Save-Lease
 $null=Read-BridgeLease $instance
 $lease.controller_heartbeat_utc=[DateTimeOffset]::UtcNow.AddSeconds(-6).ToString('o');Save-Lease
 $staleDenied=$false
 try {$null=Read-BridgeLease $instance} catch {$staleDenied=$true}
 if(-not $staleDenied) {throw 'Stale heartbeat accepted'}
 $lease.controller_heartbeat_utc=[DateTimeOffset]::UtcNow.AddSeconds(10).ToString('o');Save-Lease
 $futureDenied=$false
 try {$null=Read-BridgeLease $instance} catch {$futureDenied=$true}
 if(-not $futureDenied) {throw 'Future heartbeat accepted'}
 $lease.controller_heartbeat_utc=[DateTimeOffset]::UtcNow.ToString('o');$lease.active=$false;Save-Lease
 $inactiveDenied=$false
 try {$null=Read-BridgeLease $instance} catch {$inactiveDenied=$true}
 if(-not $inactiveDenied) {throw 'Closed lease accepted'}
 $lease.active=$true;$lease.version=1;Save-Lease
 $legacyClear=$false
 try {$null=Read-BridgeLease $instance} catch {$legacyClear=$_.Exception.Message -like '*requires update*'}
 if(-not $legacyClear) {throw 'Legacy unqueryable target did not return an update instruction'}
 $lease.version=2;$lease.controller_heartbeat_utc=[DateTimeOffset]::UtcNow.ToString('o');Save-Lease
 $fixture.Stop()
 Start-Sleep -Milliseconds 5200
 $exitDenied=$false
 try {$null=Read-BridgeLease $instance} catch {$exitDenied=$true}
 if(-not $exitDenied) {throw 'Exited controller accepted'}
 [pscustomobject]@{legacy_null=$oldWasNull;heartbeat_valid=$true;stale_denied=$staleDenied;future_denied=$futureDenied;inactive_denied=$inactiveDenied;legacy_clear=$legacyClear;exit_denied=$exitDenied} | ConvertTo-Json -Compress
} finally {if($legacy){$legacy.Dispose()};$fixture.Dispose()}
`
	path := filepath.Join(root, "limited-controller.ps1")
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(script)...), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", path, "-Root", root).CombinedOutput()
	if err != nil {
		t.Fatalf("limited controller test failed: %v\n%s", err, output)
	}
	var result map[string]bool
	if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
		t.Fatalf("bad test output: %v\n%s", err, output)
	}
	for _, key := range []string{"legacy_null", "heartbeat_valid", "stale_denied", "future_denied", "inactive_denied", "legacy_clear", "exit_denied"} {
		if !result[key] {
			t.Fatalf("%s failed: %+v", key, result)
		}
	}
}
