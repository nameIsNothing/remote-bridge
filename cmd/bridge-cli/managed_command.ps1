$ErrorActionPreference='Stop'
$null=Read-BridgeLease $instance
if(-not ('BridgeCommandProcess' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
public sealed class BridgeBoundedText {
    public string Text;
    public bool Truncated;
}
public sealed class BridgeCommandProcess:IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Limits {
        public long ProcessTime,JobTime; public uint Flags;
        public UIntPtr MinWorkingSet,MaxWorkingSet; public uint ActiveLimit;
        public UIntPtr Affinity; public uint Priority,Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] struct IO { public ulong A,B,C,D,E,F; }
    [StructLayout(LayoutKind.Sequential)] struct Extended {
        public Limits Basic; public IO Counters;
        public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,IntPtr info,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    IntPtr job=IntPtr.Zero;
    public Process Process;
    public Task<BridgeBoundedText> Stdout,Stderr;
    static async Task<BridgeBoundedText> ReadBounded(StreamReader reader) {
        var text=new StringBuilder(); var buffer=new char[4096]; bool truncated=false; int count;
        while((count=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))>0) {
            int take=Math.Min(count,131072-text.Length);
            if(take>0) text.Append(buffer,0,take);
            if(take<count) truncated=true;
        }
        return new BridgeBoundedText{Text=text.ToString(),Truncated=truncated};
    }
    public BridgeCommandProcess(string command) {
        try {
            job=CreateJobObject(IntPtr.Zero,null);
            if(job==IntPtr.Zero) throw new Exception("CreateJobObject failed");
            var limits=new Extended(); limits.Basic.Flags=0x2000;
            IntPtr block=Marshal.AllocHGlobal(Marshal.SizeOf(limits));
            try {
                Marshal.StructureToPtr(limits,block,false);
                if(!SetInformationJobObject(job,9,block,(uint)Marshal.SizeOf(limits))) throw new Exception("SetInformationJobObject failed");
            } finally { Marshal.FreeHGlobal(block); }
            // Fixed, readable bootstrap; the command travels over private
            // stdin only after Job assignment. No encoded script in argv.
            var start=new ProcessStartInfo("powershell.exe",
                "-NoLogo -NoProfile -NonInteractive -Command \"[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); $OutputEncoding=[Console]::OutputEncoding; $ProgressPreference='SilentlyContinue'; & ([scriptblock]::Create([Console]::In.ReadToEnd()))\"");
            start.UseShellExecute=false; start.CreateNoWindow=true;
            start.RedirectStandardInput=true; start.RedirectStandardOutput=true; start.RedirectStandardError=true;
            start.StandardOutputEncoding=Encoding.UTF8; start.StandardErrorEncoding=Encoding.UTF8;
            Process=new Process(); Process.StartInfo=start;
            if(!Process.Start()) throw new Exception("Could not start command");
            // ReadToEnd blocks until EOF. Assign the Job before sending the
            // command; child processes cannot race the Job.
            if(!AssignProcessToJobObject(job,Process.Handle)) throw new Exception("AssignProcessToJobObject failed");
            Stdout=ReadBounded(Process.StandardOutput); Stderr=ReadBounded(Process.StandardError);
            byte[] input=Encoding.UTF8.GetBytes(command);
            Process.StandardInput.BaseStream.Write(input,0,input.Length);
            Process.StandardInput.BaseStream.Flush(); Process.StandardInput.Close();
        } catch { Dispose(); throw; }
    }
    public void StopTree() {
        if(job!=IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; }
    }
    public void Dispose() {
        StopTree();
        if(Process!=null) {
            try { if(!Process.HasExited) Process.Kill(); } catch {}
            Process.Dispose(); Process=null;
        }
    }
}
'@
}
$null=Read-BridgeLease $instance
$process=$null
try {
  $process=[BridgeCommandProcess]::new([string]$command)
  $deadline=[DateTime]::UtcNow.AddSeconds([int]$timeout)
  while(-not $process.Process.WaitForExit(200)) {
    $null=Read-BridgeLease $instance
    if([DateTime]::UtcNow -ge $deadline) { throw 'Remote command timed out' }
  }
  $null=Read-BridgeLease $instance
  $process.StopTree()
  $stdout=$process.Stdout.GetAwaiter().GetResult()
  $stderr=$process.Stderr.GetAwaiter().GetResult()
  [pscustomobject]@{stdout=$stdout.Text;stderr=$stderr.Text;exit_code=$process.Process.ExitCode;truncated=($stdout.Truncated -or $stderr.Truncated)}
} finally { if($process) { $process.Dispose() } }
