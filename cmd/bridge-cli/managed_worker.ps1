# This worker owns the credential prompt and PSSession. Its config lives in
# the manager's protected directory; passwords never enter argv or Go.
param([Parameter(Mandatory=$true)][string]$ConfigPath)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$OutputEncoding=[Console]::OutputEncoding
$config=Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
. (Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'ui.ps1')
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Text;
public static class BridgeLocalRPC {
    public static string Post(string url,string token,string pin,string json) {
        var req=(HttpWebRequest)WebRequest.Create(url);
        req.Proxy=null; req.AllowAutoRedirect=false; req.Timeout=10000;
        req.Method="POST"; req.ContentType="application/json";
        req.Headers["Authorization"]="Bearer "+token;
        req.ServerCertificateValidationCallback=(sender,cert,chain,errors)=>{
            using(var sha=SHA256.Create()) {
                return String.Equals(BitConverter.ToString(sha.ComputeHash(cert.GetRawCertData())).Replace("-",""),pin,StringComparison.OrdinalIgnoreCase);
            }
        };
        byte[] body=Encoding.UTF8.GetBytes(json);
        req.ContentLength=body.Length;
        using(var stream=req.GetRequestStream()) { stream.Write(body,0,body.Length); }
        using(var response=req.GetResponse())
        using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8)) { return reader.ReadToEnd(); }
    }
}
'@
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
function LocalRPC($Message) {
  $json=$Message | ConvertTo-Json -Depth 8 -Compress
  return ([BridgeLocalRPC]::Post(($config.endpoint+'/v1/worker'),$config.token,$config.fingerprint,$json) | ConvertFrom-Json)
}
$session=$null; $job=$null; $secure=$null; $credential=$null; $failure=''; $phase='password'
try {
  Write-Host ('Connecting to '+$config.session.hostname+' / '+$config.session.target+' / '+$config.session.username)
  Write-Host 'Enter the Windows account password once. Codex receives no password.'
  $secure=Read-BridgePassword
  $phase='local_interface'
  $null=LocalRPC @{operation='next'}
  $credential=[PSCredential]::new([string]$config.session.username,$secure)
  $connection=@{ComputerName=[string]$config.session.target;Port=[int]$config.session.port;Credential=$credential;Authentication='Negotiate';ErrorAction='Stop'}
  if($config.session.port -eq 5986) { $connection.UseSSL=$true }
  $connection.SessionOption=New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 15000 -IdleTimeout 600000
  $phase='authentication'
  $session=New-PSSession @connection
  $credential=$null; $secure.Dispose(); $secure=$null
  $phase='target_validation'
  $prepare=[scriptblock]::Create(('param($instance,$managerSession)'+[Environment]::NewLine+$config.lease_script+@'

$lease=Publish-BridgeConnected $instance $managerSession
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
[pscustomobject]@{hostname=$env:COMPUTERNAME;username=$id.Name;sid=$id.User.Value;instance_id=$lease.instance_id;expires_at=$lease.expires_at}
'@))
  $identity=Invoke-Command -Session $session -ScriptBlock $prepare -ArgumentList $config.session.instance_id,$config.session.id -ErrorAction Stop
  if($identity.hostname -ine $config.session.hostname -or $identity.username -ine $config.session.username) { throw 'Authenticated target identity does not match the selected computer' }
  # Remoting adds PSComputerName/RunspaceId properties. Project only our
  # protocol fields so strict local decoding never accepts remoting extras.
  $verified=@{hostname=[string]$identity.hostname;username=[string]$identity.username;sid=[string]$identity.sid;instance_id=[string]$identity.instance_id;expires_at=[string]$identity.expires_at}
  $null=LocalRPC @{operation='ready';session=$verified}
  $phase='connected'
  Show-BridgeManager
  $nextProbe=[DateTime]::UtcNow.AddSeconds(2)
  while($true) {
    Update-BridgeManager
    if($script:closeRequested) { break }
    if($job -and $job.State -notin @('Running','NotStarted','Blocked')) {
      $reply=@{operation='result';id=$workID}
      try {
        $values=@(Receive-Job -Job $job -ErrorAction Stop)
        if($values.Count -ne 1 -or $null -eq $values[0].exit_code) { throw 'Remote command returned an invalid result' }
        $reply.result=@{stdout=[string]$values[0].stdout;stderr=[string]$values[0].stderr;exit_code=[int]$values[0].exit_code;truncated=[bool]$values[0].truncated}
      } catch { $reply.error=$_.Exception.Message; $failure=$_.Exception.Message }
      Remove-Job -Job $job -Force -ErrorAction SilentlyContinue; $job=$null
      $null=LocalRPC $reply
      if($failure) { break }
    }
    if(-not $job -and [DateTime]::UtcNow -ge $nextProbe) {
      $probe=[scriptblock]::Create(('param($instance)'+[Environment]::NewLine+$config.lease_script+[Environment]::NewLine+'$null=Read-BridgeLease $instance'))
      Invoke-Command -Session $session -ScriptBlock $probe -ArgumentList $config.session.instance_id -ErrorAction Stop
      $nextProbe=[DateTime]::UtcNow.AddSeconds(2)
    }
    $work=LocalRPC @{operation='next'}
    if($work.operation -eq 'close') { break }
    if($work.operation -eq 'exec') {
      if($job) { throw 'Worker received overlapping commands' }
      $workID=$work.id
      $remote=[scriptblock]::Create(('param($instance,$command,$timeout)'+[Environment]::NewLine+$config.lease_script+[Environment]::NewLine+$config.command_script))
      # Cast in expression mode before entering cmdlet argument mode.
      # An inline [int] cast in a comma-separated ArgumentList is a string.
      $commandTimeout=[int]$work.timeout_seconds
      $remoteArguments=@($config.session.instance_id,$work.command,$commandTimeout)
      $job=Invoke-Command -Session $session -ScriptBlock $remote -ArgumentList $remoteArguments -AsJob -ErrorAction Stop
    }
  }
} catch {
  $failure=('['+$phase+'] '+$_.Exception.Message)
  # Retain only locations/types, never credentials, script text or output.
  try {
    @{stage=$phase;line=$_.InvocationInfo.ScriptLineNumber;error_type=$_.Exception.GetType().FullName} |
      ConvertTo-Json -Compress | Set-Content -LiteralPath (Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'worker-error.json') -Encoding UTF8
  } catch {}
  [Console]::Error.WriteLine($failure)
} finally {
  try { $null=LocalRPC @{operation='closing'} } catch {}
  if($job) { Stop-Job -Job $job -ErrorAction SilentlyContinue; Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
  if($session) {
    try {
      $disconnect=[scriptblock]::Create(('param($instance,$managerSession)'+[Environment]::NewLine+$config.lease_script+[Environment]::NewLine+'$null=Publish-BridgeConnected $instance $managerSession disconnected'))
      Invoke-Command -Session $session -ScriptBlock $disconnect -ArgumentList $config.session.instance_id,$config.session.id -ErrorAction SilentlyContinue
    } catch {}
    try { Remove-PSSession -Session $session -ErrorAction Stop } catch { $failure='WinRM cleanup failed: '+$_.Exception.Message }
  }
  $credential=$null
  if($secure) { $secure.Dispose() }
  try { $null=LocalRPC @{operation='closed';error=$failure} } catch {}
  Close-BridgeManager
}
