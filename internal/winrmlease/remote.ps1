function Get-BridgeLeaseRoot {
  return (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'RemoteBridge-WinRM')
}
function Read-BridgeLease([string]$Instance) {
  if($Instance -notmatch '^ssh-[a-f0-9]{12}$') { throw 'Invalid target instance' }
  $directory=Join-Path (Get-BridgeLeaseRoot) $Instance
  $path=Join-Path $directory 'lease.json'
  for($parent=$path;$parent;$parent=[IO.Path]::GetDirectoryName($parent)) {
    $item=Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0) { throw 'Target lease path contains a reparse point' }
  }
  # Allow atomic replacement by the target heartbeat writer while retaining
  # one consistent file handle. Sharing flags do not grant write permission.
  $share=[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
  $reader=$null
  try {
    if($stream.Length -gt 8192) {throw 'Target lease is invalid'}
    $reader=[IO.StreamReader]::new($stream,[Text.Encoding]::UTF8)
    $lease=$reader.ReadToEnd() | ConvertFrom-Json
  } finally {if($reader){$reader.Dispose()}else{$stream.Dispose()}}
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  if($lease.version -notin @(1,2) -or -not $lease.active -or $lease.instance_id -cne $Instance -or
     $lease.sid -cne $identity.User.Value -or $lease.username -ine $identity.Name -or
     $lease.hostname -ine $env:COMPUTERNAME -or
     [DateTimeOffset]::Parse($lease.expires_at).UtcDateTime -le [DateTime]::UtcNow) {
    throw 'Target connection ended, expired or changed identity'
  }
  if($lease.version -eq 2) {
    if([int]$lease.controller_pid -le 0 -or [string]$lease.controller_start_ticks -notmatch '^[1-9][0-9]{15,19}$' -or -not $lease.controller_heartbeat_utc) {throw 'Target controller registration is invalid'}
    $seen=[DateTimeOffset]::Parse($lease.controller_heartbeat_utc).UtcDateTime
    $age=([DateTime]::UtcNow-$seen).TotalSeconds
    if($age -lt -2 -or $age -gt 5) {throw 'Target window heartbeat stopped or expired'}
  } else {
    $controller=[Diagnostics.Process]::GetProcessById([int]$lease.controller_pid)
    try {
      $started=$controller.StartTime
      $exited=$controller.HasExited
      if($null -eq $started -or $null -eq $exited) {throw 'Target program requires update: this account cannot query the elevated window process'}
      if($exited -or $started.ToUniversalTime().Ticks.ToString() -cne $lease.controller_start_ticks) {throw 'Target window is no longer running'}
    } finally {$controller.Dispose()}
  }
  return $lease
}
function Publish-BridgeConnected([string]$Instance,[string]$SessionID,[string]$State='connected') {
  $lease=Read-BridgeLease $Instance
  if($SessionID -notmatch '^rb-[a-f0-9]{24}$') { throw 'Invalid manager session ID' }
  if($State -notin @('connected','disconnected')) { throw 'Invalid feedback state' }
  $path=Join-Path (Get-BridgeLeaseRoot) ($Instance + '\feedback.json')
  $item=Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0) { throw 'Feedback file is a reparse point' }
  $feedback=[pscustomobject]@{instance_id=$Instance;session_id=$SessionID;username=$lease.username;sid=$lease.sid;state=$State}
  [IO.File]::WriteAllText($path,($feedback | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  return $lease
}
