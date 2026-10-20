# Isolated native UI fixture. No credentials, WinRM, system changes or clipboard.
param([string]$OutDir='build\_validation\managed-ui')
$ErrorActionPreference='Stop'
$repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$destination=[IO.Path]::GetFullPath((Join-Path $repo $OutDir))
$buildRoot=[IO.Path]::GetFullPath((Join-Path $repo 'build'))
if(-not $destination.StartsWith($buildRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) {throw 'Preview must stay in build directory'}
$null=New-Item -ItemType Directory -Force -Path $destination
$source=[IO.File]::ReadAllText((Join-Path $repo 'cmd\bridge-cli\managed_ui.ps1'),[Text.Encoding]::UTF8)
. ([scriptblock]::Create($source))
$config=[pscustomobject]@{session=[pscustomobject]@{hostname='TEST-LONG-COMPUTER-NAME';target='192.0.2.10';username='TEST-LONG-COMPUTER-NAME\preview-user';id='rb-0123456789abcdef01234567';expires_at=[DateTimeOffset]::UtcNow.AddHours(3).ToString('o')};handoff='Remote Bridge UI fixture, no live session'}
function LocalRPC($Message) {return [pscustomobject]@{operation='idle'}}
function Save-Preview($Form,$Name) {
 $bitmap=[Drawing.Bitmap]::new($Form.Width,$Form.Height)
 try {$Form.DrawToBitmap($bitmap,[Drawing.Rectangle]::new(0,0,$Form.Width,$Form.Height));$bitmap.Save((Join-Path $destination $Name),[Drawing.Imaging.ImageFormat]::Png)}
 finally {$bitmap.Dispose()}
}
$script:fixtureError=''
$timer=New-Object Windows.Forms.Timer
$timer.Interval=200
$timer.Add_Tick({
 $timer.Stop()
 try {
  $login=[Windows.Forms.Application]::OpenForms[0]
  $box=@($login.Controls[0].Controls | Where-Object {$_ -is [Windows.Forms.TextBox]})[0]
  if(-not $box.UseSystemPasswordChar -or -not $box.Focused) {throw 'Password masking or initial focus failed'}
  $box.Text='fixture-only'
  Save-Preview $login 'password.png'
  $login.AcceptButton.PerformClick()
 } catch {$script:fixtureError=$_.Exception.Message;$login.DialogResult='Cancel';$login.Close()}
})
$timer.Start()
try {$secure=Read-BridgePassword; $secure.Dispose()} finally {$timer.Dispose()}
if($script:fixtureError) {throw $script:fixtureError}
Show-BridgeManager
Update-BridgeManager
Save-Preview $script:managerForm 'connected.png'
$script:managerForm.Size=[Drawing.Size]::new(520,320)
Update-BridgeManager
Save-Preview $script:managerForm 'connected-narrow.png'
if(-not $script:copyButton.Enabled -or -not $script:endButton.Enabled) {throw 'Connected actions disabled'}
$script:endButton.PerformClick()
Update-BridgeManager
if(-not $script:closeRequested -or $script:copyButton.Enabled -or $script:endButton.Enabled) {throw 'End transition failed'}
Save-Preview $script:managerForm 'ending.png'
Close-BridgeManager
[pscustomobject]@{password_mask=$true;initial_focus=$true;connected_actions=$true;ending_disables_actions=$true;previews=$destination} | ConvertTo-Json -Compress
