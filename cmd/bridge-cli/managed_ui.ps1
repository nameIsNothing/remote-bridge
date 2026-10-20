Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
function New-BridgeForm([string]$Title) {
  $form=New-Object Windows.Forms.Form
  $form.Text=$Title
  $form.StartPosition='CenterScreen'
  $form.Size=[Drawing.Size]::new(620,380)
  $form.MinimumSize=[Drawing.Size]::new(520,320)
  $form.AutoScaleMode=[Windows.Forms.AutoScaleMode]::Dpi
  $form.Font=[Drawing.Font]::new('Microsoft YaHei UI',10)
  $form.AutoScroll=$true
  $panel=New-Object Windows.Forms.FlowLayoutPanel
  $panel.Dock='Fill'; $panel.FlowDirection='TopDown'; $panel.WrapContents=$false
  $panel.Padding=[Windows.Forms.Padding]::new(24)
  $panel.AutoScroll=$true
  $form.Controls.Add($panel)
  $form.Add_Resize({
    param($sender,$eventArgs)
    foreach($control in $sender.Controls[0].Controls) {
      if($control -is [Windows.Forms.Label]) { $control.MaximumSize=[Drawing.Size]::new([Math]::Max(280,$sender.ClientSize.Width-64),0) }
    }
  })
  return $form
}
function Add-BridgeLabel($Form,[string]$Text) {
  $label=New-Object Windows.Forms.Label
  $label.Text=$Text; $label.AutoSize=$true
  $label.MaximumSize=[Drawing.Size]::new(530,0)
  $label.Margin=[Windows.Forms.Padding]::new(0,0,0,14)
  $Form.Controls[0].Controls.Add($label)
  return $label
}
function Read-BridgePassword {
  $form=New-BridgeForm 'Remote Bridge · 连接目标电脑'
  $null=Add-BridgeLabel $form ('目标：'+$config.session.hostname+'  '+$config.session.target)
  $null=Add-BridgeLabel $form ('账号：'+$config.session.username)
  $null=Add-BridgeLabel $form '输入 Windows 账号密码（不是 PIN）。本次连接期间只需输入一次。'
  $box=New-Object Windows.Forms.TextBox
  $box.UseSystemPasswordChar=$true; $box.Width=420; $box.AccessibleName='Windows 账号密码'
  $box.Margin=[Windows.Forms.Padding]::new(0,0,0,16)
  $form.Controls[0].Controls.Add($box)
  $buttons=New-Object Windows.Forms.FlowLayoutPanel
  $buttons.AutoSize=$true; $buttons.WrapContents=$true
  $connect=New-Object Windows.Forms.Button
  $connect.Text='连接'; $connect.Width=130; $connect.Height=38
  $connect.Add_Click({ if($box.Text.Length -gt 0) { $form.DialogResult='OK'; $form.Close() } else { $box.Focus() } })
  $cancel=New-Object Windows.Forms.Button
  $cancel.Text='取消'; $cancel.Width=130; $cancel.Height=38; $cancel.DialogResult='Cancel'
  $buttons.Controls.AddRange(@($connect,$cancel)); $form.Controls[0].Controls.Add($buttons)
  $form.AcceptButton=$connect; $form.CancelButton=$cancel
  $form.Add_Shown({$box.Focus()})
  $timer=New-Object Windows.Forms.Timer
  $timer.Interval=1000
  $timer.Add_Tick({
    try { $response=LocalRPC @{operation='next'}; if($response.operation -eq 'close') { $form.DialogResult='Cancel'; $form.Close() } }
    catch { $form.DialogResult='Cancel'; $form.Close() }
  })
  $timer.Start()
  try {
    if($form.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { throw '连接已取消或管理端已退出' }
    $secure=New-Object Security.SecureString
    foreach($character in $box.Text.ToCharArray()) { $secure.AppendChar($character) }
    $box.Clear()
    if($secure.Length -eq 0) { $secure.Dispose(); throw '密码不能为空，请重新连接' }
    return $secure
  } finally { $timer.Stop(); $timer.Dispose(); $box.Clear(); $form.Dispose() }
}
function Show-BridgeManager {
  $script:closeRequested=$false
  $script:managerForm=New-BridgeForm 'Remote Bridge · 管理端'
  $null=Add-BridgeLabel $managerForm '已连接 · 可以交给 Codex'
  $null=Add-BridgeLabel $managerForm ('电脑：'+$config.session.hostname+'  '+$config.session.target+[Environment]::NewLine+'账号：'+$config.session.username)
  $script:lifetimeLabel=Add-BridgeLabel $managerForm ''
  $buttons=New-Object Windows.Forms.FlowLayoutPanel
  $buttons.AutoSize=$true; $buttons.WrapContents=$true
  $script:copyButton=New-Object Windows.Forms.Button
  $copyButton.Text='复制 Codex 交接指令'; $copyButton.Width=220; $copyButton.Height=38
  $script:endButton=New-Object Windows.Forms.Button
  $endButton.Text='结束连接'; $endButton.Width=150; $endButton.Height=38
  $buttons.Controls.AddRange(@($copyButton,$endButton))
  $managerForm.Controls[0].Controls.Add($buttons)
  $script:copyStatus=Add-BridgeLabel $managerForm '将交接指令粘贴到 Codex 聊天。此窗口保持打开即可持续使用连接。'
  $copyButton.Add_Click({
    try { [Windows.Forms.Clipboard]::SetText([string]$config.handoff); $copyStatus.Text='交接指令已复制，请到 Codex 聊天中粘贴发送。' }
    catch { $copyStatus.Text='暂时无法复制。管理端控制台中也显示了交接指令。' }
  })
  $endButton.Add_Click({$script:closeRequested=$true;$copyButton.Enabled=$false;$endButton.Enabled=$false;$copyStatus.Text='正在结束连接…'})
  $managerForm.Add_FormClosing({
    if(-not $script:allowFormClose) { $_.Cancel=$true; $script:closeRequested=$true; $copyButton.Enabled=$false; $endButton.Enabled=$false; $copyStatus.Text='正在结束连接…' }
  })
  $managerForm.Show()
  $copyButton.Focus()
}
function Update-BridgeManager {
  if($script:managerForm) {
    $remaining=[DateTimeOffset]::Parse($config.session.expires_at).UtcDateTime-[DateTime]::UtcNow
    $seconds=[Math]::Max(0,[int][Math]::Floor($remaining.TotalSeconds))
    $hours=[int][Math]::Floor($seconds/3600)
    $minutes=[int][Math]::Floor(($seconds%3600)/60)
    $script:lifetimeLabel.Text=('剩余时间：{0:D2}:{1:D2}:{2:D2}   会话：{3}' -f $hours,$minutes,($seconds%60),$config.session.id)
    [Windows.Forms.Application]::DoEvents()
  }
}
function Close-BridgeManager {
  if($script:managerForm) { $script:allowFormClose=$true; $script:managerForm.Close(); $script:managerForm.Dispose() }
}
