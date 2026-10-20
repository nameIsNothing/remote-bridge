# Remote Bridge 0.2.6 SSH（给管理端 Codex/AI）

0.2.7-test.1 包保留本 SSH 路径；新版双击目标程序默认进入 WinRM，请先阅读同目录的 TESTING-WINRM.txt（中文测试说明）。测试 SSH 时在目标机 PowerShell 运行 .\bridge-target.exe gui --ssh，再按下面的 SSH 配对流程操作。

这是可信局域网内的 Windows 自用工具。目标机和管理机使用同一版完整发布目录；解压后保留 `packages\openssh\OpenSSH-Win64.zip` 和 `manifest.json`。

目标机双击 `bridge-target.exe`，在“检查 / 连接”窗口点击“配置并开始连接”，确认配置及必要的标准 Windows UAC。程序自动准备连接组件、临时账号、局域网规则和专用服务，完成 SSH 启动检查后开始广播。无需手动切换网络类型；窗口应保持打开。

管理端在本目录执行：

```powershell
.\bridge-cli.exe ssh --discover --command "Get-Date; hostname; whoami"
```

首次连接，目标机在“允许管理端连接？”中点击“允许连接”；随后自动建立 SSH，窗口显示身份验证是否成功。同一公钥、来源 IP 和目标实例在原有 30 分钟有效期内复用授权，后续命令无需重复点击。不要调用 WinRM `trust`，不要要求目标机提供密码，不要读取、打印或提交私钥。

需要交互 PowerShell 时省略命令：

```powershell
.\bridge-cli.exe ssh --discover
```

发现多个目标或广播受限时：

```powershell
.\bridge-cli.exe ssh --discover --json
.\bridge-cli.exe ssh --target <IP> --instance <实例ID> --command "Get-Date"
```

`--json` 只返回发现元数据；它不配对、不启动 SSH。管理端短期密钥与固定主机公钥保存在当前用户受 ACL 保护的授权缓存中；复用不延长 TTL。过期缓存在下次 SSH 调用时清理。需要让下次连接重新确认，可先删除本地缓存：

```powershell
.\bridge-cli.exe ssh --forget-session --instance <实例ID>
```

删除本地缓存不会关闭目标入口。目标端点击“结束连接”或正常关闭窗口会回收本次资源；失败留在窗口中，可点击“复制诊断信息”。窗口异常退出时专用宿主会停止 SSH 子进程，账号、规则和服务注册等残留由下次确认配置恢复回收；当前 WinRM `revoke` 不处理 SSH 状态。

目标端自动追加诊断日志到程序旁的 `logs\bridge-target.jsonl`；程序目录不可写时使用 `%LOCALAPPDATA%\RemoteBridge\logs\bridge-target.jsonl`，实际路径在窗口和复制诊断中显示。UTF-8 JSON Lines 包含检查、配置步骤、UAC、配对、清理及服务宿主错误。日志按约 1 MiB 轮换，保留 `.1` 备份，结束连接后仍保留。仅读取这些诊断文件排错，不读取密码、SSH 私钥或远程命令输出；更新时保留已有 `logs` 目录。

旧 WinRM 计划或旧 SSH 状态在用户确认配置后按所有权核对并清理。自用包保留 SHA-256 校验，不要求签名。新版真实 SSH 登录和完整双机回收仍需验收；开发记录见源码目录 `docs/开发交接.md`。
