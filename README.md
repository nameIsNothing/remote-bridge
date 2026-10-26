# Remote Bridge 0.3.1-test.1（Windows / Linux / macOS 局域网）

开发续接先读 [项目规则](AGENTS.md)、[开发交接](docs/开发交接.md) 和 [Agent 启动说明](docs/agent-start.md)。工程已经存在；GitLab 部署与运维位于同级 `../gitlab-ops`。

0.3.1-test.1 将 Linux/macOS SSH 目标入口、批准缓存和托管会话统一设为 **3 小时**，从目标本次开启入口时计算，复用不续期。打开交互式 U盘启动器后直接开始，省略启动时第一次 `y`；正常 sudo 授权与管理端首次配对允许保留。直接调用 `bridge-target ssh` 仍需完整确认，后台/管道不能使用启动器的 `--start` 模式。旧窗口保持原期限，需更新两端并重新开启才生效。旧 Windows SSH 仍为30分钟，WinRM仍为3小时，单条命令超时不变。

管理端 0.3.0-test.3 修复双击找不到 WinRM 目标后立即关闭窗口的问题：保持 Windows/WinRM 优先，没有匹配 WinRM 时自动识别 Unix SSH。双击启动失败会保留独占控制台并等待回车；命令行参数、后台调用和 MCP 不新增暂停。目标端继续为 0.3.0-test.2，协议与权限模型不变。

0.3.0-test.2 修复 Unix 授权文件上方 `/var/tmp` 可写、与 OpenSSH StrictModes 不兼容的问题。临时入口改用 macOS `/private/var` 或 Linux `/var/lib` 下的独立目录，逐级验证 root 所有权、写权限和普通账号遍历权限；不调整既有系统目录权限。管理端身份检查失败会显示具体 SSH 错误。

Unix 测试版新增 U 盘启动器：Mac 打开 `unix/Start.command`，Linux 在终端运行 `sh unix/start-unix.sh`。启动器选择对应架构，将校验后的程序复制到本机运行；目标机无需安装开发环境。显示检查说明后直接请求正常 sudo 授权，开启最长 3 小时的独立 SSH 入口，首次配对再由目标用户确认。原账号、系统 SSH、已有密钥及防火墙不被改写；远程命令使用普通账号权限。

管理机使用匹配的新版程序：`bridge-cli.exe ssh --target <IP> --manage`。连接后复用现有 `session status / exec / close` 和四个 MCP 工具，Unix 命令使用 POSIX `sh`。每条命令重新建立 SSH 连接，复用同一次批准的短期授权与固定主机公钥；期限不延长。单条命令最多 120 秒，输出每流最多 512 KiB。完整启动、权限、日志、回滚及验收步骤见 [Unix 测试说明](docs/TESTING-UNIX.txt)。Mac 及 Linux 的实机完成项分别以开发交接为准。

```powershell
.\scripts\build-unix.ps1 -Archive
# 输出 dist/unix，覆盖 macOS/Linux 的 amd64、arm64；Windows 包单独构建。
.\bridge-cli.exe ssh --target <IP> --manage
.\bridge-cli.exe session exec --id rb-<会话编号> --command "hostname; id; uname -srm" --json
```

0.2.9-test.3 为非交互系统检查和 WinRM 配置助手显式提供空输入管道，避免在启动 PowerShell 前因无法打开 Windows 的 NUL 设备而失败。无需修改 NUL 驱动、UAC 或安全软件设置；新电脑仍需用新版实测。交互式输入及会话权限不变。

0.2.9-test.2 修复 WinRM 重复回收遇到“规则或临时账号已不存在”的终止错误时误报失败的问题。权限、提供程序和资源归属错误继续明确失败；不会删除当前 Windows 账号。错误密码与重复清理的现场因果仍需日志核验，3 小时会话策略不变。

**当前开发版（2026-10-20）：** 默认使用 WinRM 当前账号托管连接，保留 SSH。管理端输入一次密码后保持认证会话，通过 CLI / MCP 交给 Codex；可复制交接指令，在任一端结束。目标端绑定入口期限并反馈认证状态。详见 [托管会话设计](docs/托管会话设计.md) 和 [中文测试说明](docs/TESTING-WINRM.txt)。新流程需要两端一起更新，真实双机验收仍待完成；旧 0.2.7-test.1 的登录实测不能代替本版验收。

目标电脑双击 `bridge-target.exe`，确认配置并保持窗口打开。管理电脑双击 `bridge-cli.exe`，在原生窗口输入公告账号的 Windows 密码，登录后点击“复制 Codex 交接指令”并发到聊天。管理窗口保持打开即可复用连接，不需要把密码交给 Codex。

0.2.9-test.1 将 WinRM 托管入口和管理会话设为 **3 小时**，从目标端本次配置时起计时；复用、断开后重连均不续期。两端需更新并重新打开，已有会话的原期限不变。旧 Windows SSH 路径仍为 30 分钟。管理端倒计时显示时、分、秒。

会话权限取决于目标 Windows 登录令牌，不会因目标配置窗口经过 UAC 提升而自动变成管理员。EDY 的既有实测令牌为普通远程权限；本版只延长时间，不增加权限。

0.2.8-test.2 修复登录后校验管理员目标窗口时出现空值错误的问题。目标窗口每秒更新受保护的存活状态，管理端无需查询管理员进程；正常结束立即撤销入口，强制退出后最多 5 秒状态过期。此修复需要更新两端，并重新打开目标窗口。

0.2.8-test.3 仅修复管理端派发命令时的超时参数转换。发布包内管理端为 test.3，目标端继续为 test.2；已运行 test.2 目标窗口时无需再次覆盖目标端。

这是可信局域网内的自用实验工具，目标机不运行业务 Agent。公网 Relay、远程桌面、Web 尚未实现。Windows 保留 LocalSubnet 和离线包 SHA-256 校验，不要求发行者签名。UAC 前原用户交接、普通账号首次授权以及两端异常退出后的完整回收仍需完善；已有账号的原生 WinRM/SSH 权限不随托管连接结束而删除。

## 当前托管连接

管理机有多个目标时运行 `.\bridge-cli.exe manage --discover --target <目标IP>`。首次精确 TrustedHosts 准备可能请求标准 UAC；不要用 PIN 代替账号密码。

Codex 可直接调用本地程序：

```powershell
.\bridge-cli.exe session list
.\bridge-cli.exe session status --id rb-<会话编号>
.\bridge-cli.exe session exec --id rb-<会话编号> --command "hostname; whoami; Get-Date" --json
.\bridge-cli.exe session close --id rb-<会话编号>
```

也可一次性配置 `bridge-cli.exe mcp` 作为 Codex STDIO MCP，使用状态、执行和结束工具；[配置示例和生命周期边界](docs/托管会话设计.md)。本轮不自动修改全局 Codex 配置。单条命令默认超时 30 秒，各命令使用独立 PowerShell 子进程。连接有效期不自动续期。

## 保留的 SSH 界面与流程

本节描述 SSH 路径，目标机使用 `bridge-target.exe gui --ssh`；默认双击为上面的 WinRM 流程。

1. 在目标机复制或解压完整发布目录，双击 `bridge-target.exe`。初次检查只读取权限、地址、组件、端口和旧配置。
2. 查看检查结果。“待配置”由程序处理；端口占用、离线包损坏等异常会说明处理方法。
3. 点击“配置并开始连接”，在弹窗中确认修改；需要管理员权限时允许标准 Windows UAC。程序自动继续配置并广播，无需手工运行命令或切换到“专用网络”。
4. 管理端执行连接命令；目标机在“允许管理端连接？”中点击“允许连接”。请求到期会自动关闭，过期点击不会授权。
5. 完成真实 SSH 身份验证后显示“连接成功”。相同公钥、来源 IP 和目标实例在原有 30 分钟有效期内无需再次确认；新密钥、新来源或重新建立入口会重新确认。
6. 点击“结束连接”或正常关闭窗口，程序停止广播、结束本次服务和子进程，并回收临时账号、规则与运行目录。失败会显示原因并保留恢复状态，可用“复制诊断信息”交接问题。下次确认配置时会核对遗留进程的实际程序路径，回收旧实例的子进程并等待退出，再删除运行目录。

管理机保持使用命令行；首次执行：

```powershell
.\bridge-cli.exe ssh --discover --command "Get-Date; hostname; whoami"
```

后续继续运行同样的连接命令即可复用授权。进入交互 PowerShell 时省略 `--command`：

```powershell
.\bridge-cli.exe ssh --discover
```

有多个目标或广播受限时，先查看发现元数据，再指定目标和实例：

```powershell
.\bridge-cli.exe ssh --discover --json
.\bridge-cli.exe ssh --target 192.168.100.27 --instance <实例ID> --command "Get-Date"
```

`--json` 只做发现，不弹配对框、不执行 SSH。目标端与管理端应一起更新，避免旧版配对协议不认识请求有效期字段。

配置报错时，日志优先保存在程序目录的 `logs\bridge-target.jsonl`，目录不可写则回退到 `%LOCALAPPDATA%\RemoteBridge\logs\bridge-target.jsonl`。窗口详情和“复制诊断信息”均显示实际路径。日志为 UTF-8 JSON Lines，记录版本、时间、步骤、耗时、退出码和错误；记录检查、UAC 交接、配置、配对及清理过程，清理连接后仍保留。每个文件约 1 MiB 时轮换，保留一个 `.1` 备份；不记录密码、密钥、脚本、远程命令及其输出。服务宿主的结构化错误会在清理运行目录前转存到该日志。

## 构建和发布

构建机需要 Go 1.22 或更新版本；目标机不需要安装 Go、Node、Python 或 WebView。

```powershell
go test ./...
go vet ./...
.\scripts\build.ps1
```

默认只输出 `dist\windows-amd64`：两个 exe、管理员启动器、SSH 指引、`TESTING-WINRM.txt`、`MANAGED-SESSIONS.md` 和 `packages\openssh` 下的离线 ZIP/manifest，共 8 个文件。将整个目录复制到 U 盘，不要只复制 exe。需要整体压缩包时显式使用 `-Archive`；打包只收录发布文件，不收录运行日志。

目标 exe 使用 Windows GUI 子系统，双击直接显示界面；管理端保持控制台程序。目标端 `gui`、`ssh`、`winrm`、`plan/inspect/apply/revoke/rollback` 子命令保留。`bridge-target-admin.cmd` 可提前用标准 UAC 打开界面，配置仍需弹窗确认。无参数启动不自动配置系统；内部 `ssh-service` 入口只接受 SCM 启动，不供日常调用。

优先使用可信安装位置的 OpenSSH；缺失时校验并解压随包离线组件，离线包不可用时才尝试 Windows 在线安装。现有系统 `sshd`、端口 22 和全局配置不被替换。程序为本次入口注册手动启动的独立服务 `RemoteBridge-<实例ID>`，服务宿主复制到受保护的 ProgramData 目录。在线安装的 Windows OpenSSH 功能不会在连接结束时卸载。

随包 OpenSSH 为 `10.0.0.0p2-Preview`、amd64、最低 Windows Build 17763，ZIP 的 SHA-256 为 `23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5`。程序验证摘要、架构、Build 和解压路径，不执行 ZIP 内安装脚本。

## 旧版 WinRM 局域网实验步骤

下面是保留的 WinRM 兼容路径，必须显式运行 `bridge-target winrm` 或 `bridge-target apply`。示例假设目标机显示出的可连接地址是 `192.168.1.30`。请把地址替换成实际值。目标机可能同时显示以太网、Wi-Fi、虚拟网卡等多个地址；简易向导会自动选择第一个活动地址，脚本化连接时可用 `--target-address` 指定。

### 1. 在目标机启动并确认地址

在已获批准的管理员 PowerShell 中运行 `bridge-target.exe winrm`，进入保留的旧临时账号向导。当前默认双击 `bridge-target-admin.cmd` 打开的是 WinRM 当前账号桌面窗口，与本节旧向导不同。旧向导会先显示类似下面的信息：

```text
目标机名称：PC-001
可用地址：192.168.1.30（以太网）
WinRM 端口：5985
防火墙来源范围：LocalSubnet
```

目标端向导会自动选择第一个活动地址，并检测 WinRM listener：已有 listener 时不重复配置；未发现时会在确认后自动准备。简易实验模式不需要输入管理机 IP，但会把防火墙范围放宽为 `LocalSubnet`，只适合可信局域网测试。apply 完成后向导会停留在窗口中，方便记录一次性密码和状态文件路径，按回车才关闭。检测到旧状态文件时，向导会先征求确认，确认后自动撤销旧计划并覆盖；取消确认则不会修改旧计划。

交互式 apply 成功后会同时创建一个只允许 `LocalSubnet` 访问的 UDP 37020 发现规则，并在窗口、账号 TTL 或 revoke 之前响应发现请求。公告只有主机名、IPv4、WinRM 端口、固定账号名和过期时间，不含密码、状态路径或脚本；直接执行非交互式 `bridge-target apply` 不会启动常驻发现 responder。

### 2. 在目标机先做只读检查

严格模式仍可在目标机用“以管理员身份运行”的 PowerShell 从 U 盘执行：

```powershell
.\bridge-target.exe inspect --manager-ip 192.168.1.20
```

它会检查管理员权限、Windows/WinRM 服务、监听器、现有 WinRM 防火墙规则、临时账号和网络配置，不会改系统。

如果 `inspect.firewall-winrm` 发现已有 `RemoteAddress=Any` 或 `LocalSubnet` 的 5985/5986 入站规则，apply 不会替你覆盖它；应先按组织策略收紧/停用该规则，否则旧规则仍可能让其他主机访问。

### 3. 生成计划并人工查看

第一版默认使用 WinRM HTTP/5985，只适合隔离且可信的局域网。`--allow-http` 是明确的风险确认，不会自动打开公网端口。简易向导已经替你选择 `LocalSubnet` 和 `--allow-http`；严格脚本模式仍需显式填写管理机 IP。

```powershell
.\bridge-target.exe plan `
  --manager-ip 192.168.1.20 `
  --allow-http `
  --configure-listener > .\dry-run-plan.json
Get-Content .\dry-run-plan.json
```

`--configure-listener` 在实际 apply 时会在没有 listener 的情况下调用 `winrm quickconfig -quiet`，可能改变本机 WinRM 策略；仅执行 plan 不会应用这些修改。不确定时先省略它，只查看检查结果。HTTPS 模式不会自动创建证书，需要先由管理员配置并验证证书：

```powershell
.\bridge-target.exe plan --manager-ip 192.168.1.20 --transport https
```

### 4. 明确应用配置

确认计划后执行：

```powershell
.\bridge-target.exe apply `
  --manager-ip 192.168.1.20 `
  --allow-http `
  --configure-listener `
  --instructions-dir .\remote-bridge
```

简易局域网模式不需要输入管理机 IP：

```powershell
.\bridge-target.exe apply `
  --simple-lan `
  --instructions-dir .\remote-bridge
```

非交互 WinRM 应用入口也支持等价的 `bridge-target --apply ...` 形式。`plan/inspect` 不应用账号/服务/规则变更，但无参数 SSH 向导和 `winrm` 交互向导仍会在配置确认后修改系统，不能用“没有 apply 就不修改”概括所有入口。

命令会使用固定的临时账号名 `RemoteBridge`，并为每次 apply 生成新的随机密码；密码只在屏幕显示一次，不写入状态文件。状态文件默认放在当前用户缓存目录（U 盘只读也能运行），也可以用 `--state <路径>` 指定；命令会在输出中显示实际路径。账号默认有效期 30 分钟。只有 apply 完整成功后，屏幕显示的密码和连接资料才可使用；如果 apply 失败，不会生成可用密码，也不会启动发现 responder。

命令会在 `--instructions-dir` 指定的位置（未指定时为目标 exe 所在目录）生成：

- `REMOTE-BRIDGE.md`：包含目标地址、端口、临时账号、有效期、执行示例和撤销命令；
- `remote-bridge-connection.json`：只包含设备 ID、目标地址、端口、传输方式、账号/配对元数据等非敏感字段。

目录不可写时会回退到用户缓存目录，并打印实际路径。默认临时账号名固定为 `RemoteBridge`，每次 apply 会重新生成随机密码并刷新过期时间，方便管理机重复使用同一个用户名；如果该名称已被非 Remote Bridge 账号占用，apply 会拒绝覆盖。同一目标不要并行建立多个计划；新的 apply 会轮换该账号密码，使旧连接失效。把输出中的目标地址、临时账号和一次性密码交给管理机操作者。密码不会写入上述文件、状态文件、审计日志或命令参数；不要把它粘贴到聊天记录、脚本、日志或仓库。

### 5. 让 Codex/其他 AI 使用连接资料

管理机不需要先手动打开 `bridge-cli.exe`。把生成资料所在目录带到管理机，并在该目录启动 Codex，或者在会话中明确要求 AI 读取 `REMOTE-BRIDGE.md`。AI 必须同时具备运行 PowerShell/本地命令的权限；说明文件只提供连接方法，不会绕过用户授权，也不会自动扫描任意 U 盘目录。

如果没有手抄目标地址，可以在目标机向导仍停留时，在管理机运行一次发现：

```powershell
.\bridge-cli.exe discover --once --json
```

它会列出局域网内仍在有效期内的 Remote Bridge 公告。发现结果只是未认证的定位信息，不会带出密码，也不会自动修改 TrustedHosts；从输出中确认目标后，再使用返回的地址继续下面的步骤。不同 VLAN、Wi-Fi 客户端隔离、广播策略或防火墙可能阻止发现，此时直接使用目标窗口显示的地址即可。

说明文件会指导 AI 先调用 `bridge-cli.exe trust <目标IP>`，再调用 `check` 和 `exec`。普通权限运行 `trust` 时，程序会自动唤起标准 Windows UAC；用户点击“是”后等待配置完成。它只把目标 IP 加入 WinRM TrustedHosts，这是使用 IP + 本地账号连接时的必要准备步骤。例如：

```powershell
.\bridge-cli.exe trust 192.168.1.30
.\bridge-cli.exe check --target 192.168.1.30 --port 5985
.\bridge-cli.exe exec `
  --target 192.168.1.30 `
  --port 5985 `
  --username 'PC-001\RemoteBridge' `
  --command "Get-ComputerInfo | Select-Object WindowsProductName,OsVersion"
```

命令按顺序执行；`trust` 只添加当前目标地址，不会自动信任整个局域网。

执行时 `bridge-cli` 会在管理机本地安全提示中读取一次性密码，不接受 `--password`。如果当前 Codex 运行环境不能处理交互式 SecureString 提示，操作者应在管理机 PowerShell 中手动运行该命令，或按 AI 的提示完成安全输入；不要把密码写入 AI 指令文件。

### 6. 手动连接（不使用 Codex）

把 `bridge-cli.exe` 放到管理机临时目录，在 PowerShell 中执行：

```powershell
.\bridge-cli.exe trust 192.168.1.30
.\bridge-cli.exe check --target 192.168.1.30 --port 5985
.\bridge-cli.exe exec `
  --target 192.168.1.30 `
  --port 5985 `
  --username '目标主机名\RemoteBridge' `
  --command "Get-ComputerInfo | Select-Object WindowsProductName,OsVersion"
```

`exec` 会在控制台用 `Read-Host -AsSecureString` 提示密码，不接受 `--password`，因此密码不会进入进程参数。需要交互式 PowerShell 时使用：

```powershell
  .\bridge-cli.exe shell --target 192.168.1.30 --port 5985 --username '目标主机名\RemoteBridge'
```

本地账号建议把用户名写成 `目标主机名\临时账号`（或按组织 WinRM 策略使用 `./临时账号`）。用 IP + 本地账号时，Windows WinRM 可能还要求管理机配置 TrustedHosts。直接运行下面的命令即可；如果当前窗口不是管理员权限，`bridge-cli` 会自动请求标准 Windows UAC：

```powershell
.\bridge-cli.exe trust 192.168.1.30
# 也支持：.\bridge-cli.exe trust --target 192.168.1.30
```

`trust` 只接受一个 IP 或主机名，会保留已有 TrustedHosts 项并避免重复添加；它不接受密码，也不会把密码写入参数或配置。UAC 只用于完成 TrustedHosts 配置，用户仍需点击“是”确认；它不会自动提升后续的 `exec` 或 `shell` 命令。

### 7. 实验结束后撤销

在目标机仍以管理员 PowerShell 执行：

```powershell
.\bridge-target.exe revoke
```

或使用 `rollback` 别名。撤销脚本只删除带有本计划描述标记的临时账号和防火墙规则；已有的 WinRM 服务、listener 和其他管理员规则不会被删除。账号过期时间只是兜底措施，实验结束仍应主动 revoke。

## 安全边界与已知限制

- TCP 2222 / UDP 37020 的防火墙范围为 LocalSubnet，适用于公用或专用网络配置。局域网发现与 UDP 配对没有独立的密码学身份认证；目标用户只应批准认识的管理端。
- 配对批准绑定管理端公钥和来源 IP。SSH 只接受公钥，禁用密码认证，启用 StrictModes；临时目录、服务程序和主机密钥限制为 SYSTEM / Administrators，普通远程账号只能读取必要文件。
- 管理端短期授权缓存位于当前用户 `%LOCALAPPDATA%\RemoteBridge\ssh-sessions`，Windows ACL 仅允许当前用户；实例、目标 IP、端口、账号与固定主机公钥都须一致。复用不会延长原有期限。空闲的过期缓存在下一次 SSH 调用时删除，没有后台清理进程。
- 可运行 `bridge-cli ssh --forget-session --instance <实例ID>` 删除该实例的本地缓存；这只删除管理端本地资料。目标入口应通过窗口“结束连接”关闭；当前 `bridge-target revoke/rollback` 仍只处理 WinRM。
- 30 分钟期限由目标服务宿主和管理端会话共同约束。窗口进程退出或期限到达时，宿主停止 SSH 和 Job 内子进程；强制终止或断电后的账号、规则、服务注册和状态文件仍须在下次确认配置时恢复回收。异常退出的整套系统回收尚未实机验收。
- 清理只处理本计划的账号、规则、服务和精确目录，失败保留状态并显示原因。程序不会保存管理员明文密码，也不会自动给予远程账号管理员权限。
- 管理端记录命令摘要和会话事件；目标端新增配对、身份验证、清理事件。交互 shell 的每条命令、完整安装生命周期及审计写入失败处理仍未完成。
- SHA-256 校验没有提供发行者签名验证；当前按自用范围发布。WinRM HTTP 兼容路径仍只用于明确同意的可信隔离 LAN，listener、系统服务和 quickconfig 的策略变更按旧版说明处理。

## 开发验证

2026-10-08 界面调整轮使用项目内便携 Go 1.27.1 完成 `go test -json ./...`、`go vet ./...` 和 Windows 打包：11 个包、109 个顶层测试及 56 个子测试通过，无失败或跳过。原生窗口的只读检查、配置弹窗、Escape 取消、正常关闭及最小布局预览通过；没有应用系统配置。测试与发布核对记录位于 `build\_validation`，详细结果见开发交接。

真实 SSH 双机验收仍待使用新版发布包执行：首次确认 → 执行命令 → 第二条命令免确认 → 正常结束 / TTL → 回收资源。此前 0.1.0 的 WinRM 只读执行成功，但 SSH 登录未成功；旧记录保留在 [开发交接](docs/开发交接.md)。

更多背景：[产品与技术方案](docs/方案.md)、[分阶段开发计划](docs/开发计划.md)、[安全边界](docs/安全边界.md)。
