---
version: alpha
name: Remote Bridge
description: Chinese Windows utility for checking and opening one temporary LAN connection.
colors:
  background: "#F3F6FA"
  text: "#17283B"
  muted: "#547086"
  primary: "#127668"
  warning: "#B65315"
  danger: "#B42330"
typography:
  display:
    fontFamily: "Segoe UI"
    fontSize: "25px"
  body:
    fontFamily: "Microsoft YaHei UI"
    fontSize: "15px"
  utility:
    fontFamily: "Consolas"
    fontSize: "14px"
spacing:
  page: "24px"
  control-gap: "12px"
omitted:
  - section: rounded
    reason: Native Windows controls own their platform geometry.
components:
  button:
    height: "38px"
    backgroundColor: "{colors.background}"
    textColor: "{colors.text}"
  checklist:
    height: "200px"
    textColor: "{colors.text}"
  confirmation:
    width: "580px"
  subtitle:
    textColor: "{colors.muted}"
  pending-status:
    textColor: "{colors.warning}"
  error-status:
    textColor: "{colors.danger}"
  connected-status:
    textColor: "{colors.primary}"
---

# Remote Bridge Design System

## Overview

面向把 U 盘插到另一台 Windows 电脑上的中文用户。窗口只有一项工作：检查电脑、配置临时入口，让管理端连接。视觉参照 Windows 的连接诊断工具，采用原生控件和可复制的结果。明确的“检查 → 连接”两段是主要识别特征；不增加导航、仪表盘指标或装饰动画。

这是简体中文桌面工具，当前场景为可信局域网自用，未声明日本市场或其他业务地域。时间使用目标电脑的本地时区，入口期限由 UTC 时间控制。

运行时主题所有者是 `cmd/bridge-target/gui_theme.go`，本文件镜像其值。`gui_windows.go` 把 COLORREF、字体和尺寸应用到共享原生控件。颜色采用 Windows BBGGRR 编码，高对比度模式采用系统颜色；按钮、滚动条、列表选择和键盘焦点由 Windows 负责，不复制到独立页面样式。

## Colors

浅蓝灰背景用于整个工作区，深蓝文字保持工具信息的清晰度，青绿色用于进度。警告和错误必须同时包含文字原因与下一步，不能依赖颜色。原生列表和按钮保留系统反馈，高对比度使用系统窗口和文字色。

## Typography

Segoe UI 用于英文工具标题；Microsoft YaHei UI 用于中文检查项、状态、按钮和说明；Consolas 用于电脑名和地址。字体随 DPI 重建，中文不使用斜体或纯等宽字体。长错误信息保留在可选择、可滚动的说明框中。

## Layout

默认窗口 940 × 760 逻辑像素，外围间距 24。标题与电脑信息在顶部，检查列表在上半部分，连接状态、进度及说明在下半部分。主按钮固定在底部左侧，诊断与检查按钮在右侧。较短窗口缩减列表高度，由列表与说明框各自滚动；不遮挡底部按钮。最小窗口 640 × 500，按照 DPI 缩放并限制初始大小在当前工作区内。

## Elevation & Depth

主窗口使用平面布局。仅确认窗口采用系统模态边框，禁用背景窗口并在取消或完成后恢复焦点。UAC 使用 Windows 标准授权界面。

## Shapes

按钮、列表、进度条与滚动条采用原生 Windows 外观。控件高度 38，保持标题改变与忙碌状态时的位置、尺寸稳定。

## Components

### Canonical UI Map

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Buttons | Windows BUTTON controls in nativeGUI | DESIGN.md | primary / neutral / disabled | Native preview, Tab and access keys |
| Checklist | Windows ListView in nativeGUI | guiBackend.Check | normal / pending / error | Read-only native preview |
| Confirmation | nativeGUI.openDialog | Explicit user consent and request expiry | configuration / SSH pairing | Cancel preview, deadline unit tests |
| Status | guiController | SSH readiness, auth and cleanup results | pending / success / failure | gui_controller_test.go, ssh_pairing_test.go |
| Scrollbar | Windows native controls | Windows theme / high contrast | checklist / details | Native narrow-window preview |

检查列表由 `guiBackend.Check` 提供，只读系统配置。每项显示“正常”“待配置”或“异常”及说明；配置成功后更新为正常，结束后相关项显示“已清理”或“需检查”。未知检查不能显示为正常。所有系统修改均由配置确认后的 `guiController.Start` 驱动。

连接状态由 `gui_controller.go` 统一管理：检查、配置、等待请求、等待确认、等待登录、认证成功、停止与失败。单击重复防护、取消、到期与清理错误共用该控制器。只有服务端真实认证消息可产生“连接成功”，配对批准不等同于认证成功。

确认窗口由 `nativeGUI.openDialog` 统一创建，使用原生可聚焦按钮；默认焦点为取消，支持 Tab、Escape、关闭与请求到期自动取消。原生按钮提供悬停、按下、禁用和键盘焦点。状态说明始终留在窗口内，诊断复制不包括密码、私钥或命令内容。

诊断日志从程序启动时追加写入，优先保存在程序旁的 `logs`，无法写入时回退到用户缓存。详情区和诊断复制显示实际文件路径，写入失败单独显示原因；连接失败或结束后保留日志。配置步骤和服务宿主错误使用统一结构化记录及脱敏逻辑，中文错误可直接阅读，不增加额外确认弹窗。

目标机使用上述工作窗口；管理机新增原生密码窗口和会话窗口。默认流程为 WinRM 当前账号托管连接，SSH 显式入口继续保留。没有分页、日期选择或 Toast 能力；列表、按钮、密码遮罩和滚动条由 Windows 所有。

### 管理端托管连接

行为依据为 `docs/托管会话设计.md`，控件所有者为 `cmd/bridge-cli/managed_ui.ps1` 的 Windows Forms 原生工厂。沿用中文 Microsoft YaHei UI、24px 边距和 38px 按钮，系统负责颜色、焦点与高对比度。管理窗口默认 620×380，最小 520×320；长主机、账号和提示自动换行，短窗口由面板滚动保持按钮可达。不添加独立 Web 样式。

| 能力 | 控件所有者 | 状态与行为 | 验证 |
|---|---|---|---|
| 密码输入 | Read-BridgePassword | Windows 密码遮罩；初始焦点在输入框；Enter 连接、Escape/关闭取消；不持久化输入 | 隔离工作进程测试；原生预览 |
| 连接状态 | Show/Update-BridgeManager | 成功认证后显示主机、账号、会话及剩余时间；期限不续期 | worker / lease / server 测试 |
| 交接 | 复制 Codex 交接指令 | 成功和复制失败均在原位置反馈；控制台提供同样指令；不含密码或能力令牌 | Handoff 脱敏测试；预览 |
| 结束 | 管理端按钮或窗口关闭 | 立即禁用重复操作，显示正在结束，关闭 PSSession；清理超时报未确认 | CLI/MCP 结束测试 |
| 错误 | 管理端控制台及原生错误窗 | 认证、目标校验、脚本缺失和连接错误显示阶段及具体原因；目标版本问题提示更新后重连 | 故障测试及人工双机待验收 |

发现等待与登录等待显示在控制台；密码窗口关闭后连接最多等待两分钟。连接成功窗口始终保持可复制的主机、账号与期限；只有认证后才能交接。目标端 connected/disconnected 由已验证账号的入口反馈驱动，不能用 UDP 广播代替认证。突然断电的反馈可能滞后，详见设计中的生命周期边界。

WinRM 入口有效期为 3 小时，从目标端本次配置起计算；目标检查说明、底部提示和配置确认使用同一有效期。管理端显示 HH:MM:SS 倒计时，并沿用目标绝对到期时间；重连不续期。SSH 仍为 30 分钟，使用自身确认文案。UAC 配置权限不等同于远程会话的管理员权限，本轮不改变权限模型。

## Do's and Don'ts

- 检查结果、配置进度和错误原因必须与真实运行状态对应。
- 同一管理端在当前入口有效期内确认一次；新密钥或新来源重新确认。
- 取消检查、配置、连接或确认时保持窗口可响应。
- 不用“已配对”代替“连接成功”，不把清理失败写成全部完成。
- 不在使用流程中要求复制 PowerShell 配置命令。
