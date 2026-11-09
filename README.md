# PortMonitor · 本地端口监视器

**简体中文** · [English](#english)

一个面向 Windows 的图形化端口监视工具。它列出本机正在监听的端口和占用它的进程，用大白话解释「这个程序是干什么的、能不能结束、结束后会有什么影响」，并支持安全地退出对应的监听程序。

> **重要：如果结束进程失败，请先试这一招**
>
> **右键 `start.bat` →「以管理员身份运行」。**
>
> 这是实际使用中已验证有效的解决方法。普通权限下，Windows 不允许终止部分系统进程以及由其他账户启动的服务，表现为：结束失败、提示权限不足、或者读不到进程路径与命令行。提升权限后即可正常结束。
> 程序底部状态栏会实时显示当前是「管理员权限」还是「普通权限」，操作前可以先看一眼。

## 功能

- **端口一览**：TCP / UDP、IPv4 / IPv6，监听与已建立连接；显示端口、PID、进程名、完整路径、命令行。
- **大白话解释**：选中任意一行，详情面板说明「这是什么 / 这个端口用来做什么 / 能否结束 / 结束后的影响 / 会不会自动恢复」。
- **五级退出建议**：禁止结束、不建议结束、谨慎后可结束、通常可以结束、本程序自身，并用颜色区分。
- **安全退出**：二次确认 → 温和关闭（WM_CLOSE 或 `taskkill` 不带 `/F`）→ 进程未响应时才询问是否强制结束。
- **硬护栏**：系统关键进程、本程序自身及其父进程一律拒绝结束，避免误杀。
- **变化感知**：新增 / 释放的端口高亮并在状态栏计数；支持搜索、协议筛选、排序、暂停刷新与 1 / 2 / 5 秒或手动刷新。
- **操作留痕**：每次操作写入 `logs/port_monitor.log`。

## 快速开始

1. 环境：Windows 10 / 11，Python 3.10 或更高版本，安装时勾选 **Add Python to PATH**。
   `tkinter` 随官方 Python 安装包提供；`psutil` 是可选依赖，未安装时会自动回退到 `netstat` + `tasklist` + Win32 API。
2. 双击 `start.bat`（优先用 `pythonw` 启动，没有控制台黑框）；或在命令行运行 `python app.py`。
3. 需要结束系统服务类进程时：**右键 `start.bat` →「以管理员身份运行」**。

## 文件结构

| 文件 | 说明 |
| --- | --- |
| `app.py` | tkinter 界面、详情面板、退出交互流程 |
| `core.py` | 端口采集、进程信息、结束控制、操作日志（可无界面调用） |
| `explain.py` | 进程 / 端口知识库，生成通俗说明与退出建议 |
| `verify.py` | 无头自测脚本 |
| `start.bat` | Windows 一键启动 |
| `README.md` | 本文档 |
| `.gitignore` | 忽略缓存与运行日志 |

## 安全设计

- 任何结束操作都必须先通过 `core.check_terminable()`：PID 0/4、本程序自身及父进程链、系统关键进程名单一律拒绝，并说明原因。
- 二次确认框会展示完整路径与命令行，避免认错进程；结束后的影响也在同一窗口显示。
- 默认绝不强制结束；强制操作必须由用户在温和关闭失败后再确认一次。
- 所有结果写入本地日志，便于事后追溯。

## 自测

```bat
python verify.py 5
```

脚本会启动真实的测试监听进程（TCP IPv4 / TCP IPv6 / UDP），验证采集、变化差分、护栏、温和关闭与强制结束、端口释放、psutil 缺失时的回退路径、详情面板分区以及界面构造。**不会操作系统进程。**

## 已知行为

Windows 对没有窗口的后台 / 控制台进程会直接拒绝温和终止（系统返回「只能强行终止」）。这类目标会进入「温和关闭失败 → 询问是否强制结束」流程，这是「温和优先」策略的预期设计，不是错误。

## 扩展说明

编辑 `explain.py` 里的 `PROCESS_KB` / `PORT_KB` 两个字典即可增加进程与端口的通俗解释。整个解释层纯本地规则，不联网、不调用任何大模型。

---

## English

[简体中文](#简体中文)

A Windows GUI tool that lists listening ports and the processes behind them, explains in plain language what each program does, whether it is safe to close, and what happens afterwards — then lets you terminate the process safely.

> **Important: if terminating a process fails, try this first**
>
> **Right-click `start.bat` → "Run as administrator".**
>
> This is a verified fix from real-world use. In a standard (non-elevated) session, Windows refuses to terminate certain system processes and services started by other accounts. Typical symptoms: termination fails, an access-denied error appears, or process paths and command lines come back blank. Re-running the app elevated resolves it.
> The status bar always shows whether the app is running elevated, so you can check before you try.

### Features

- **Port overview**: TCP / UDP, IPv4 / IPv6, listening and established connections, with port, PID, process name, full path and command line.
- **Plain-language explanation**: select any row to see "What is this / What is this port for / Can I close it / What happens if I do / Will it come back".
- **Five-level recommendation**: Do not close, Not recommended, Close with care, Usually safe to close, This app itself — each colour-coded.
- **Safe termination**: confirmation dialog → graceful close (`WM_CLOSE` or `taskkill` without `/F`) → only ask about a forced kill if the process is still alive.
- **Hard guardrails**: critical system processes, the app itself and its parent chain are always refused, with a reason.
- **Change awareness**: newly appeared / released ports are highlighted and counted; search, protocol filter, sorting, pause, and 1 / 2 / 5 s or manual refresh.
- **Audit trail**: every action is appended to `logs/port_monitor.log`.

### Quick start

1. Requirements: Windows 10 / 11 and Python 3.10+ with **Add Python to PATH** enabled.
   `tkinter` ships with the official Python installer; `psutil` is optional — the app falls back to `netstat` + `tasklist` + Win32 API when it is missing.
2. Double-click `start.bat` (uses `pythonw` when available, so there is no console window), or run `python app.py`.
3. To terminate system services: **right-click `start.bat` → "Run as administrator"**.

### Files

| File | Purpose |
| --- | --- |
| `app.py` | tkinter UI, detail panel, termination flow |
| `core.py` | Port collection, process info, termination control, logging (headless-friendly) |
| `explain.py` | Process / port knowledge base and plain-language advice |
| `verify.py` | Headless self-test |
| `start.bat` | One-click Windows launcher |
| `README.md` | This document |
| `.gitignore` | Ignores caches and runtime logs |

### Safety design

- Every termination goes through `core.check_terminable()`: PID 0/4, the app itself and its parent chain, and a list of critical system processes are always refused.
- The confirmation dialog shows the full path and command line, plus the expected impact, so you can verify the target before acting.
- Forced termination is never the default; the user must confirm it separately after a graceful attempt fails.
- All results are written to a local log for later review.

### Self-test

```bat
python verify.py 5
```

Starts real test listeners (TCP IPv4 / TCP IPv6 / UDP) and verifies collection, diffing, guardrails, graceful and forced termination, port release, the psutil-free fallback path, detail-panel sections and UI construction. **It never touches system processes.**

### Known behaviour

Windows refuses a graceful stop for windowless background / console processes ("can only be terminated forcefully"). Those targets go through the "graceful attempt failed → ask about forced kill" path. This is the intended consequence of the graceful-first policy, not a bug.

### Extending

Add plain-language descriptions by editing the `PROCESS_KB` / `PORT_KB` dictionaries in `explain.py`. The explanation layer is entirely local: no network calls, no LLM.
