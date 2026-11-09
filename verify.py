# -*- coding: utf-8 -*-
"""无头自测：起真实的测试监听进程，验证采集、差分、护栏、退出控制与日志。

用法： python verify.py [轮数，默认 3]
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

import core
import explain

CHILD_CODE = r'''
import socket, sys, time
proto = sys.argv[1]
if proto == "tcp6":
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::1", 0))
    s.listen(5)
elif proto == "tcp":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(5)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
print("READY", s.getsockname()[1], flush=True)
while True:
    time.sleep(0.3)
'''

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = ""):
    results.append((name, bool(ok), detail))
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", name,
                           (" - " + detail) if detail else ""))


def spawn(proto: str):
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD_CODE, proto],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    line = proc.stdout.readline().strip()
    if not line.startswith("READY"):
        raise RuntimeError("child did not report READY: %r" % line)
    return proc, int(line.split()[1])


def wait_listen(port: int, pid: int, timeout: float = 6.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for e in core.snapshot(include_established=True):
            if e.port == port and e.pid == pid and e.state == "LISTEN":
                return e
        time.sleep(0.35)
    return None


def kill_leftover(proc):
    if proc.poll() is None:
        try:
            proc.kill()
        except Exception:
            pass


def run_round(index: int):
    print("\n=== 第 %d 轮 ===" % index)
    base = core.snapshot(include_established=True)
    check("采集返回非空快照", len(base) > 0, "%d 条" % len(base))
    check("监听条目可读到进程路径",
          any(e.state == "LISTEN" and e.exe for e in base))

    fake = core.PortEntry(proto="TCP", port=1, pid=1, pname="x.exe")
    added, removed, now = core.diff_keys(set(), [fake])
    check("差分：新增识别", len(added) == 1 and len(removed) == 0)
    check("差分：释放识别", len(core.diff_keys(now, [])[1]) == 1)

    check("护栏：拦截系统 PID 4", not core.check_terminable(4, "System")[0])
    check("护栏：拦截自身进程", not core.check_terminable(os.getpid(), "python.exe")[0])
    check("护栏：拦截 svchost.exe",
          not core.check_terminable(999999, "svchost.exe")[0])
    check("护栏：放行普通进程", core.check_terminable(999999, "myapp.exe")[0])

    for proto, label in (("tcp", "TCP IPv4"), ("tcp6", "TCP IPv6"), ("udp", "UDP")):
        try:
            proc, port = spawn(proto)
        except Exception as exc:
            check("%s 测试监听启动" % label, False, str(exc))
            continue
        try:
            entry = wait_listen(port, proc.pid)
            check("%s 端口被正确采集" % label, entry is not None,
                  "port=%s pid=%s" % (port, proc.pid))
            if entry is None:
                continue
            ok, msg = core.graceful_terminate(proc.pid, 1.5,
                                              entry.pname, entry.exe)
            if ok:
                check("%s 温和关闭生效" % label, True, msg[:70])
            else:
                check("%s 温和关闭按预期返回失败态" % label,
                      any(k in msg for k in ("仍在运行", "强制结束", "拒绝温和")),
                      msg[:70])
                ok2, msg2 = core.force_terminate(proc.pid,
                                                 entry.pname, entry.exe)
                check("%s 强制结束生效" % label, ok2, msg2[:70])
            time.sleep(0.4)
            still = [e for e in core.snapshot(include_established=True)
                     if e.port == port and e.pid == proc.pid and e.state == "LISTEN"]
            check("%s 结束后端口释放" % label, not still)
            core.log_action("SELFTEST", entry,
                            "成功" if not still else "端口仍占用", label)
        finally:
            kill_leftover(proc)

    check("操作日志写入", os.path.exists(core.log_path()) and
          os.path.getsize(core.log_path()) > 0, core.log_path())


def fallback_test():
    print("\n=== psutil 缺失时的 netstat 回退路径 ===")
    saved = core.psutil
    core.psutil = None
    try:
        raw = core._netstat_raw(True)
        check("netstat 解析出条目", len(raw) > 0, "%d 条" % len(raw))
        check("netstat 含监听项与 PID",
              any(r["state"] == "LISTEN" and r["pid"] > 0 for r in raw))
        check("tasklist 能解析进程名",
              "python" in core._tasklist_name(os.getpid()).lower(),
              core._tasklist_name(os.getpid()))
        check("Win32 API 能读取进程路径",
              bool(core._process_path(os.getpid())))
        entries = core.snapshot(include_established=False)
        check("回退模式完整快照可用", len(entries) > 0, "%d 条" % len(entries))
        check("回退模式 pid_exists 可用", core.pid_exists(os.getpid()))
    finally:
        core.psutil = saved


def explain_test():
    print("\n=== 通俗解释与退出建议 ===")
    sys_ent = core.PortEntry(proto="TCP", port=135, pid=4,
                             pname="svchost.exe", exe=r"C:\Windows\System32\svchost.exe")
    a = explain.evaluate(sys_ent)
    check("系统进程判定为禁止结束", a.level == "block", a.level_text)
    check("系统进程有通俗用途说明", len(a.what) > 15, a.what[:50])
    check("系统进程有结束后影响", len(a.impact) > 15, a.impact[:50])
    check("系统进程有自动恢复说明", len(a.restart) > 8)
    check("端口用途可解释", "RPC" in a.port_what or "135" in a.port_what,
          a.port_what)

    db = core.PortEntry(proto="TCP", port=3306, pid=99999, pname="mysqld.exe")
    b = explain.evaluate(db)
    check("数据库端口给出谨慎建议", b.level == "caution", b.level_text)
    check("数据库说明含端口语义", "MySQL" in b.port_what, b.port_what)

    unknown = core.PortEntry(proto="TCP", port=45678, pid=99998,
                             pname="mycoolapp.exe", exe=sys.executable)
    c = explain.evaluate(unknown)
    check("未知程序有兜底说明", len(c.what) > 15, c.what[:60])
    check("兜底说明读到程序自带描述",
          "Python" in c.what or "程序自称" in c.what, c.what[:60])
    check("兜底说明给出建议与影响",
          bool(c.suggestion) and bool(c.impact) and bool(c.level_text))
    check("临时端口有解释", "临时端口" in explain.port_description(50001))
    check("exe 版本信息可读",
          bool(explain.file_info(sys.executable).get("company")),
          str(explain.file_info(sys.executable).get("company")))
    check("弹窗摘要可用", bool(explain.brief(sys_ent)))
    for name, adv in (("系统", a), ("数据库", b), ("未知", c)):
        check("%s说明字段无空值" % name,
              all(getattr(adv, f) for f in
                  ("what", "port_what", "suggestion", "impact", "restart",
                   "level_text", "group", "source")))


def gui_smoke(index: int = 1):
    print("\n=== 界面构造 smoke test #%d ===" % index)
    try:
        import tkinter as tk
        import app
        root = tk.Tk()
        root.withdraw()
        ui = app.PortMonitorApp(root)
        root.update()
        check("主窗口与表格构造成功", len(ui.tree["columns"]) == len(app.COLUMNS))
        deadline = time.monotonic() + 10
        while not ui.entries and time.monotonic() < deadline:
            root.update()
            time.sleep(0.05)
        check("界面异步采集到数据", bool(ui.entries), "%d 条" % len(ui.entries))
        ui.render(force=True)
        root.update()
        check("渲染后表格有数据", len(ui.tree.get_children()) > 0,
              "%d 行" % len(ui.tree.get_children()))
        ui.tree.selection_set(ui.tree.get_children()[0])
        ui.on_select()
        panel = ui.detail.get("1.0", "end")
        for section in ("【这是什么】", "【这个端口用来做什么】", "【能否结束】",
                        "【结束后的影响】", "【会不会自动恢复】", "【技术信息】"):
            check("详情面板含分区 " + section, section in panel)
        check("详情面板含退出等级",
              any(w in panel for w in ("禁止结束", "不建议结束", "谨慎后可结束",
                                       "通常可以结束", "本程序自身")))
        sample = core.PortEntry(port=1, pid=1, pname="demo.exe")
        dlg_cancel = app.ConfirmDialog(root, sample)
        root.after(80, dlg_cancel._cancel)
        root.wait_window(dlg_cancel)
        check("确认对话框取消流程", dlg_cancel.result is False)
        dlg_ok = app.ConfirmDialog(root, sample)
        root.after(80, dlg_ok._confirm)
        root.wait_window(dlg_ok)
        check("确认对话框确认流程", dlg_ok.result is True)
        ui.shutdown()
    except Exception as exc:
        check("界面构造 smoke test", False, "%s: %s" % (type(exc).__name__, exc))


def main():
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    print("Python %s | psutil %s | admin %s" % (
        sys.version.split()[0], core.psutil is not None, core.is_admin()))
    for i in range(1, rounds + 1):
        run_round(i)
    fallback_test()
    explain_test()
    for i in range(1, 4):
        gui_smoke(i)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = [r for r in results if not r[1]]
    print("\n===== 汇总：%d/%d 通过 =====" % (passed, len(results)))
    for name, _, detail in failed:
        print("  FAILED: %s - %s" % (name, detail))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
