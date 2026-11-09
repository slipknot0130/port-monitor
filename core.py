# -*- coding: utf-8 -*-
"""端口监视器核心层：端口采集、进程信息、进程退出控制、操作日志。

本模块不依赖 tkinter，可在无界面环境下被脚本直接调用测试。
数据源优先使用 psutil；缺失时自动回退到 netstat + tasklist + Win32 API。
"""
from __future__ import annotations

import ctypes
import os
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime

try:
    import psutil
except Exception:
    psutil = None

APP_NAME = "PortMonitor"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "port_monitor.log")

# 禁止结束的进程：结束它们会导致系统不稳定或桌面消失
PROTECTED_NAMES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe",
    "lsm.exe", "audiodg.exe", "spoolsv.exe", "explorer.exe",
}
PROTECTED_PIDS = {0, 4}

_ENCODING = "mbcs" if os.name == "nt" else "utf-8"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SYSROOT = os.environ.get("SystemRoot", r"C:\Windows")
_SYS32 = os.path.join(_SYSROOT, "System32")


def _sys_tool(name: str) -> str:
    path = os.path.join(_SYS32, name)
    return path if os.path.exists(path) else name


@dataclass
class PortEntry:
    proto: str = ""
    family: str = ""
    state: str = ""
    ip: str = ""
    port: int = 0
    raddr: str = ""
    pid: int = 0
    pname: str = ""
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    created: str = ""
    key: tuple = field(default_factory=tuple)
    flag: str = ""

    @property
    def local(self) -> str:
        if ":" in self.ip:
            return "[%s]:%s" % (self.ip, self.port)
        return "%s:%s" % (self.ip, self.port)

    def as_line(self) -> str:
        return "port=%s proto=%s pid=%s name=%s path=%s" % (
            self.port, self.proto, self.pid, self.pname, self.exe)


# --------------------------------------------------------------------------
# 基础工具
# --------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(args, timeout: float = 8.0):
    try:
        cp = subprocess.run(
            args, capture_output=True, text=True, encoding=_ENCODING,
            errors="replace", timeout=timeout, creationflags=_NO_WINDOW,
        )
        return cp.returncode, (cp.stdout or "") + (cp.stderr or "")
    except Exception as exc:
        return -1, str(exc)


def _process_path(pid: int) -> str:
    """用 Win32 API 取进程完整路径，非管理员也能读大部分进程。"""
    if os.name != "nt" or not pid or pid <= 0:
        return ""
    try:
        k32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = ctypes.c_ulong(32768)
            if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                return buf.value
        finally:
            k32.CloseHandle(handle)
    except Exception:
        pass
    return ""


def _tasklist_name(pid: int) -> str:
    rc, out = _run([_sys_tool("tasklist.exe"), "/FI", "PID eq %s" % pid,
                    "/FO", "CSV", "/NH"], timeout=5)
    if rc != 0 or not out:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("INFO:") or line.startswith("信息:"):
            continue
        parts = line.split('","')
        if parts:
            return parts[0].strip('"')
    return ""


def pid_exists(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    if psutil is not None:
        try:
            return psutil.pid_exists(pid)
        except Exception:
            pass
    if os.name != "nt":
        return False
    try:
        k32 = ctypes.windll.kernel32
        handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        k32.GetExitCodeProcess(handle, ctypes.byref(code))
        k32.CloseHandle(handle)
        return code.value == 259  # STILL_ACTIVE
    except Exception:
        return False


def process_details(pid: int, cache: dict | None = None) -> dict:
    info = dict(pname="", exe="", cmdline="", username="", created="")
    if not pid or pid <= 0:
        return info
    if cache is not None and pid in cache:
        return cache[pid]

    if psutil is not None:
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                info["pname"] = p.name()
                for attr, fn in (
                    ("exe", p.exe), ("cmdline", lambda: " ".join(p.cmdline())),
                    ("username", p.username),
                ):
                    try:
                        value = fn()
                        info[attr] = value if isinstance(value, str) else str(value)
                    except Exception:
                        pass
                try:
                    info["created"] = datetime.fromtimestamp(
                        p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
        except Exception:
            info["pname"] = _tasklist_name(pid)
    else:
        info["pname"] = _tasklist_name(pid)

    if not info["exe"]:
        info["exe"] = _process_path(pid)
    if not info["pname"] and info["exe"]:
        info["pname"] = os.path.basename(info["exe"])

    if cache is not None:
        cache[pid] = info
    return info


# --------------------------------------------------------------------------
# 端口采集
# --------------------------------------------------------------------------
def _split_addr(text: str):
    text = (text or "").strip()
    if text.startswith("["):
        end = text.find("]")
        if end > 0:
            ip = text[1:end]
            port_text = text[end + 1:].lstrip(":")
        else:
            ip, port_text = text, "0"
    else:
        ip, _, port_text = text.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        port = 0
    return ip, port


def _psutil_raw(include_established: bool):
    raw = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.type == socket.SOCK_STREAM:
                proto, state = "TCP", (conn.status or "").upper()
            elif conn.type == socket.SOCK_DGRAM:
                proto, state = "UDP", "LISTEN"
            else:
                continue
            if not include_established and proto == "TCP" and state != "LISTEN":
                continue
            if not conn.laddr:
                continue
            ip, port = conn.laddr.ip, conn.laddr.port
            family = "IPv6" if conn.family == socket.AF_INET6 else "IPv4"
            raddr = ("%s:%s" % (conn.raddr.ip, conn.raddr.port)) if conn.raddr else ""
            raw.append(dict(proto=proto, family=family, state=state, ip=ip,
                            port=port, raddr=raddr, pid=conn.pid or 0))
        except Exception:
            continue
    return raw


def _netstat_raw(include_established: bool):
    rc, out = _run([_sys_tool("netstat.exe"), "-ano"], timeout=12)
    if rc != 0 and not out:
        return []
    raw = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
            continue
        proto = parts[0]
        ip, port = _split_addr(parts[1])
        if proto == "TCP":
            if len(parts) < 5:
                continue
            state = parts[3].upper()
            if state == "LISTENING":
                state = "LISTEN"
            if not include_established and state != "LISTEN":
                continue
            raddr = parts[2] if parts[2] not in ("*:*", "0.0.0.0:0", "[::]:0") else ""
            try:
                pid = int(parts[4])
            except ValueError:
                pid = 0
        else:
            state = "LISTEN"
            raddr = ""
            try:
                pid = int(parts[3])
            except (ValueError, IndexError):
                pid = 0
        family = "IPv6" if ":" in ip else "IPv4"
        raw.append(dict(proto=proto, family=family, state=state, ip=ip,
                        port=port, raddr=raddr, pid=pid))
    return raw


def snapshot(include_established: bool = True) -> list[PortEntry]:
    """采集当前连接/监听端口，并补全进程详情。"""
    raw = (_psutil_raw(include_established) if psutil is not None
           else _netstat_raw(include_established))
    cache: dict[int, dict] = {}
    result = []
    for item in raw:
        info = process_details(item["pid"], cache)
        key = (item["proto"], item["family"], item["ip"], item["port"], item["pid"])
        result.append(PortEntry(
            proto=item["proto"], family=item["family"], state=item["state"],
            ip=item["ip"], port=item["port"], raddr=item["raddr"],
            pid=item["pid"], pname=info["pname"], exe=info["exe"],
            cmdline=info["cmdline"], username=info["username"],
            created=info["created"], key=key,
        ))
    result.sort(key=lambda e: (e.port, e.proto, e.pid))
    return result


def diff_keys(previous: set, current: list[PortEntry]):
    """返回 (新增 key 集合, 消失 key 集合)。"""
    now = {e.key for e in current}
    return now - previous, previous - now, now


# --------------------------------------------------------------------------
# 退出控制
# --------------------------------------------------------------------------
def _self_lineage() -> set[int]:
    pids = {os.getpid()}
    if psutil is not None:
        try:
            pids.update(p.pid for p in psutil.Process(os.getpid()).parents())
        except Exception:
            pass
    return pids


_SELF_LINEAGE = None
_NAME_CACHE: dict[int, str] = {}


def _lookup_name(pid: int, exe: str) -> str:
    if pid in _NAME_CACHE:
        return _NAME_CACHE[pid]
    name = os.path.basename(exe).lower() if exe else ""
    if not name:
        name = (process_details(pid).get("pname") or "").lower()
    if len(_NAME_CACHE) > 512:
        _NAME_CACHE.clear()
    _NAME_CACHE[pid] = name
    return name


def check_terminable(pid: int, pname: str = "", exe: str = ""):
    """返回 (是否允许, 原因)。这是结束进程前必过的硬护栏。"""
    global _SELF_LINEAGE
    if not pid or pid <= 0:
        return False, "该条目没有有效的 PID（系统保留连接），无法结束"
    if pid in PROTECTED_PIDS:
        return False, "PID %s 属于系统内核进程，禁止结束" % pid
    if _SELF_LINEAGE is None:
        _SELF_LINEAGE = _self_lineage()
    if pid in _SELF_LINEAGE:
        return False, "这是本程序自身或其父进程，禁止结束"
    name = (pname or "").lower()
    if not name:
        name = _lookup_name(pid, exe)
    if name in PROTECTED_NAMES:
        return False, "%s 是系统关键进程，已列入保护名单" % (pname or name)
    return True, "允许"


def _close_windows_of_pid(pid: int) -> int:
    """向该进程的可见顶层窗口发送 WM_CLOSE，返回发送数量。"""
    if os.name != "nt":
        return 0
    try:
        user32 = ctypes.windll.user32
        PROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
        found = {"n": 0}

        def callback(hwnd, _lparam):
            if not user32.IsWindowVisible(hwnd):
                return 1
            owner = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == pid:
                user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
                found["n"] += 1
            return 1

        user32.EnumWindows(PROC(callback), None)
        return found["n"]
    except Exception:
        return 0


def graceful_terminate(pid: int, wait_seconds: float = 3.0,
                       pname: str = "", exe: str = ""):
    """温和关闭：先发 WM_CLOSE；无窗口则 taskkill 不带 /F。返回 (是否结束, 说明)。"""
    allowed, reason = check_terminable(pid, pname, exe)
    if not allowed:
        return False, reason
    if not pid_exists(pid):
        return True, "进程已自行退出，无需操作"

    windows = _close_windows_of_pid(pid)
    note = "已向 %d 个窗口发送关闭消息" % windows
    if windows == 0:
        rc, out = _run([_sys_tool("taskkill.exe"), "/PID", str(pid)])
        brief = " ".join(out.split())[:170]
        note = "已发送温和终止请求（taskkill，不带 /F）：%s" % brief
        if rc != 0 and ("not found" in out.lower() or "找不到" in out):
            return True, "进程在请求发出前已退出"
        if rc != 0 and ("forcefully" in out.lower() or "强行" in out or "/F" in out):
            return False, ("该进程没有可关闭的窗口，系统拒绝温和终止；需要强制结束。"
                           "系统返回：%s" % brief)

    deadline = time.monotonic() + max(0.2, wait_seconds)
    while time.monotonic() < deadline:
        if not pid_exists(pid):
            return True, note + "，进程已退出，端口应已释放"
        time.sleep(0.2)
    return False, note + "，等待 %.1f 秒后进程仍在运行" % wait_seconds


def force_terminate(pid: int, pname: str = "", exe: str = ""):
    """强制结束：仅在用户明确二次确认后调用。"""
    allowed, reason = check_terminable(pid, pname, exe)
    if not allowed:
        return False, reason
    if not pid_exists(pid):
        return True, "进程已自行退出，无需操作"
    if psutil is not None:
        try:
            psutil.Process(pid).kill()
            time.sleep(0.3)
            if not pid_exists(pid):
                return True, "已强制结束（psutil.kill）"
        except Exception:
            pass
    rc, out = _run([_sys_tool("taskkill.exe"), "/PID", str(pid), "/F"])
    if rc == 0:
        return True, "已强制结束（taskkill /F）"
    return False, "强制结束失败：%s%s" % (
        out.strip()[:200], "（可尝试以管理员身份运行）" if not is_admin() else "")


# --------------------------------------------------------------------------
# 操作日志
# --------------------------------------------------------------------------
def log_action(action: str, entry: PortEntry | None, result: str,
               detail: str = ""):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = "%s | %-12s | %s | 结果=%s | %s\n" % (
            stamp, action, entry.as_line() if entry else "-", result, detail)
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass


def log_path() -> str:
    return LOG_FILE
