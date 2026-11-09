# -*- coding: utf-8 -*-
"""本地端口监视器 · 图形界面

功能：列出本机监听/连接端口及占用进程，支持搜索、筛选、定时刷新，
在详情面板用通俗语言说明程序用途、能否结束与结束后的影响，
并可安全地「退出」某个端口对应的监听程序（温和关闭优先，失败后询问强制结束）。
"""
from __future__ import annotations

import ctypes
import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

import core
import explain

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

REFRESH_CHOICES = {"1 秒": 1000, "2 秒": 2000, "5 秒": 5000, "手动": 0}
COLUMNS = [
    ("port", "端口", 72), ("proto", "协议", 62), ("state", "状态", 100),
    ("family", "类型", 62), ("local", "本地地址", 175), ("pid", "PID", 72),
    ("pname", "进程名", 155), ("exe", "可执行路径", 330), ("flag", "变化", 66),
]


class ConfirmDialog(tk.Toplevel):
    """结束进程前的二次确认，完整展示目标进程信息。"""

    def __init__(self, parent, entry: core.PortEntry):
        super().__init__(parent)
        self.result = False
        self.title("确认结束进程")
        self.transient(parent)
        self.resizable(False, False)
        self.grab_set()

        frame = ttk.Frame(self, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="即将结束占用该端口的进程，请确认目标无误：",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w")

        lines = [
            ("端口", "%s  %s  %s  %s" % (entry.port, entry.proto, entry.family, entry.state)),
            ("本地地址", entry.local),
            ("PID", str(entry.pid or "-")),
            ("进程名", entry.pname or "-"),
            ("完整路径", entry.exe or "（权限不足，无法读取）"),
            ("命令行", entry.cmdline or "（权限不足，无法读取）"),
            ("所属用户", entry.username or "-"),
            ("启动时间", entry.created or "-"),
        ]
        box = tk.Text(frame, width=82, height=10, wrap="word",
                      font=("Consolas", 9), background="#F7F8FA",
                      relief="solid", borderwidth=1)
        for label, value in lines:
            box.insert("end", "%-10s %s\n" % (label + "：", value))
        box.configure(state="disabled")
        box.pack(fill="both", expand=True, pady=(10, 8))

        ttk.Label(frame, foreground="#A32D2D",
                  text="默认只发送温和关闭请求；若进程未响应，会再次询问是否强制结束。\n"
                       "结束后的影响：%s" % explain.evaluate(entry).impact,
                  wraplength=560).pack(anchor="w", pady=(0, 10))

        bar = ttk.Frame(frame)
        bar.pack(fill="x")
        ttk.Button(bar, text="取消", command=self._cancel).pack(side="right")
        ttk.Button(bar, text="温和关闭", command=self._confirm).pack(side="right", padx=6)
        self.bind("<Escape>", lambda _e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry("+%d+%d" % (max(0, x), max(0, y)))

    def _confirm(self):
        self.result = True
        self.destroy()

    def _cancel(self):
        self.result = False
        self.destroy()

    @classmethod
    def ask(cls, parent, entry) -> bool:
        dlg = cls(parent, entry)
        parent.wait_window(dlg)
        return dlg.result


class PortMonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.entries: dict[tuple, core.PortEntry] = {}
        self.iid_key: dict[str, tuple] = {}
        self.new_keys: set = set()
        self.watch_ports: set[int] = set()
        self.released_hint = ""
        self.last_removed = 0
        self.last_sig = None
        self.last_refresh: datetime | None = None
        self.first_load = True
        self.busy = False
        self.paused = False
        self.running = True
        self._after_ids: set = set()
        self.q: queue.Queue = queue.Queue()
        self.sort_col = "port"
        self.sort_reverse = False
        self._last_detail_sig = None

        self.search_var = tk.StringVar()
        self.proto_var = tk.StringVar(value="全部")
        self.only_listen_var = tk.BooleanVar(value=True)
        self.interval_var = tk.StringVar(value="2 秒")
        self.status_var = tk.StringVar(value="正在初始化…")

        title = "本地端口监视器 · PortMonitor"
        if not core.is_admin():
            title += "（普通权限）"
        root.title(title)
        root.geometry("1180x820")
        root.minsize(940, 640)

        self._build_style()
        self._build_toolbar()
        self._build_table()
        self._build_detail()
        self._build_bottom()

        self._later(120, self._drain)
        self._later(150, self._tick)
        self.request_refresh()
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)

    def _later(self, delay: int, fn):
        """登记定时器，回调执行后自动注销，退出时可一次性取消全部残留。"""
        holder = [None]

        def wrapper():
            self._after_ids.discard(holder[0])
            if self.running:
                fn()

        try:
            holder[0] = self.root.after(delay, wrapper)
            self._after_ids.add(holder[0])
        except Exception:
            pass
        return holder[0]

    # ---------------------------------------------------------------- UI
    def _build_style(self):
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=24, font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"))
        style.configure("Danger.TButton", foreground="#A32D2D")

    def _build_toolbar(self):
        bar = ttk.Frame(self.root, padding=(8, 8, 8, 4))
        bar.pack(fill="x")

        ttk.Label(bar, text="搜索").pack(side="left")
        entry = ttk.Entry(bar, textvariable=self.search_var, width=22)
        entry.pack(side="left", padx=(4, 12))
        self.search_var.trace_add("write", lambda *_: self.render(force=True))

        ttk.Label(bar, text="协议").pack(side="left")
        proto = ttk.Combobox(bar, textvariable=self.proto_var, width=7,
                             state="readonly", values=["全部", "TCP", "UDP"])
        proto.pack(side="left", padx=(4, 12))
        proto.bind("<<ComboboxSelected>>", lambda *_: self.render(force=True))

        ttk.Checkbutton(bar, text="仅显示监听中", variable=self.only_listen_var,
                        command=lambda: self.render(force=True)).pack(side="left", padx=(0, 12))

        ttk.Label(bar, text="刷新").pack(side="left")
        interval = ttk.Combobox(bar, textvariable=self.interval_var, width=7,
                                state="readonly", values=list(REFRESH_CHOICES))
        interval.pack(side="left", padx=(4, 12))

        self.pause_btn = ttk.Button(bar, text="暂停刷新", command=self.toggle_pause, width=10)
        self.pause_btn.pack(side="left", padx=(0, 6))
        ttk.Button(bar, text="立即刷新", command=self.request_refresh, width=10).pack(side="left")

        ttk.Label(bar, text="（可输入端口 / PID / 进程名 / 路径过滤）",
                  foreground="#5F5E5A").pack(side="left", padx=(12, 0))

    def _build_table(self):
        wrap = ttk.Frame(self.root, padding=(8, 2))
        wrap.pack(fill="both", expand=True)
        cols = [c[0] for c in COLUMNS]
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings",
                                 selectmode="extended")
        for key, label, width in COLUMNS:
            self.tree.heading(key, text=label,
                              command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, minwidth=50,
                             anchor="w" if key in ("local", "exe", "pname") else "center")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1)
        wrap.columnconfigure(0, weight=1)

        self.tree.tag_configure("new", background="#EAF3DE")
        self.tree.tag_configure("protected", foreground="#888780")
        self.tree.tag_configure("self", background="#FAEEDA")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Button-3>", self.on_right_click)
        self.tree.bind("<Double-1>", lambda _e: self.show_detail_dialog())

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="结束选中进程", command=self.terminate_selected)
        self.menu.add_command(label="查看完整详情", command=self.show_detail_dialog)
        self.menu.add_separator()
        self.menu.add_command(label="复制端口", command=lambda: self.copy_field("port"))
        self.menu.add_command(label="复制 PID", command=lambda: self.copy_field("pid"))
        self.menu.add_command(label="打开所在文件夹", command=self.open_location)

    def _build_detail(self):
        box = ttk.LabelFrame(self.root,
                             text="选中条目详解 · 大白话说明 + 退出建议", padding=6)
        box.pack(fill="x", padx=8, pady=(2, 2))
        frame = ttk.Frame(box)
        frame.pack(fill="x")
        self.detail = tk.Text(frame, height=11, wrap="word",
                              font=("Microsoft YaHei UI", 9),
                              background="#F7F8FA", relief="flat",
                              padx=6, pady=4)
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=sb.set)
        self.detail.pack(side="left", fill="x", expand=True)
        sb.pack(side="right", fill="y")

        ui_font = ("Microsoft YaHei UI", 9)
        self.detail.tag_configure("h", font=(ui_font[0], 9, "bold"),
                                  foreground="#0C447C", spacing1=8)
        self.detail.tag_configure("danger", font=(ui_font[0], 9, "bold"),
                                  foreground="#A32D2D")
        self.detail.tag_configure("warn", font=(ui_font[0], 9, "bold"),
                                  foreground="#854F0B")
        self.detail.tag_configure("safe", font=(ui_font[0], 9, "bold"),
                                  foreground="#3B6D11")
        self.detail.tag_configure("muted", foreground="#5F5E5A")
        self.detail.configure(state="disabled")

    def _build_bottom(self):
        bar = ttk.Frame(self.root, padding=(8, 4))
        bar.pack(fill="x")
        self.terminate_btn = ttk.Button(bar, text="退出选中监听程序",
                                        command=self.terminate_selected,
                                        style="Danger.TButton", width=20)
        self.terminate_btn.pack(side="left")
        ttk.Button(bar, text="查看完整详情", command=self.show_detail_dialog,
                   width=14).pack(side="left", padx=6)
        ttk.Button(bar, text="打开日志文件", command=self.open_log,
                   width=14).pack(side="left")
        ttk.Button(bar, text="退出程序", command=self.shutdown,
                   width=10).pack(side="right")
        ttk.Label(self.root, textvariable=self.status_var, anchor="w",
                  padding=(10, 5), foreground="#5F5E5A").pack(fill="x", side="bottom")

    # ------------------------------------------------------------- 数据循环
    def interval_ms(self) -> int:
        return REFRESH_CHOICES.get(self.interval_var.get(), 2000)

    def _tick(self):
        if not self.running:
            return
        interval = self.interval_ms()
        if interval > 0 and not self.paused and not self.busy:
            self.request_refresh()
        self._later(interval if interval > 0 else 1000, self._tick)

    def request_refresh(self):
        if self.busy or not self.running:
            return
        self.busy = True
        if not self.entries:
            self.status_var.set("首次采集中，请稍候…")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self):
        try:
            data = core.snapshot(include_established=True)
            self.q.put(("data", data))
        except Exception as exc:
            self.q.put(("error", str(exc)))
        finally:
            self.busy = False

    def _drain(self):
        if not self.running:
            return
        while True:
            try:
                kind, payload = self.q.get_nowait()
            except queue.Empty:
                break
            if kind == "error":
                self.status_var.set("采集失败：%s" % payload)
                continue
            entries = payload
            added, removed, _ = core.diff_keys(set(self.entries), entries)
            self.new_keys = set() if self.first_load else added
            self.last_removed = len(removed) if not self.first_load else 0
            self.first_load = False
            self.entries = {e.key: e for e in entries}
            self.last_refresh = datetime.now()
            if self.watch_ports:
                still = {e.port for e in entries if e.state == "LISTEN"}
                gone = self.watch_ports - still
                if gone:
                    self.released_hint = "端口 %s 已释放" % ", ".join(map(str, sorted(gone)))
                    self.watch_ports -= gone
            self.render()
        self._later(150, self._drain)

    # ------------------------------------------------------------- 渲染
    def _sort_key(self, e: core.PortEntry):
        value = getattr(e, self.sort_col, "")
        if self.sort_col in ("port", "pid"):
            try:
                return (1, int(value or 0))
            except (TypeError, ValueError):
                return (0, 0)
        return (0, str(value or "").lower())

    def render(self, force: bool = False):
        entries = list(self.entries.values())
        sig = tuple(sorted((e.key, e.state, e.pname, e.exe, e.flag)
                           for e in entries))
        if not force and sig == self.last_sig:
            self._update_status()
            return
        self.last_sig = sig

        selected = {self.iid_key.get(i) for i in self.tree.selection()}
        yview = self.tree.yview()[0]
        self.tree.delete(*self.tree.get_children())
        self.iid_key = {}

        query = self.search_var.get().strip().lower()
        proto = self.proto_var.get()
        only_listen = self.only_listen_var.get()
        ordered = sorted(entries, key=self._sort_key, reverse=self.sort_reverse)
        shown = 0
        for e in ordered:
            if proto != "全部" and e.proto != proto:
                continue
            if only_listen and e.state != "LISTEN":
                continue
            if query and not any(query in str(v).lower() for v in
                                 (e.port, e.pid, e.ip, e.local, e.pname, e.exe)):
                continue
            flag = "新增" if e.key in self.new_keys else ""
            tags = []
            if flag:
                tags.append("new")
            if e.pid == os.getpid():
                tags.append("self")
            elif e.pid and not core.check_terminable(e.pid, e.pname, e.exe)[0]:
                tags.append("protected")
            iid = self.tree.insert("", "end", values=(
                e.port, e.proto, e.state, e.family, e.local, e.pid or "-",
                e.pname or "-", e.exe or "-", flag), tags=tuple(tags))
            self.iid_key[iid] = e.key
            if e.key in selected:
                self.tree.selection_add(iid)
            shown += 1
        try:
            self.tree.yview_moveto(yview)
        except Exception:
            pass
        self._visible_count = shown
        self._update_status()

    def _update_status(self):
        listening = sum(1 for e in self.entries.values() if e.state == "LISTEN")
        stamp = self.last_refresh.strftime("%H:%M:%S") if self.last_refresh else "-"
        admin = "管理员权限" if core.is_admin() else "普通权限（部分系统进程需管理员才能结束）"
        extra = (" | " + self.released_hint) if self.released_hint else ""
        self.status_var.set(
            "共 %d 条连接，其中监听 %d 个 | 当前显示 %d 行 | 本次新增 %d / 释放 %d | "
            "刷新于 %s | %s | 操作日志已开启%s" % (
                len(self.entries), listening, getattr(self, "_visible_count", 0),
                len(self.new_keys), self.last_removed, stamp, admin, extra))

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.configure(text="恢复刷新" if self.paused else "暂停刷新")
        if not self.paused:
            self.request_refresh()

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_col, self.sort_reverse = col, False
        self.render(force=True)

    # ------------------------------------------------------------- 交互
    def _selected_entries(self) -> list[core.PortEntry]:
        keys = [self.iid_key.get(i) for i in self.tree.selection()]
        return [self.entries[k] for k in keys if k in self.entries]

    def on_select(self, _event=None):
        items = self._selected_entries()
        sig = tuple((e.key, e.pname, e.exe, e.cmdline, e.state) for e in items)
        if sig == self._last_detail_sig:
            return
        self._last_detail_sig = sig

        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")

        def put(text, *tags):
            self.detail.insert("end", text, tags if tags else ())

        if not items:
            put("【选中一行查看通俗解释】\n", "h")
            put("这里会说明这个程序是干什么的、能不能结束，以及结束后会发生什么。\n")
            put("右键表格可结束进程、复制端口或 PID、打开文件所在位置；双击可看完整详情。\n", "muted")
        elif len(items) > 1:
            put("【已选中 %d 项】\n" % len(items), "h")
            put("点击「退出选中监听程序」会逐个确认；只选中一条时，这里会显示通俗解释与退出建议。\n")
        else:
            e = items[0]
            a = explain.evaluate(e)
            put("【这是什么】", "h")
            put("   %s\n" % a.group, "muted")
            put(a.what + "\n")
            put("【这个端口用来做什么】\n", "h")
            put(a.port_what + "\n")
            put("【能否结束】", "h")
            put("   %s\n" % a.level_text, a.tag)
            if a.level in ("block", "self"):
                put("原因：%s\n" % a.reason, "muted")
            put("建议：%s\n" % a.suggestion)
            put("【结束后的影响】\n", "h")
            put(a.impact + "\n")
            put("【会不会自动恢复】\n", "h")
            put(a.restart + "\n")
            put("【技术信息】\n", "h")
            put("端口 %s · %s · %s · %s · 本地 %s · 远程 %s · PID %s\n" % (
                e.port, e.proto, e.family, e.state, e.local,
                e.raddr or "-", e.pid or "-"), "muted")
            put("进程 %s · 用户 %s · 启动 %s\n" % (
                e.pname or "-", e.username or "-", e.created or "-"), "muted")
            put("路径 %s\n" % (e.exe or "-"), "muted")
            put("命令行 %s\n" % (e.cmdline or "-"), "muted")
            put("说明来源：%s\n" % a.source, "muted")
        self.detail.yview_moveto(0)
        self.detail.configure(state="disabled")

    def on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            self.tree.selection_set(iid)
        if self.tree.selection():
            self.menu.tk_popup(event.x_root, event.y_root)

    def copy_field(self, field):
        items = self._selected_entries()
        if not items:
            return
        value = "\n".join(str(getattr(e, field)) for e in items)
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.status_var.set("已复制 %d 个%s到剪贴板" % (len(items), field))

    def open_location(self):
        items = self._selected_entries()
        if not items or not items[0].exe:
            messagebox.showinfo("提示", "没有可用的进程路径。", parent=self.root)
            return
        folder = os.path.dirname(items[0].exe)
        if os.path.isdir(folder):
            os.startfile(folder)
        else:
            messagebox.showwarning("提示", "目录不存在：%s" % folder, parent=self.root)

    def open_log(self):
        path = core.log_path()
        if os.path.exists(path):
            os.startfile(path)
        else:
            messagebox.showinfo("提示", "尚无操作日志。结束一次进程后会自动生成。",
                                parent=self.root)

    def show_detail_dialog(self):
        items = self._selected_entries()
        if not items:
            return
        e = items[0]
        a = explain.evaluate(e)
        messagebox.showinfo("条目详情",
            "【这是什么】\n%s\n\n"
            "【这个端口用来做什么】\n%s\n\n"
            "【能否结束】%s\n%s\n\n"
            "【结束后的影响】\n%s\n\n"
            "【会不会自动恢复】\n%s\n\n"
            "【技术信息】\n端口 %s  %s / %s  %s\n本地 %s\nPID %s\n进程 %s\n"
            "路径 %s\n命令行 %s\n用户 %s\n启动 %s" % (
                a.what, a.port_what, a.level_text, a.suggestion,
                a.impact, a.restart, e.port, e.proto, e.family, e.state,
                e.local, e.pid or "-", e.pname or "-", e.exe or "-",
                e.cmdline or "-", e.username or "-", e.created or "-"),
            parent=self.root)

    # ------------------------------------------------------------- 结束进程
    def terminate_selected(self):
        items = self._selected_entries()
        if not items:
            messagebox.showinfo("提示", "请先在表格中选中要结束的进程所在行。",
                                parent=self.root)
            return
        if len(items) > 1 and not messagebox.askokcancel(
                "批量操作", "已选中 %d 项，将逐个弹出确认框，逐项执行。继续？" % len(items),
                parent=self.root):
            return
        for e in items:
            self.terminate_one(e)
        self.released_hint = ""
        self._later(900, self.request_refresh)

    def terminate_one(self, e: core.PortEntry):
        allowed, reason = core.check_terminable(e.pid, e.pname, e.exe)
        if not allowed:
            core.log_action("BLOCKED", e, "拒绝", reason)
            messagebox.showwarning("操作已被阻止",
                "%s\n\n%s\n\n为保护系统稳定，此操作不会执行。" % (e.pname or e.exe or "-", reason),
                parent=self.root)
            return
        if not ConfirmDialog.ask(self.root, e):
            core.log_action("CANCEL", e, "用户取消")
            return

        ok, msg = core.graceful_terminate(e.pid, 3.0, e.pname, e.exe)
        if ok:
            core.log_action("GRACEFUL", e, "成功", msg)
            self.watch_ports.add(e.port)
            messagebox.showinfo("已完成",
                "端口 %s 对应的进程已温和退出。\n\n%s\n\n稍后状态栏会显示端口释放结果。" % (
                    e.port, msg), parent=self.root)
            return

        core.log_action("GRACEFUL_FAIL", e, "失败", msg)
        force = messagebox.askyesno("温和关闭未生效",
            "%s\n\n目标：%s (PID %s)\n\n是否强制结束？强制结束可能使该进程丢失未保存的数据。" % (
                msg, e.pname or "-", e.pid), parent=self.root)
        if not force:
            core.log_action("FORCE_CANCEL", e, "用户取消强制")
            return
        ok2, msg2 = core.force_terminate(e.pid, e.pname, e.exe)
        core.log_action("FORCE", e, "成功" if ok2 else "失败", msg2)
        if ok2:
            self.watch_ports.add(e.port)
            messagebox.showinfo("强制结束完成", msg2, parent=self.root)
        else:
            messagebox.showerror("强制结束失败", msg2, parent=self.root)

    def shutdown(self):
        self.running = False
        for after_id in list(self._after_ids):
            try:
                self.root.after_cancel(after_id)
            except Exception:
                pass
        self._after_ids.clear()
        self.root.destroy()


def main():
    root = tk.Tk()
    PortMonitorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
