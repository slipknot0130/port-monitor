# -*- coding: utf-8 -*-
"""把端口与进程信息翻译成普通人能看懂的说明，并给出退出建议与影响预估。

纯本地规则，不联网、不调用大模型：
1) 内置常见 Windows 进程 / 常用软件知识库；
2) 知识库未命中时，读取 exe 自带的「文件说明 / 产品名称 / 公司」，再按安装路径推断；
3) 结合端口用途、系统护栏结论，输出风险等级、建议、结束后的影响、是否会自动恢复。

想扩充规则，直接改 PROCESS_KB / PORT_KB 两个字典即可。
"""
from __future__ import annotations

import ctypes
import os
import struct
from dataclasses import dataclass
from functools import lru_cache

import core

# ---------------------------------------------------------------------------
# 风险等级
# ---------------------------------------------------------------------------
LEVEL_STYLE = {
    "block": ("禁止结束", "danger"),
    "avoid": ("不建议结束", "warn"),
    "caution": ("谨慎后可结束", "warn"),
    "ok": ("通常可以结束", "safe"),
    "self": ("本程序自身", "danger"),
}

SUGGESTION = {
    "block": "请保留它。如果它占用了你想要的端口，正确做法是改你自己程序的端口，而不是结束系统进程。",
    "avoid": "建议保留。确实需要停用时，优先用该软件自己的退出菜单，或在「服务」管理器里停止对应服务。",
    "caution": "先确认没有别的任务正在依赖它，再结束；结束后如果要继续用，记得重新启动。",
    "ok": "可以结束。结束前请先保存这个程序里正在编辑的内容。",
    "self": "这是监视器自己，请点窗口右下角的「退出程序」。",
}


def K(what: str, level: str, impact: str, restart: str, group: str = "软件"):
    return dict(what=what, level=level, impact=impact, restart=restart, group=group)


# ---------------------------------------------------------------------------
# 常见进程知识库（键为小写进程名）
# ---------------------------------------------------------------------------
PROCESS_KB = {
    "system": K("这是 Windows 内核自己占用的连接，代表操作系统底层，并不是一个能关掉的软件。",
                "block", "无法结束；强行针对它操作只会导致系统不稳定。",
                "它随 Windows 启动，一直存在。", "系统"),
    "system idle process": K("表示 CPU 当前空闲的比例，只是一个统计数字，不是真实程序。",
                "block", "无需也无法结束。", "一直存在。", "系统"),
    "registry": K("Windows 注册表在内存中的工作区，系统配置的存放地。",
                "block", "结束会影响整个系统。", "随系统启动。", "系统"),
    "memory compression": K("Windows 压缩内存以节省物理内存的机制，属于系统底层。",
                "block", "结束会让可用内存变少、系统变卡。", "由系统自动管理。", "系统"),
    "svchost.exe": K("Windows 把很多后台功能拆成一个个「服务」，这个进程是这些服务共用的外壳。"
                   "它本身不干具体的活，真正干活的是装在里面的服务，比如网络、更新、共享、DNS 等。",
                "block", "装在它里面的服务会一起停掉，可能出现断网、无法解析网址、共享失效、"
                   "更新失败等问题；多个服务共用一个进程，很难只停其中一个。",
                "关键服务通常会被 Windows 立刻自动重启，但中断期间相关功能不可用，且重启可能失败。", "系统"),
    "lsass.exe": K("Windows 的账号与登录安全模块，负责验证密码、管理登录凭据。",
                "block", "系统安全机制会失效，Windows 通常会在一分钟内自动重启电脑。",
                "无法安全恢复，系统会强制重启。", "系统"),
    "services.exe": K("Windows 服务管理器，所有后台服务的总开关。",
                "block", "系统服务全部失控，通常直接触发重启。", "无法安全恢复。", "系统"),
    "csrss.exe": K("Windows 图形界面的底层支撑进程，负责窗口、控制台等基础机制。",
                "block", "系统直接蓝屏重启。", "无法安全恢复。", "系统"),
    "wininit.exe": K("Windows 开机时的初始化进程，系统启动骨架的一部分。",
                "block", "系统直接崩溃重启。", "无法安全恢复。", "系统"),
    "winlogon.exe": K("负责登录、锁屏、注销和安全桌面（按 Ctrl+Alt+Del 的界面）。",
                "block", "会无法登录或锁屏，可能触发蓝屏。", "无法安全恢复。", "系统"),
    "smss.exe": K("Windows 会话管理器，开机时最早启动的进程之一。",
                "block", "系统崩溃。", "无法安全恢复。", "系统"),
    "dwm.exe": K("桌面窗口管理器，你看到的窗口边框、透明效果、动画和整个画面合成都由它负责。",
                "block", "屏幕可能黑屏或只剩纯色背景，窗口显示异常。",
                "Windows 一般会自动重启它，画面会闪烁几秒。", "系统"),
    "explorer.exe": K("Windows 桌面和文件资源管理器：任务栏、开始菜单、桌面图标、打开的文件夹窗口都是它。",
                "block", "任务栏和桌面图标会消失、文件夹窗口全关；不会损坏文件，但会打断当前操作。",
                "有时会自启；没有的话可以在任务管理器里「运行新任务」输入 explorer 恢复。", "系统"),
    "fontdrvhost.exe": K("系统字体渲染进程，负责把文字画到屏幕上。",
                "block", "屏幕文字可能显示异常。", "系统一般会自动重启它。", "系统"),
    "sihost.exe": K("Windows 外壳基础组件，配合开始菜单、通知中心等界面工作。",
                "block", "开始菜单、通知中心等界面功能异常。", "系统一般会自动重启它。", "系统"),
    "ctfmon.exe": K("输入法与文字服务的后台进程，负责候选词、语言栏。",
                "avoid", "输入法可能无法使用或候选词不出现。", "通常会自动重新出现。", "系统"),
    "audiodg.exe": K("Windows 音频引擎，所有声音都经过它处理。",
                "avoid", "所有程序会没有声音，直到它重新启动。", "播放声音时 Windows 会自动重建。", "系统"),
    "spoolsv.exe": K("打印后台服务，管理打印任务和打印机队列。",
                "avoid", "正在打印的任务会中断，之后也无法打印，直到服务恢复。",
                "Windows 服务管理器通常会自动重启。", "系统"),
    "searchindexer.exe": K("Windows 搜索索引服务，让开始菜单和文件搜索能快速找到东西。",
                "avoid", "搜索变慢或搜不到结果；重建索引会占用 CPU 和磁盘一段时间。",
                "服务通常会自动重启。", "系统"),
    "wmiprvse.exe": K("Windows 管理接口（WMI）的提供程序，很多管理、监控软件靠它读系统信息。",
                "avoid", "部分管理工具、监控软件会取不到数据。", "有程序请求时会自动重新拉起。", "系统"),
    "dllhost.exe": K("COM 组件宿主进程，Windows 里一些小功能模块借它运行。",
                "avoid", "依赖它的具体功能会中断，可能影响资源管理器的部分扩展。",
                "需要时会自动重建。", "系统"),
    "taskhostw.exe": K("Windows 通用任务宿主，负责跑计划任务和部分系统后台任务。",
                "avoid", "计划任务、自动维护可能中断。", "系统会按需重建。", "系统"),
    "runtimebroker.exe": K("权限中介进程，帮助商店应用申请摄像头、麦克风、文件等权限。",
                "avoid", "商店类应用可能打不开或无法访问文件。", "打开相关应用时会自动重建。", "系统"),
    "msmpeng.exe": K("Microsoft Defender 杀毒引擎，负责实时查杀与后台扫描。",
                "avoid", "电脑暂时失去实时防护，恶意软件更容易趁虚而入。",
                "防护服务会自动尝试重启。", "安全软件"),
    "securityhealthservice.exe": K("Windows 安全中心的状态服务，负责显示防护状态与提示。",
                "avoid", "安全中心显示异常，防护状态提醒失效。", "服务会自动重启。", "安全软件"),
    "trustedinstaller.exe": K("Windows 更新与系统文件安装服务，正在安装补丁时会出现。",
                "avoid", "正在安装的更新可能失败，甚至留下损坏的系统文件。",
                "有更新任务时会自动出现。", "系统"),
    "tiworker.exe": K("Windows 更新在后台准备安装文件的进程。",
                "avoid", "更新安装中断，下次需要重新下载准备。", "由更新计划重新触发。", "系统"),
    "wuauclt.exe": K("Windows 更新客户端，负责检查和下载补丁。",
                "avoid", "更新检查中断，不会损坏系统。", "下次更新周期会重新启动。", "系统"),
    "w3wp.exe": K("IIS 网站服务器的工作进程，你本机跑的网站就由它对外提供页面。",
                "caution", "本机网站立刻打不开，正在处理的访问请求会失败。",
                "有新的访问请求时 IIS 通常会自动拉起新的工作进程。", "服务"),
    "sqlservr.exe": K("SQL Server 数据库服务，负责存放和查询数据。",
                "caution", "所有连接这个数据库的程序会立刻报错；正在写入的数据可能不完整。",
                "如果设为自动启动，重启电脑或手动启动服务后恢复。", "数据库"),
    "mysqld.exe": K("MySQL 数据库服务，网站和很多软件的后台数据都存在它这里。",
                "caution", "依赖它的网站或程序会连不上数据库；未落盘的写入可能丢失。",
                "不会自动恢复，需要手动启动 MySQL 服务。", "数据库"),
    "postgres.exe": K("PostgreSQL 数据库服务。",
                "caution", "依赖它的程序无法读写数据，连接会全部断开。",
                "不会自动恢复，需要手动启动服务。", "数据库"),
    "redis-server.exe": K("Redis 缓存服务，常用来存临时数据和加速网站。",
                "caution", "依赖它的程序取不到缓存、可能报错；内存里尚未保存到磁盘的数据会丢。",
                "不会自动恢复，需要手动启动。", "数据库"),
    "mongod.exe": K("MongoDB 文档数据库服务。",
                "caution", "连接它的程序读写失败，正在进行的写入可能中断。",
                "不会自动恢复，需要手动启动。", "数据库"),
    "nginx.exe": K("Nginx，常用的网站服务器／反向代理，负责把访问转发给后台程序。",
                "caution", "通过它访问的网站或接口会立刻不可用。",
                "不会自动恢复，需要手动重新启动。", "服务"),
    "httpd.exe": K("Apache 网站服务器，负责对外提供网页。",
                "caution", "本机网站立刻无法访问。", "不会自动恢复，需要手动启动。", "服务"),
    "node.exe": K("Node.js 运行环境。通常是某个前端项目、本地开发服务器或后台服务的载体，"
                  "具体做什么要看下面的命令行。",
                "caution", "它支撑的本地网页／接口会立刻打不开；如果这是你自己刚启动的测试服务，可以放心结束。",
                "不会自动重启，重新运行原来的启动命令即可。", "开发工具"),
    "python.exe": K("Python 运行环境。说明有一个用 Python 写的程序正在运行，可能是本地服务、"
                    "脚本或 AI 工具，具体做什么请看下面的命令行。",
                "caution", "这个脚本／服务会立刻停止；如果它正在处理文件或写数据，可能留下未完成的结果。",
                "不会自动重启，需要手动重新运行。", "开发工具"),
    "pythonw.exe": K("Python 的无窗口运行方式，程序在后台跑、不显示黑框。",
                "caution", "对应后台任务会停止，且因为看不到窗口，不容易察觉它已经退出。",
                "不会自动重启。", "开发工具"),
    "java.exe": K("Java 运行环境，某个 Java 程序（常见是后台服务、开发工具）正在跑。",
                "caution", "对应的服务或工具会停止，正在处理的请求会断开。",
                "不会自动重启，需要手动启动。", "开发工具"),
    "dotnet.exe": K(".NET 程序运行环境，某个用 .NET 写的服务或工具在运行。",
                "caution", "对应的服务会停止。", "不会自动重启。", "开发工具"),
    "code.exe": K("VS Code 代码编辑器，也常附带本地开发服务器、语言服务等子进程。",
                "ok", "编辑器窗口会关闭，未保存的代码可能丢失；正在跑的本地预览也会停。",
                "不会自动重启，双击图标即可再打开。", "开发工具"),
    "chrome.exe": K("Google Chrome 浏览器，占用端口多半是在做网页连接或本地调试。",
                "ok", "这个标签页或整个浏览器会关闭，正在填写但未提交的表单内容会丢失。",
                "不会自动重启，手动打开即可。", "浏览器"),
    "msedge.exe": K("Microsoft Edge 浏览器。",
                "ok", "对应标签页／窗口关闭，未提交的网页表单内容会丢失。",
                "不会自动重启。", "浏览器"),
    "firefox.exe": K("Mozilla Firefox 浏览器。",
                "ok", "对应窗口关闭，未提交的内容会丢失。", "不会自动重启。", "浏览器"),
    "onedrive.exe": K("OneDrive 云盘同步客户端，负责把本地文件和云端保持一致。",
                "avoid", "文件停止同步；正在上传的改动可能停在半路，之后再同步可能产生冲突副本。",
                "登录后通常会随系统自启，也可以手动打开。", "云同步"),
    "baidunetdisk.exe": K("百度网盘客户端，负责上传下载和同步。",
                "ok", "正在进行的上传／下载会中断，需要重新开始时可能要续传。",
                "不会自动重启。", "云同步"),
    "wechat.exe": K("微信电脑版。", "ok", "微信退出，未发送完的消息和正在查看的窗口关闭。",
                "不会自动重启，手动打开即可。", "通讯"),
    "weixin.exe": K("微信电脑版。", "ok", "微信退出，未发送完的消息可能丢失。",
                "不会自动重启。", "通讯"),
    "qq.exe": K("QQ 电脑版。", "ok", "QQ 退出，正在传输的文件会中断。", "不会自动重启。", "通讯"),
    "wxwork.exe": K("企业微信客户端。", "ok", "退出登录，消息提醒停止。", "通常有自启设置。", "通讯"),
    "feishu.exe": K("飞书客户端。", "ok", "退出登录，消息与会议提醒停止。", "通常有自启设置。", "通讯"),
    "dingtalk.exe": K("钉钉客户端。", "ok", "退出登录，考勤与消息提醒停止。", "通常有自启设置。", "通讯"),
    "steam.exe": K("Steam 游戏平台。", "ok", "平台退出，正在下载的游戏暂停；正在运行的游戏一般不受影响。",
                "不会自动重启。", "游戏"),
    "spotify.exe": K("Spotify 音乐客户端。", "ok", "音乐播放停止。", "不会自动重启。", "娱乐"),
    "cloudmusic.exe": K("网易云音乐客户端。", "ok", "音乐播放停止，下载任务中断。", "不会自动重启。", "娱乐"),
    "wps.exe": K("WPS Office 办公软件。", "ok", "正在编辑的文档窗口会关闭，未保存的内容可能丢失。",
                "不会自动重启。", "办公"),
    "et.exe": K("WPS 表格。", "ok", "表格窗口关闭，未保存的编辑会丢失。", "不会自动重启。", "办公"),
    "wpp.exe": K("WPS 演示。", "ok", "演示文稿窗口关闭，未保存的编辑会丢失。", "不会自动重启。", "办公"),
    "winword.exe": K("Microsoft Word。", "ok", "文档窗口关闭，未保存的内容可能丢失。",
                "不会自动重启。", "办公"),
    "excel.exe": K("Microsoft Excel。", "ok", "表格窗口关闭，未保存的内容可能丢失。",
                "不会自动重启。", "办公"),
    "dockerd.exe": K("Docker 引擎，负责运行和管理容器。",
                "caution", "所有正在运行的容器会停止，本地起的服务（数据库、网站等）全部不可用。",
                "不会自动重启，需要重新启动 Docker Desktop。", "开发工具"),
    "com.docker.backend.exe": K("Docker Desktop 的后台服务。",
                "caution", "容器和镜像管理功能暂停，正在跑的容器可能断开。",
                "重启 Docker Desktop 后恢复。", "开发工具"),
    "sshd.exe": K("SSH 服务，让别人可以远程登录到这台电脑的命令行。",
                "caution", "已经连上来的远程会话会断开，别人无法再远程连入。",
                "设为服务时通常由服务管理器重启。", "服务"),
    "mstsc.exe": K("远程桌面连接客户端，是你连去别的电脑时用的窗口。",
                "ok", "这个远程桌面窗口关闭，但对端电脑不受影响。", "不会自动重启。", "工具"),
    "conhost.exe": K("控制台窗口的宿主，命令行黑框就是它画出来的。",
                "ok", "对应的命令行窗口会关闭，里面正在跑的命令会中断。", "不会自动重启。", "系统"),
    "cmd.exe": K("Windows 命令行窗口。", "ok", "窗口关闭，里面正在执行的命令会中断。",
                "不会自动重启。", "系统"),
    "powershell.exe": K("Windows PowerShell 命令行窗口。", "ok",
                "窗口关闭，正在执行的脚本会中断。", "不会自动重启。", "系统"),
}

# ---------------------------------------------------------------------------
# 常见端口知识库
# ---------------------------------------------------------------------------
PORT_KB = {
    20: "FTP 文件传输的数据通道", 21: "FTP 文件传输服务（上传下载文件）",
    22: "SSH 远程登录与安全终端", 23: "Telnet 远程登录（老旧协议）",
    25: "SMTP 发送邮件", 53: "DNS 域名解析（把网址翻译成 IP 地址）",
    67: "DHCP 服务端（自动分配 IP 地址）", 68: "DHCP 客户端（获取 IP 地址）",
    80: "HTTP 网页服务", 110: "POP3 收邮件", 123: "NTP 网络时间同步",
    135: "Windows RPC 端点映射（很多系统功能的总入口）",
    137: "NetBIOS 名称服务（网上邻居）", 138: "NetBIOS 数据报（网上邻居）",
    139: "Windows 文件共享（NetBIOS 会话）", 143: "IMAP 收邮件",
    161: "SNMP 网络设备管理", 389: "LDAP 目录服务（域账号登录）",
    443: "HTTPS 加密网页服务", 445: "Windows 文件与打印机共享（SMB）",
    465: "SMTP 加密发信", 514: "Syslog 日志收集", 587: "SMTP 加密发信",
    631: "网络打印服务", 993: "IMAP 加密收邮件", 995: "POP3 加密收邮件",
    1080: "SOCKS 代理", 1433: "SQL Server 数据库", 1521: "Oracle 数据库",
    2049: "NFS 网络文件共享", 2375: "Docker 远程管理接口（未加密）",
    2376: "Docker 远程管理接口（加密）", 3000: "本地开发网页服务（前端项目常见）",
    3306: "MySQL 数据库", 3389: "Windows 远程桌面",
    5000: "本地开发服务（Python / Flask 等常用）", 5173: "Vite 前端开发服务器",
    5432: "PostgreSQL 数据库", 5601: "Kibana 日志面板",
    5672: "RabbitMQ 消息队列", 5900: "VNC 远程桌面",
    6379: "Redis 缓存数据库", 8000: "本地网页服务 / 开发服务器",
    8008: "本地网页服务备用端口", 8080: "本地网页服务 / 开发服务器",
    8081: "本地网页服务备用端口", 8443: "HTTPS 备用端口",
    8888: "本地开发服务（Jupyter 等常用）", 9200: "Elasticsearch 搜索服务",
    11211: "Memcached 缓存", 27017: "MongoDB 数据库",
}
DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017, 5672}
SERVICE_PORTS = {20, 21, 22, 25, 53, 67, 80, 110, 123, 135, 137, 138, 139,
                 389, 443, 445, 631, 3389, 2375, 2376, 5900}


def port_description(port: int) -> str:
    if port in PORT_KB:
        return "%s 端口通常用于「%s」。" % (port, PORT_KB[port])
    if port and port >= 49152:
        return ("%s 属于临时端口，一般是程序临时用来对外通信或供本机其他程序连接的，"
                "不一定是固定服务。" % port)
    if port:
        return "%s 端口没有收录在常见用途表里，通常属于某个具体软件自己约定的通信端口。" % port
    return "这一条没有可识别的端口号。"


# ---------------------------------------------------------------------------
# 读取 exe 自带的说明信息（无需管理员权限）
# ---------------------------------------------------------------------------
@lru_cache(maxsize=512)
def file_info(path: str) -> dict:
    empty = dict(description="", product="", company="", version="")
    if os.name != "nt" or not path or not os.path.isfile(path):
        return empty
    try:
        ver = ctypes.WinDLL("version.dll")
        ver.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p,
                                                ctypes.POINTER(ctypes.c_uint)]
        ver.GetFileVersionInfoSizeW.restype = ctypes.c_uint
        ver.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint,
                                            ctypes.c_uint, ctypes.c_void_p]
        ver.GetFileVersionInfoW.restype = ctypes.c_int
        ver.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_uint)]
        ver.VerQueryValueW.restype = ctypes.c_int

        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return empty
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return empty

        def query(sub: str) -> str:
            ptr = ctypes.c_void_p()
            length = ctypes.c_uint()
            if not ver.VerQueryValueW(buf, sub, ctypes.byref(ptr),
                                      ctypes.byref(length)) or not ptr.value:
                return ""
            return ctypes.wstring_at(ptr.value, length.value).split("\x00")[0].strip()

        trans_ptr = ctypes.c_void_p()
        trans_len = ctypes.c_uint()
        blocks = ["040904B0", "080404B0", "040904E4"]
        if ver.VerQueryValueW(buf, r"\VarFileInfo\Translation",
                              ctypes.byref(trans_ptr), ctypes.byref(trans_len)) \
                and trans_ptr.value and trans_len.value >= 4:
            data = ctypes.string_at(trans_ptr.value, min(trans_len.value, 64))
            lang, codepage = struct.unpack_from("<HH", data, 0)
            blocks.insert(0, "%04X%04X" % (lang, codepage))

        out = dict(empty)
        for block in blocks:
            for key, field in (("description", "FileDescription"),
                               ("product", "ProductName"),
                               ("company", "CompanyName"),
                               ("version", "FileVersion")):
                if not out[key]:
                    out[key] = query(r"\StringFileInfo\%s\%s" % (block, field))
            if out["description"]:
                break
        return out
    except Exception:
        return empty


# ---------------------------------------------------------------------------
# 说明生成
# ---------------------------------------------------------------------------
@dataclass
class Advice:
    level: str
    level_text: str
    tag: str
    group: str
    what: str
    port_what: str
    suggestion: str
    impact: str
    restart: str
    source: str
    reason: str


def _path_hint(exe: str) -> str:
    lower = (exe or "").lower()
    sysroot = os.environ.get("SystemRoot", r"C:\Windows").lower()
    if not lower:
        return "权限不足，读不到这个程序的文件位置。"
    if lower.startswith(sysroot):
        return "它位于 Windows 系统目录，属于系统自带的组件。"
    if "\\appdata\\local\\temp" in lower or "\\temp\\" in lower:
        return "它从临时目录运行，可能是安装器、解压出来的工具，或来路不明的程序，建议多留个心眼。"
    if "\\program files" in lower:
        return "它安装在「Program Files」，是这台电脑上正常安装过的软件。"
    if "\\appdata\\" in lower:
        return "它装在当前用户的目录里，一般是随用户账号启动的软件。"
    return "它是一个运行在本地的程序。"


def _guess_what(entry, name: str, info: dict, kb: dict | None) -> tuple[str, str, str]:
    if kb:
        return kb["what"], kb["group"], "内置知识库"
    bits = []
    label = info.get("description") or info.get("product")
    company = info.get("company") or ""
    if label:
        text = "这个程序自称「%s」" % label
        if company and company.lower() not in label.lower():
            text += "，由 %s 提供" % company
        text += "。"
    else:
        text = "这是一个叫 %s 的程序。" % (entry.pname or "未知进程")
    text += _path_hint(entry.exe)
    text += "它现在正占用一个本机端口对外提供连接。"

    group = "软件"
    lower_path = (entry.exe or "").lower()
    if lower_path.startswith(os.environ.get("SystemRoot", r"C:\Windows").lower()):
        group = "系统组件"
    elif "microsoft" in company.lower():
        group = "微软软件"
    elif any(k in name for k in ("python", "node", "java", "dotnet", "code", "docker")):
        group = "开发工具"
    return text, group, "程序自带说明 + 路径推断"


def evaluate(entry) -> Advice:
    """输入 core.PortEntry，输出可直接展示给普通人的说明与退出建议。"""
    name = (entry.pname or os.path.basename(entry.exe or "") or "").lower()
    kb = PROCESS_KB.get(name)
    info = file_info(entry.exe) if entry.exe else {}
    allowed, reason = core.check_terminable(entry.pid, entry.pname, entry.exe)

    what, group, source = _guess_what(entry, name, info, kb)
    port_what = port_description(entry.port)
    impact = kb["impact"] if kb else ""
    restart = kb["restart"] if kb else ""

    if not allowed:
        if entry.pid and entry.pid == os.getpid():
            level = "self"
        else:
            level = "block"
        if not impact:
            is_system = (entry.exe or "").lower().startswith(
                os.environ.get("SystemRoot", r"C:\Windows").lower())
            if is_system:
                impact = ("这是 Windows 自带组件，结束它可能让相关系统功能失效、界面异常，"
                          "严重时会导致系统重启。")
            else:
                impact = "这个程序提供的功能会立刻停止，正在处理的数据可能丢失。"
            restart = ("系统组件通常由 Windows 自动拉起，但中断期间功能不可用；"
                       "普通程序不会自动恢复，需要手动打开。")
    elif kb:
        level = kb["level"]
    elif (entry.exe or "").lower().startswith(
            os.environ.get("SystemRoot", r"C:\Windows").lower()):
        level = "avoid"
    elif entry.port in DB_PORTS or entry.port in SERVICE_PORTS:
        level = "caution"
    elif name in ("python.exe", "pythonw.exe", "node.exe", "java.exe", "javaw.exe"):
        level = "caution"
    elif "microsoft" in (info.get("company") or "").lower():
        level = "caution"
    else:
        level = "ok"

    if not impact:
        if level == "avoid":
            impact = ("相关系统功能会暂时不可用，可能出现界面闪烁或某个后台能力失效；"
                      "一般不会损坏文件。")
        elif level == "caution":
            impact = ("这台电脑上依赖它的程序会立刻连不上，正在进行的任务会中断；"
                      "如果它正在写数据，可能留下未完成的结果。通常不影响 Windows 本身。")
        else:
            impact = ("这个程序提供的功能会立刻停止，未保存的内容可能丢失；"
                      "一般不会影响 Windows 系统本身。")
    if not restart:
        restart = ("普通程序不会自动恢复，需要手动重新打开；"
                   "如果它是开机自启的软件，下次登录时会再出现。")

    level_text, tag = LEVEL_STYLE[level]
    return Advice(level=level, level_text=level_text, tag=tag, group=group,
                  what=what, port_what=port_what,
                  suggestion=SUGGESTION[level], impact=impact,
                  restart=restart, source=source, reason=reason)


def brief(entry) -> str:
    """给弹窗用的一行摘要。"""
    a = evaluate(entry)
    return "[%s] %s %s" % (a.level_text, a.what, a.suggestion)
