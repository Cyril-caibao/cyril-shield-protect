# -*- coding: utf-8 -*-
"""UPX 命令行封装：内置 upx.exe 定位、版本、压缩 / 解压 / 测试 / 信息。

UPX 可执行文件随程序一起分发（tools/upx.exe），运行时不引用任何外部路径，
也不读取 / 写入任何配置文件。
"""
from __future__ import annotations

import locale
import os
import subprocess
import sys
from dataclasses import dataclass


def _app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def bundled_paths() -> list[str]:
    """随包内嵌的 upx.exe 候选位置（打包后 / 源码运行两种形态）。"""
    bases = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        bases.append(meipass)
    bases.append(_app_dir())
    out = []
    for b in bases:
        out.append(os.path.join(b, "tools", "upx.exe"))
        out.append(os.path.join(b, "upx.exe"))
    return out


def find_upx(explicit: str = "") -> str:
    """返回内置 upx.exe 的绝对路径，找不到返回空字符串。"""
    candidates = []
    if explicit and explicit.strip():
        candidates.append(explicit.strip().strip('"'))
    candidates += bundled_paths()
    for c in candidates:
        if c and os.path.isfile(c) and os.path.basename(c).lower() in ("upx.exe", "upx"):
            return os.path.abspath(c)
    return ""


def run(upx: str, args: list[str], on_line=None, timeout: int = 600):
    """执行 UPX，逐行回调输出，返回 (returncode, 全部输出行)。"""
    if not upx or not os.path.isfile(upx):
        raise FileNotFoundError("内置 UPX 组件缺失，请重新安装本程序")
    if on_line is None:
        on_line = lambda _line: None
    cmd = [upx] + args
    on_line("$ " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    enc = locale.getpreferredencoding(False) or "utf-8"
    creationflags = 0x08000000 if os.name == "nt" else 0  # CREATE_NO_WINDOW
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding=enc, errors="replace", bufsize=1,
        creationflags=creationflags,
    )
    lines: list[str] = []
    try:
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            lines.append(line)
            on_line(line)
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise TimeoutError(f"UPX 执行超时（{timeout} 秒）")
    return proc.returncode, lines


def version(upx: str) -> str:
    rc, lines = run(upx, ["-V"])
    return "\n".join(lines).strip()


@dataclass
class PackOptions:
    level: int = 7                 # 1..9
    best: bool = False
    brute: bool = False
    lzma: bool = False
    force: bool = True
    compress_icons: int = 2        # 0=不压缩图标, 2=默认
    compress_resources: bool = True
    strip_relocs: bool = True
    overlay: str = "copy"
    extra: str = ""

    def args(self) -> list[str]:
        a: list[str] = []
        if self.best:
            a.append("--best")
        elif self.brute:
            a.append("--brute")
        else:
            a.append(f"-{max(1, min(9, int(self.level)))}")
        if self.lzma:
            a.append("--lzma")
        if self.force:
            a.append("-f")
        a.append(f"--compress-icons={self.compress_icons}")
        if not self.compress_resources:
            a.append("--compress-resources=0")
        if not self.strip_relocs:
            a.append("--strip-relocs=0")
        if self.overlay in ("copy", "strip", "skip"):
            a.append(f"--overlay={self.overlay}")
        if self.extra.strip():
            a.extend(self.extra.strip().split())
        a += ["--force-overwrite", "--no-color", "--no-progress"]
        return a


MODES = {
    "pack": "压缩加壳",
    "unpack": "脱壳还原",
    "test": "完整性测试",
    "list": "查看压缩信息",
    "fileinfo": "查看壳参数",
}


def build_command(mode: str, input_path: str, output_path: str,
                  opts: PackOptions | None = None) -> list[str]:
    opts = opts or PackOptions()
    common = ["--no-color", "--no-progress"]
    if mode == "pack":
        args = opts.args() + [f"-o{output_path}", input_path]
    elif mode == "unpack":
        args = ["-d", "--force-overwrite"] + common + [f"-o{output_path}", input_path]
    elif mode == "test":
        args = ["-t"] + common + [input_path]
    elif mode == "list":
        args = ["-l"] + common + [input_path]
    elif mode == "fileinfo":
        args = ["--fileinfo"] + common + [input_path]
    else:
        raise ValueError(f"未知模式: {mode}")
    return args


def execute(mode: str, upx: str, input_path: str, output_path: str = "",
            opts: PackOptions | None = None, on_line=None, timeout: int = 600):
    """执行一次 UPX 操作，返回 (returncode, lines, 输出文件)。"""
    if not input_path or not os.path.isfile(input_path):
        raise FileNotFoundError("请选择有效的输入文件")
    args = build_command(mode, input_path, output_path, opts)
    rc, lines = run(upx, args, on_line=on_line, timeout=timeout)
    result_file = output_path if mode in ("pack", "unpack") else ""
    return rc, lines, result_file
