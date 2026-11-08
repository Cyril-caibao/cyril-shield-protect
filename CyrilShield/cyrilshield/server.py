# -*- coding: utf-8 -*-
"""本地 Web 服务：把图标提取 / UPX 加壳 / VM 虚拟壳暴露为 JSON 接口。

设计要点：
  * 只监听 127.0.0.1，随机端口 + 随机访问令牌，避免其他进程/网页调用；
  * 上传的文件落在本地工作目录，任务在后台线程执行，前端轮询日志；
  * 所有可下载 / 可打开的文件路径都限制在本次会话写入过的目录内。
"""
from __future__ import annotations

import json
import mimetypes
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import apk, pe, upx, vmgen

TOKEN = secrets.token_urlsafe(18)
JOBS: dict[str, "Job"] = {}
FILES: dict[str, dict] = {}
PECACHE: dict[str, pe.PEFile] = {}
ALLOWED: set[str] = set()
LAST_SEEN = [0.0]
IDLE_LIMIT = 300.0


# --------------------------------------------------------------------------
# 路径
# --------------------------------------------------------------------------
def data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    d = os.path.join(base, "CyrilShield")
    os.makedirs(d, exist_ok=True)
    return d


def web_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.join(getattr(sys, "_MEIPASS", ""), "cyrilshield", "web")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


def default_outdir() -> str:
    for cand in (os.path.join(os.path.expanduser("~"), "Desktop"),
                 os.path.join(os.path.expanduser("~"), "Downloads")):
        if os.path.isdir(cand):
            # 带 -Output 后缀：源码仓库通常也叫 CyrilShield，同名会把产物写进仓库里
            return os.path.join(cand, "CyrilShield-Output")
    return os.path.join(data_dir(), "output")


def allow(path: str) -> str:
    p = os.path.abspath(path)
    ALLOWED.add(p)
    return p


def is_allowed(path: str) -> bool:
    p = os.path.abspath(path)
    for root in ALLOWED:
        if p == root or p.startswith(root + os.sep):
            return True
    return False


# --------------------------------------------------------------------------
# 任务
# --------------------------------------------------------------------------
class Job:
    def __init__(self, kind: str):
        self.id = secrets.token_hex(6)
        self.kind = kind
        self.state = "running"
        self.logs: list[list[str]] = []
        self.result = None
        self.error = ""
        self.created = time.time()
        self.lock = threading.Lock()

    def log(self, msg: str, tag: str = "INFO") -> None:
        with self.lock:
            self.logs.append([tag, str(msg)])

    def snapshot(self, since: int = 0) -> dict:
        with self.lock:
            chunk = self.logs[since:]
            total = len(self.logs)
        return {
            "id": self.id, "kind": self.kind, "state": self.state,
            "logs": chunk, "next": total,
            "progress": total, "result": self.result, "error": self.error,
        }


def start_job(kind: str, fn, *args) -> Job:
    job = Job(kind)
    JOBS[job.id] = job

    def runner():
        try:
            job.result = fn(job, *args)
            job.state = "done"
        except Exception as exc:  # noqa: BLE001
            job.error = f"{type(exc).__name__}: {exc}"
            job.log(job.error, "ERR")
            job.state = "error"

    threading.Thread(target=runner, daemon=True).start()
    return job


def gc_jobs() -> None:
    now = time.time()
    for k, j in list(JOBS.items()):
        if j.state != "running" and now - j.created > 1800:
            JOBS.pop(k, None)


# --------------------------------------------------------------------------
# 任务实现
# --------------------------------------------------------------------------
def _stem(name: str) -> str:
    return os.path.splitext(os.path.basename(name))[0] or "output"


def job_icons(job: Job, fid: str, outdir: str, want_ico: bool, want_png: bool) -> dict:
    info = FILES[fid]
    pf = PECACHE.get(fid) or pe.load(info["path"])
    PECACHE[fid] = pf
    root = os.path.abspath(outdir or default_outdir())
    target = os.path.join(root, "icons_" + _stem(info["name"]))
    os.makedirs(target, exist_ok=True)
    allow(root)
    allow(target)
    job.log(f"导出目录：{target}")
    old_path = pf.path
    pf.path = info["name"]          # 让导出文件名使用原始文件名，而不是带上传前缀的路径
    try:
        files = pe.export_icons(pf, target, want_ico, want_png,
                                log=lambda s: job.log(s, "DIM"))
    finally:
        pf.path = old_path
    if not files:
        raise RuntimeError("没有导出任何文件")
    allow(target)
    listing = []
    for p in files:
        try:
            listing.append({"name": os.path.basename(p), "path": p,
                            "size": os.path.getsize(p)})
        except OSError:
            pass
    job.log(f"完成，共 {len(listing)} 个文件")
    return {"dir": target, "files": listing}


def job_upx(job: Job, fid: str, mode: str, opts: dict, outdir: str, outname: str) -> dict:
    info = FILES[fid]
    src = info["path"]
    tool = upx.find_upx()
    if not tool:
        raise RuntimeError("内置 UPX 组件缺失")
    job.log(f"UPX：{tool}")
    root = os.path.abspath(outdir or default_outdir())
    os.makedirs(root, exist_ok=True)
    allow(root)
    before = os.path.getsize(src)
    suffix = {"pack": "_upx", "unpack": "_unpacked"}.get(mode, "")
    out = ""
    if mode in ("pack", "unpack"):
        name = (outname.strip() or (_stem(info["name"]) + suffix + ".exe"))
        if not name.lower().endswith(".exe"):
            name += ".exe"
        out = os.path.join(root, name)
    po = upx.PackOptions(
        level=int(opts.get("level", 7)),
        best=bool(opts.get("best")),
        brute=bool(opts.get("brute")),
        lzma=bool(opts.get("lzma")),
        force=bool(opts.get("force", True)),
        compress_icons=int(opts.get("icons", 2)),
        compress_resources=not opts.get("noRes"),
        strip_relocs=not opts.get("keepReloc"),
        extra=str(opts.get("extra", "")),
    )
    rc, lines, of = upx.execute(mode, tool, src, out, po,
                                on_line=lambda s: job.log(s, "DIM"))
    result = {"mode": mode, "size_before": before, "lines": lines[-8:], "ok": rc == 0}
    if mode in ("pack", "unpack"):
        if rc != 0:
            raise RuntimeError(f"UPX 返回退出码 {rc}")
    elif rc != 0:
        job.log("提示：" + " ".join(x.strip() for x in lines[-2:] if x.strip()), "WARN")
    if of and os.path.isfile(of):
        after = os.path.getsize(of)
        result.update({"path": of, "name": os.path.basename(of), "size_after": after,
                       "ratio": round((1 - after / before) * 100, 1) if before else 0})
        allow(of)
        allow(os.path.dirname(of))
        job.log(f"输出：{of}  ({before:,} → {after:,} 字节)", "OK")
    return result


def job_vm(job: Job, fid: str, opts: dict, outdir: str, outname: str) -> dict:
    info = FILES[fid]
    src = info["path"]
    root = os.path.abspath(outdir or default_outdir())
    os.makedirs(root, exist_ok=True)
    allow(root)
    name = outname.strip() or (_stem(info["name"]) + "_vm.exe")
    if not name.lower().endswith(".exe"):
        name += ".exe"
    out = os.path.join(root, name)
    vo = vmgen.VMOptions(
        password=str(opts.get("password", "")),
        junk_level=int(opts.get("junk", 1)),
        verify=bool(opts.get("verify", True)),
        cleanup=bool(opts.get("cleanup", True)),
        forward_args=bool(opts.get("forwardArgs", True)),
        extra_args=str(opts.get("extraArgs", "")),
        keep_icon=bool(opts.get("keepIcon", True)),
    )
    r = vmgen.build(src, out, vo, on_line=lambda s: job.log(s, "DIM"))
    allow(out)
    return {"path": r.output, "name": os.path.basename(r.output),
            "size_before": r.original_size, "size_after": r.output_size,
            "program_size": r.program_size, "fingerprint": r.fingerprint,
            "key": r.key}


def job_apk_info(job: Job, fid: str) -> dict:
    info = FILES[fid]
    tools = apk.find_tools()
    job.log(f"解析 {info['name']}", "DIM")
    if not tools["ok"]:
        job.log("Android 工具链不完整，缺少：" + "、".join(tools["missing"]), "WARN")
    data = apk.inspect(info["path"], tools)
    data["tools"] = {
        "ok": tools["ok"], "missing": tools["missing"],
        "build_tools": os.path.basename(tools["build_tools"] or ""),
        "platform": tools["platform"] or "",
        "java": os.path.basename(tools["javac"] or ""),
    }
    job.log(f"包名 {data['package'] or '未知'} · {len(data['dexes'])} 个 dex · "
            f"{data['entry']['count']} 个条目", "OK")
    if data["packers"]:
        job.log("检测到既有加固特征：" + "、".join(data["packers"]), "WARN")
    return data


def job_apk_protect(job: Job, fid: str, opts: dict, outdir: str, outname: str) -> dict:
    info = FILES[fid]
    src = info["path"]
    root = os.path.abspath(outdir or default_outdir())
    os.makedirs(root, exist_ok=True)
    allow(root)
    name = outname.strip() or (_stem(info["name"]) + "_protected.apk")
    if not name.lower().endswith(".apk"):
        name += ".apk"
    out = os.path.join(root, name)
    ao = apk.ApkOptions(
        level=str(opts.get("level", "standard")),
        strip_debug=bool(opts.get("stripDebug", True)),
        harden_backup=bool(opts.get("hardenBackup", True)),
        keystore=str(opts.get("keystore", "")),
        ks_alias=str(opts.get("ksAlias", "")),
        ks_pass=str(opts.get("ksPass", "")),
        key_pass=str(opts.get("keyPass", "")),
        v1=bool(opts.get("v1", False)),
        extra={"debug": bool(opts.get("debug", False))},
    )
    r = apk.protect(src, out, ao, log=lambda s, t="INFO": job.log(s, t))
    allow(out)
    return dict(r)


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "CyrilShield"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静默
        pass

    # -- 工具 --------------------------------------------------------------
    def _send(self, body: bytes, ctype: str, code: int = 200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8", code)

    def _err(self, msg: str, code: int = 400):
        self._json({"error": str(msg)}, code)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def _json_body(self) -> dict:
        raw = self._body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def _auth(self, q: dict) -> bool:
        tok = self.headers.get("X-Token") or (q.get("t", [""])[0] if q else "")
        if tok == TOKEN:
            LAST_SEEN[0] = time.time()
            return True
        self._err("未授权", 403)
        return False

    # -- GET ---------------------------------------------------------------
    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            p = os.path.join(web_dir(), "index.html")
            try:
                with open(p, "r", encoding="utf-8") as f:
                    html = f.read()
            except OSError:
                return self._send(b"UI not found", "text/plain; charset=utf-8", 500)
            html = html.replace("__TOKEN__", TOKEN)
            return self._send(html.encode("utf-8"), "text/html; charset=utf-8")

        if path.startswith("/s/"):
            name = os.path.basename(path[3:])
            p = os.path.join(web_dir(), name)
            if not os.path.isfile(p):
                return self._send(b"not found", "text/plain", 404)
            ctype = mimetypes.guess_type(p)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            with open(p, "rb") as f:
                return self._send(f.read(), ctype)

        if path == "/api/env":
            if not self._auth(q):
                return
            tool = upx.find_upx()
            ver = ""
            if tool:
                try:
                    ver = upx.version(tool).splitlines()[0].strip()
                except Exception as exc:
                    ver = f"读取失败：{exc}"
            ok, info = vmgen.check_backend()
            atools = apk.find_tools()
            return self._json({
                "upx": {"path": tool, "version": ver, "found": bool(tool)},
                "backend": {"ok": ok, "info": info},
                "android": {
                    "ok": atools["ok"], "missing": atools["missing"],
                    # 内置工具链的 build-tools 目录不带版本号，用 platform 版本代替，
                    # 否则侧栏会显示成「Android build-tools」，看不出是哪个版本。
                    "build_tools": (atools["platform"].replace("android-", "")
                                    if atools.get("bundled")
                                    else os.path.basename(atools["build_tools"] or "")),
                    "platform": atools["platform"] or "",
                    "bundled": bool(atools.get("bundled")),
                },
                "python": sys.version.split()[0],
                "outdir": default_outdir(),
                "frozen": bool(getattr(sys, "frozen", False)),
            })

        if path == "/api/icon":
            if not self._auth(q):
                return
            fid = q.get("fid", [""])[0]
            gi = int(q.get("g", ["0"])[0])
            ei = int(q.get("i", ["0"])[0])
            pf = PECACHE.get(fid)
            if not pf and fid in FILES:
                pf = pe.load(FILES[fid]["path"])
                PECACHE[fid] = pf
            if not pf:
                return self._err("文件未解析", 404)
            try:
                groups = pf.extract_icon_groups()
                e = groups[gi].entries[ei]
                data = pe.entry_to_png_bytes(e)
            except Exception as exc:
                return self._err(f"预览失败：{exc}", 500)
            return self._send(data, "image/png")

        if path == "/api/ico":
            if not self._auth(q):
                return
            fid = q.get("fid", [""])[0]
            gi = int(q.get("g", ["0"])[0])
            pf = PECACHE.get(fid)
            if not pf and fid in FILES:
                pf = pe.load(FILES[fid]["path"])
                PECACHE[fid] = pf
            if not pf:
                return self._err("文件未解析", 404)
            groups = pf.extract_icon_groups()
            data = groups[gi].to_ico()
            name = urllib.parse.quote(f"{_stem(FILES[fid]['name'])}_{gi}.ico")
            return self._send(data, "image/x-icon",
                              extra={"Content-Disposition": f"attachment; filename*=UTF-8''{name}"})

        if path == "/api/job":
            if not self._auth(q):
                return
            gc_jobs()
            job = JOBS.get(q.get("id", [""])[0])
            if not job:
                return self._err("任务不存在", 404)
            since = int(q.get("since", ["0"])[0])
            return self._json(job.snapshot(since))

        if path == "/api/file":
            if not self._auth(q):
                return
            p = q.get("path", [""])[0]
            if not p or not os.path.isfile(p) or not is_allowed(p):
                return self._err("文件不可访问", 403)
            name = urllib.parse.quote(os.path.basename(p))
            with open(p, "rb") as f:
                data = f.read()
            return self._send(data, "application/octet-stream",
                              extra={"Content-Disposition": f"attachment; filename*=UTF-8''{name}"})

        return self._send(b"not found", "text/plain", 404)

    # -- POST --------------------------------------------------------------
    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = urllib.parse.parse_qs(parsed.query)

        if path == "/api/ping":
            LAST_SEEN[0] = time.time()
            return self._json({"ok": True})

        if not self._auth(q):
            return

        if path == "/api/upload":
            raw_name = self.headers.get("X-Filename", "")
            name = urllib.parse.unquote(raw_name) or "input.exe"
            name = os.path.basename(name).replace("\x00", "") or "input.exe"
            data = self._body()
            if not data:
                return self._err("空文件")
            fid = secrets.token_hex(8)
            folder = os.path.join(data_dir(), "inbox")
            os.makedirs(folder, exist_ok=True)
            allow(folder)
            dest = os.path.join(folder, f"{fid}_{name}")
            with open(dest, "wb") as f:
                f.write(data)
            FILES[fid] = {"path": dest, "name": name, "size": len(data)}
            return self._json({"fid": fid, "name": name, "size": len(data)})

        if path == "/api/probe":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            try:
                pf = pe.load(FILES[fid]["path"])
            except Exception as exc:
                return self._err(f"PE 解析失败：{exc}", 400)
            PECACHE[fid] = pf
            s = pf.summary()
            s["path"] = FILES[fid]["name"]      # 展示原始文件名，而不是带上传前缀的临时路径
            groups = []
            try:
                gs = pf.extract_icon_groups()
            except Exception:
                gs = []
            for gi, g in enumerate(gs):
                groups.append({
                    "index": gi, "name": g.name, "count": len(g.entries),
                    "entries": [{"size": e.size_label, "bits": e.bit_count,
                                 "kind": e.kind, "bytes": len(e.data)}
                                for e in g.entries],
                })
            return self._json({"fid": fid, "summary": s, "groups": groups,
                               "outdir": default_outdir()})

        if path == "/api/icons":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            job = start_job("icons", job_icons, fid,
                            str(body.get("outdir", "")),
                            bool(body.get("ico", True)),
                            bool(body.get("png", True)))
            return self._json({"job": job.id})

        if path == "/api/upx":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            job = start_job("upx", job_upx, fid, str(body.get("mode", "pack")),
                            body.get("opts", {}) or {},
                            str(body.get("outdir", "")), str(body.get("outname", "")))
            return self._json({"job": job.id})

        if path == "/api/vm":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            job = start_job("vm", job_vm, fid, body.get("opts", {}) or {},
                            str(body.get("outdir", "")), str(body.get("outname", "")))
            return self._json({"job": job.id})

        if path == "/api/apk/inspect":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            job = start_job("apk", job_apk_info, fid)
            return self._json({"job": job.id})

        if path == "/api/apk/protect":
            body = self._json_body()
            fid = body.get("fid", "")
            if fid not in FILES:
                return self._err("文件不存在", 404)
            job = start_job("apk", job_apk_protect, fid, body.get("opts", {}) or {},
                            str(body.get("outdir", "")), str(body.get("outname", "")))
            return self._json({"job": job.id})

        if path == "/api/open":
            body = self._json_body()
            target = str(body.get("path", ""))
            if not target or not is_allowed(target):
                return self._err("路径不可访问", 403)
            try:
                if os.path.isdir(target):
                    subprocess.Popen(["explorer", os.path.normpath(target)])
                elif os.path.isfile(target):
                    subprocess.Popen(["explorer", "/select,", os.path.normpath(target)])
                else:
                    return self._err("路径不存在", 404)
            except Exception as exc:
                return self._err(str(exc), 500)
            return self._json({"ok": True})

        if path == "/api/quit":
            def bye():
                time.sleep(0.3)
                os._exit(0)
            threading.Thread(target=bye, daemon=True).start()
            return self._json({"ok": True})

        return self._err("未知接口", 404)


def _watchdog() -> None:
    while True:
        time.sleep(15)
        last = LAST_SEEN[0]
        if last and time.time() - last > IDLE_LIMIT:
            running = any(j.state == "running" for j in JOBS.values())
            if not running:
                os._exit(0)


def _logical_screen() -> tuple[int, int]:
    """逻辑屏幕尺寸（与浏览器 --window-size 的单位一致）。"""
    try:
        import ctypes
        u = ctypes.windll.user32
        # 本进程不做 DPI 感知，取到的就是缩放后的逻辑尺寸
        w, h = u.GetSystemMetrics(0), u.GetSystemMetrics(1)
        if w > 200 and h > 200:
            return w, h
    except Exception:
        pass
    return 1366, 768


def _open_browser(url: str) -> None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    sw, sh = _logical_screen()
    w = max(900, min(1320, sw - 70))
    h = max(620, min(900, sh - 110))
    for c in candidates:
        if os.path.isfile(c):
            try:
                subprocess.Popen([c, f"--app={url}", f"--window-size={w},{h}",
                                  "--disable-features=Translate",
                                  "--no-first-run", "--no-default-browser-check"])
                return
            except Exception:
                continue
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


def serve(port: int = 0, open_browser: bool = True, quiet: bool = False) -> None:
    mimetypes.add_type("application/javascript", ".js")
    mimetypes.add_type("image/svg+xml", ".svg")
    os.makedirs(default_outdir(), exist_ok=True)
    allow(data_dir())
    allow(default_outdir())

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    print(f"CyrilShield 已启动：{url}")
    print(f"输出目录：{default_outdir()}")
    if open_browser:
        _open_browser(url)
    threading.Thread(target=_watchdog, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    serve()
