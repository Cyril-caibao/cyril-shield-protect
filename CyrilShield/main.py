# -*- coding: utf-8 -*-
"""CyrilShield 启动入口（本地 Web 界面）。

用法：CyrilShield.exe [--port=8765] [--no-browser]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    port = 0
    open_browser = True
    for a in sys.argv[1:]:
        if a == "--no-browser":
            open_browser = False
        elif a.startswith("--port="):
            try:
                port = int(a.split("=", 1)[1])
            except ValueError:
                port = 0
    try:
        from cyrilshield.server import serve
        serve(port=port, open_browser=open_browser)
    except Exception as exc:  # 窗口模式下至少让用户看到错误
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, f"启动失败：{exc}", "CyrilShield", 0x10)
        except Exception:
            print("启动失败:", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
