# -*- coding: utf-8 -*-
"""构建便携版：把精简 JRE + Android 构建工具 + android.jar 一起打进程序。

便携版不需要目标机器安装 Java 或 Android SDK，拷贝单个 EXE 即可完成 APK 加固。

用法：
    python build_portable.py              # 单文件 EXE（默认）
    python build_portable.py --onedir     # 目录版，启动更快（整目录拷贝即可用）
    python build_portable.py --both       # 两种都出
    python build_portable.py --refresh    # 重新从本机 JDK / SDK 生成 toolchain/

toolchain/ 由本机 JDK（jlink）和 Android SDK 裁剪而来，约 104 MB：
    toolchain/jre/bin/{java,javac,keytool}.exe     jlink 精简运行时
    toolchain/android/build-tools/{d8,apksigner,zipalign}
    toolchain/android/platforms/android-XX/android.jar
"""
from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# jdk.compiler 提供 javac；jdk.zipfs 让 javac/apksigner 能读 jar；
# java.logging、java.xml 是 d8 / apksigner 的间接依赖
JMODULES = ["java.base", "jdk.compiler", "jdk.zipfs", "java.logging", "java.xml"]

# 只带加固真正用到的四个可执行体，build-tools 其余 400 MB 全部不要
BT_FILES = ["d8.bat", "apksigner.bat", "zipalign.exe"]
BT_LIBS = ["d8.jar", "apksigner.jar"]


# --------------------------------------------------------------- 解释器
def _capable(interp: str) -> bool:
    try:
        r = subprocess.run([interp, "-c", "import PyInstaller, PIL"],
                           capture_output=True, timeout=90)
        return r.returncode == 0
    except Exception:
        return False


def ensure_interpreter(argv) -> None:
    """打包需要 PyInstaller 与 Pillow；当前解释器不满足时自动换一个。"""
    try:
        import PIL  # noqa: F401
        import PyInstaller  # noqa: F401
        return
    except Exception:
        pass
    local = os.environ.get("LOCALAPPDATA", "")
    prog = os.environ.get("ProgramFiles", r"C:\Program Files")
    cands = []
    for pat in (os.path.join(local, "Programs", "Python", "Python3*", "python.exe"),
                os.path.join(prog, "Python3*", "python.exe"),
                os.path.join(local, "Programs", "Python", "Python3*", "python.exe")):
        cands += sorted(glob.glob(pat), reverse=True)
    for name in ("python", "python3"):
        found = shutil.which(name)
        if found:
            cands.append(found)
    for c in cands:
        if os.path.normcase(os.path.abspath(c)) == os.path.normcase(sys.executable):
            continue
        if os.path.isfile(c) and _capable(c):
            print(f"当前解释器缺少 PyInstaller/Pillow，改用：{c}")
            sys.exit(subprocess.call([c, os.path.abspath(__file__)] + list(argv)))
    print("警告：没找到同时装了 PyInstaller 与 Pillow 的解释器，继续可能有功能缺失")


# --------------------------------------------------------------- 本机工具链来源
def find_jdk() -> str:
    """找一个带 jlink 和 javac 的 JDK（jlink 需要完整 JDK，JRE 不行）。"""
    cands = []
    for env in ("JAVA_HOME", "JDK_HOME"):
        v = os.environ.get(env, "")
        if v:
            cands.append(v)
    javac = shutil.which("javac")
    if javac:
        cands.append(os.path.dirname(os.path.dirname(javac)))
    local = os.environ.get("LOCALAPPDATA", "")
    prog = os.environ.get("ProgramFiles", r"C:\Program Files")
    prog86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    for pat in (os.path.join(prog, "Eclipse Adoptium", "jdk-*"),
                os.path.join(prog, "Java", "jdk-*"),
                os.path.join(prog, "Microsoft", "jdk-*"),
                os.path.join(prog, "Amazon Corretto", "jdk*"),
                os.path.join(prog86, "Eclipse Adoptium", "jdk-*"),
                os.path.join(local, "Programs", "Eclipse Adoptium", "jdk-*")):
        cands += glob.glob(pat)
    for c in cands:
        if not c:
            continue
        if (os.path.isfile(os.path.join(c, "bin", "jlink.exe"))
                and os.path.isfile(os.path.join(c, "bin", "javac.exe"))):
            return os.path.normpath(c)
    return ""


def find_sdk() -> tuple[str, str]:
    """返回 (build-tools 目录, android.jar 路径)。"""
    from cyrilshield import apk
    for root in apk._sdk_roots():
        bt_dir = os.path.join(root, "build-tools")
        bt = ""
        if os.path.isdir(bt_dir):
            vers = sorted((d for d in os.listdir(bt_dir)
                           if os.path.isdir(os.path.join(bt_dir, d))), key=apk._vkey)
            for v in reversed(vers):
                base = os.path.join(bt_dir, v)
                if all(os.path.isfile(os.path.join(base, f)) for f in BT_FILES) and \
                        all(os.path.isfile(os.path.join(base, "lib", f)) for f in BT_LIBS):
                    bt = base
                    break
        jar = ""
        pdir = os.path.join(root, "platforms")
        if os.path.isdir(pdir):
            plats = [d for d in os.listdir(pdir)
                     if os.path.isfile(os.path.join(pdir, d, "android.jar"))]
            for p in sorted(plats, key=apk._vkey, reverse=True):
                jar = os.path.join(pdir, p, "android.jar")
                break
        if bt and jar:
            return bt, jar
    return "", ""


# --------------------------------------------------------------- 生成 toolchain
def make_toolchain(force: bool = False) -> str:
    root = os.path.join(ROOT, "toolchain")
    stamp = os.path.join(root, ".stamp")
    if not force and os.path.isfile(stamp):
        try:
            with open(stamp, "r", encoding="utf-8") as fh:
                info = json.load(fh)
            ok = (os.path.isfile(os.path.join(root, "jre", "bin", "javac.exe"))
                  and os.path.isfile(info.get("android_jar", "")))
            if ok:
                print(f"复用已有 toolchain（{info.get('version', '')}），"
                      f"重新生成请加 --refresh")
                return root
        except Exception:
            pass

    jdk = find_jdk()
    if not jdk:
        raise SystemExit("找不到可用的 JDK（需要 bin/jlink.exe 与 bin/javac.exe）。"
                         "请安装 JDK 11 或更高版本后重试。")
    bt, jar = find_sdk()
    if not bt:
        raise SystemExit("找不到 Android SDK build-tools（需要 d8 / apksigner / zipalign）。"
                         "请安装 Android SDK 后重试。")

    print(f"JDK：{jdk}")
    print(f"build-tools：{bt}")
    print(f"android.jar：{jar}")

    if os.path.isdir(root):
        shutil.rmtree(root)
    jre = os.path.join(root, "jre")
    print("生成精简运行时 ...")
    rc = subprocess.call([os.path.join(jdk, "bin", "jlink.exe"),
                          "--add-modules", ",".join(JMODULES),
                          "--strip-debug", "--no-man-pages", "--no-header-files",
                          "--compress=2", "--output", jre])
    if rc != 0 or not os.path.isfile(os.path.join(jre, "bin", "javac.exe")):
        raise SystemExit("jlink 生成精简运行时失败")

    abt = os.path.join(root, "android", "build-tools")
    os.makedirs(os.path.join(abt, "lib"), exist_ok=True)
    for f in BT_FILES:
        shutil.copy2(os.path.join(bt, f), os.path.join(abt, f))
    for f in BT_LIBS:
        shutil.copy2(os.path.join(bt, "lib", f), os.path.join(abt, "lib", f))
    plat = os.path.basename(os.path.dirname(jar))
    dst_jar = os.path.join(root, "android", "platforms", plat, "android.jar")
    os.makedirs(os.path.dirname(dst_jar), exist_ok=True)
    shutil.copy2(jar, dst_jar)

    info = {"jdk": jdk, "build_tools": bt, "android_jar": dst_jar,
            "platform": plat, "version": plat, "built": time.strftime("%Y-%m-%d %H:%M")}
    with open(stamp, "w", encoding="utf-8") as fh:
        json.dump(info, fh, ensure_ascii=False, indent=2)
    print(f"toolchain 就绪：{root}")
    return root


# --------------------------------------------------------------- 打包
def build(onefile: bool) -> str:
    name = "CyrilShield-Portable"
    dist = os.path.join(ROOT, "dist_portable")
    # 一律传绝对路径：--specpath 会把相对路径解析到 spec 所在目录下
    def p(*parts) -> str:
        return os.path.join(ROOT, *parts)

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
           "--onefile" if onefile else "--onedir",
           "--windowed", "--noupx", "--log-level=ERROR",
           "--name", name,
           "--icon", p("assets", "app.ico"),
           "--add-binary", p("tools", "upx.exe") + ";tools",
           "--add-data", p("cyrilshield", "web") + ";cyrilshield/web",
           "--add-data", p("assets", "app.ico") + ";assets",
           "--add-data", p("toolchain") + ";toolchain",
           "--hidden-import=PIL.Image", "--hidden-import=PIL.ImageTk",
           "--distpath", dist,
           "--workpath", p(".build_portable"),
           "--specpath", p(".build_portable"),
           p("main.py")]
    print("开始打包（onedir 时是目录，onefile 时是单文件）...")
    t0 = time.time()
    rc = subprocess.call(cmd, cwd=ROOT)
    if rc != 0:
        raise SystemExit("PyInstaller 打包失败")
    exe = os.path.join(dist, name + (".exe" if onefile else ""))
    size = os.path.getsize(exe) if os.path.isfile(exe) else 0
    print(f"完成：{exe} — {size / 1048576:.1f} MB，用时 {time.time() - t0:.0f}s")
    return exe


def main() -> int:
    argv = sys.argv[1:]
    ensure_interpreter(argv)
    force = "--refresh" in argv
    both = "--both" in argv
    onedir = "--onedir" in argv

    make_toolchain(force=force)
    if both:
        build(onefile=False)
        build(onefile=True)
    else:
        build(onefile=not onedir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
