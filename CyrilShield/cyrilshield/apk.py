"""APK 加固：dex 抽取加密 + 壳 Application 注入 + 重打包对齐签名。

依赖本机 Android 工具链（JDK / build-tools / platform），启动时自动探测。
设计目标：加固后的 APK 能被系统正常安装启动，业务代码行为不变。

防护构成（全部为对自己应用做保护，不含任何对抗分析环境的手段）：
  * 全部 classes*.dex 抽出，逐文件用 HMAC-SHA256 计数器流加密后塞回 assets
  * 载荷容器不带固定头部，nonce 与校验码附在尾部，密文任意一位被改即拒绝解密
  * 壳 Application 在 attachBaseContext 阶段解密落盘，注入自身 ClassLoader 的
    dexElements，再把真正的 Application 委托起来
  * 整体 SHA-256 校验，载荷被改动即拒绝加载
  * 类名 / 包名 / 资产路径 / 密钥分片 / 签名别名每次构建随机
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import re
import shutil
import struct
import string
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field

from . import _stream, axml


class ApkError(Exception):
    pass


# ---------------------------------------------------------------- 工具链
def _sdk_roots():
    roots = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(env)
        if v and os.path.isdir(v):
            roots.append(v)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        roots.append(os.path.join(local, "Android", "Sdk"))
    home = os.path.expanduser("~")
    roots += [
        os.path.join(home, "AppData", "Local", "Android", "Sdk"),
        os.path.join(home, "Android", "Sdk"),
        r"C:\Android\Sdk",
        r"C:\Android\android-sdk",
        "/usr/lib/android-sdk",
        os.path.join(home, "Library", "Android", "sdk"),
    ]
    seen, out = set(), []
    for r in roots:
        r = os.path.normpath(os.path.abspath(r))
        if r not in seen and os.path.isdir(r):
            seen.add(r)
            out.append(r)
    return out


def _vkey(name):
    return [int(x) for x in re.findall(r"\d+", name)] or [0]


def bundled_toolchain() -> str:
    """随程序分发的内置工具链根目录，没有则返回空字符串。

    便携版把精简 JRE + build-tools 子集 + android.jar 放在 toolchain/ 下，
    与程序同目录（源码运行时在项目根目录），优先级高于任何系统安装。
    """
    bases = []
    meipass = getattr(sys, "_MEIPASS", "")
    if meipass:
        bases.append(meipass)
    if getattr(sys, "frozen", False):
        bases.append(os.path.dirname(os.path.abspath(sys.executable)))
    else:
        bases.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for b in bases:
        p = os.path.join(b, "toolchain")
        if os.path.isdir(os.path.join(p, "jre", "bin")):
            return p
    return ""


def _tools_from_bundled(root: str) -> dict:
    """按内置工具链的固定布局填充工具信息。"""
    bin_dir = os.path.join(root, "jre", "bin")
    bt = os.path.join(root, "android", "build-tools")
    info = {"ok": False, "missing": [], "sdk": os.path.join(root, "android"),
            "build_tools": bt, "platform": "", "javac": os.path.join(bin_dir, "javac.exe"),
            "java": os.path.join(bin_dir, "java.exe"),
            "keytool": os.path.join(bin_dir, "keytool.exe"),
            "d8": os.path.join(bt, "d8.bat" if os.name == "nt" else "d8"),
            "android_jar": "", "apksigner": os.path.join(bt, "apksigner.bat" if os.name == "nt" else "apksigner"),
            "zipalign": os.path.join(bt, "zipalign.exe" if os.name == "nt" else "zipalign"),
            "aapt2": "", "java_home": os.path.join(root, "jre"), "bundled": True}

    platforms = os.path.join(root, "android", "platforms")
    if os.path.isdir(platforms):
        cands = [d for d in os.listdir(platforms)
                 if os.path.isfile(os.path.join(platforms, d, "android.jar"))]
        for plat in sorted(cands, key=_vkey, reverse=True):
            info["platform"] = plat
            info["android_jar"] = os.path.join(platforms, plat, "android.jar")
            break

    for key, label in (("javac", "JDK（javac）"), ("d8", "Android build-tools（d8）"),
                       ("android_jar", "Android platform（android.jar）"),
                       ("apksigner", "apksigner"), ("zipalign", "zipalign"),
                       ("keytool", "keytool")):
        if not os.path.isfile(info[key]) and not os.path.isdir(info[key]):
            info["missing"].append(label)
    info["ok"] = not info["missing"]
    return info


def find_tools() -> dict:
    """返回工具链信息；``ok`` 表示可以完成完整加固。"""
    root = bundled_toolchain()
    if root:
        info = _tools_from_bundled(root)
        if info["ok"]:
            return info

    info = {"ok": False, "missing": [], "sdk": "", "build_tools": "",
            "platform": "", "javac": "", "java": "", "d8": "", "android_jar": "",
            "apksigner": "", "zipalign": "", "aapt2": "", "java_home": "",
            "keytool": "", "bundled": False}

    java = shutil.which("javac")
    if java:
        info["javac"] = java
        info["java_home"] = os.path.dirname(os.path.dirname(java))
    jre = shutil.which("java")
    if jre:
        info["java"] = jre
    kt = shutil.which("keytool")
    if kt:
        info["keytool"] = kt

    for root in _sdk_roots():
        bt_dir = os.path.join(root, "build-tools")
        if os.path.isdir(bt_dir):
            versions = sorted((d for d in os.listdir(bt_dir)
                               if os.path.isdir(os.path.join(bt_dir, d))), key=_vkey)
            for ver in reversed(versions):
                base = os.path.join(bt_dir, ver)
                d8 = os.path.join(base, "d8.bat" if os.name == "nt" else "d8")
                apk_signer = os.path.join(base, "apksigner.bat" if os.name == "nt" else "apksigner")
                zip_align = os.path.join(base, "zipalign.exe" if os.name == "nt" else "zipalign")
                if os.path.isfile(d8) and os.path.isfile(apk_signer) and os.path.isfile(zip_align):
                    info.update(sdk=root, build_tools=base, d8=d8,
                                apksigner=apk_signer, zipalign=zip_align)
                    aapt2 = os.path.join(base, "aapt2.exe" if os.name == "nt" else "aapt2")
                    if os.path.isfile(aapt2):
                        info["aapt2"] = aapt2
                    break
        platforms = os.path.join(root, "platforms")
        if os.path.isdir(platforms):
            cands = [d for d in os.listdir(platforms)
                     if os.path.isfile(os.path.join(platforms, d, "android.jar"))]
            for plat in sorted(cands, key=_vkey, reverse=True):
                info["platform"] = plat
                info["android_jar"] = os.path.join(platforms, plat, "android.jar")
                break
        if info["build_tools"] and info["android_jar"]:
            break

    for key, label in (("javac", "JDK（javac）"), ("d8", "Android build-tools（d8）"),
                       ("android_jar", "Android platform（android.jar）"),
                       ("apksigner", "apksigner"), ("zipalign", "zipalign"),
                       ("keytool", "keytool")):
        if not info[key]:
            info["missing"].append(label)
    info["ok"] = not info["missing"]
    return info


def _no_window():
    if os.name == "nt":
        return subprocess.CREATE_NO_WINDOW
    return 0


def _decode(raw: bytes) -> str:
    """工具链输出解码：优先 UTF-8，退回本地代码页。"""
    if not raw:
        return ""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace")


def _run(cmd, cwd=None, timeout=900, log=None):
    if log:
        log("$ " + " ".join(os.path.basename(str(c)) if i == 0 else str(c)
                            for i, c in enumerate(cmd)))
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                       creationflags=_no_window())
    out = _decode(p.stdout or b"")
    err = _decode(p.stderr or b"")
    if p.returncode != 0 and log:
        tail = (out + err).strip().splitlines()[-8:]
        for line in tail:
            log("  " + line.strip(), "WARN")
    return p.returncode, (out + err).strip()


# ---------------------------------------------------------------- DEX 解析
def dex_header(data: bytes) -> dict:
    if len(data) < 112 or data[:4] != b"dex\n":
        raise ApkError("不是有效的 dex 文件")
    ver = data[4:7].decode("ascii", "replace").strip("\x00")
    (checksum,) = struct.unpack_from("<I", data, 8)
    file_size, header_size = struct.unpack_from("<II", data, 32)
    string_ids, = struct.unpack_from("<I", data, 56)
    type_ids, = struct.unpack_from("<I", data, 64)
    proto_ids, = struct.unpack_from("<I", data, 72)
    field_ids, = struct.unpack_from("<I", data, 80)
    method_ids, = struct.unpack_from("<I", data, 88)
    class_defs, = struct.unpack_from("<I", data, 96)
    return {"version": ver, "file_size": file_size, "strings": string_ids,
            "types": type_ids, "protos": proto_ids, "fields": field_ids,
            "methods": method_ids, "classes": class_defs,
            "checksum_ok": (zlib.adler32(data[12:]) & 0xFFFFFFFF) == checksum}


# ---------------------------------------------------------------- 签名信息
SIG_FILE_RE = re.compile(r"^META-INF/[^/]+\.(SF|RSA|DSA|EC)$", re.I)


def _signature_info(path, tools, log=None) -> dict:
    out = {"v1": False, "v2": False, "v3": False, "dn": "", "sha256": "",
           "schemes": [], "valid": None}
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception:
        return out
    out["v1"] = any(SIG_FILE_RE.match(n) for n in names)
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 65536 - 32))
            tail = fh.read()
        out["v2"] = b"APK Sig Block 42" in tail
    except Exception:
        pass
    apk = tools.get("apksigner") if tools else None
    if apk and os.path.isfile(apk):
        rc, txt = _run([apk, "verify", "--print-certs", path], timeout=180)
        for line in txt.splitlines():
            low = line.lower()
            if "certificate dn" in low:
                out["dn"] = line.split(":", 1)[1].strip()
            elif "sha-256 digest" in low:
                out["sha256"] = line.split(":", 1)[1].strip()
            elif "verified using v1 scheme" in low:
                out["v1"] = "true" in low
            elif "verified using v2 scheme" in low:
                out["v2"] = "true" in low
            elif "verified using v3 scheme" in low:
                out["v3"] = "true" in low
        out["valid"] = rc == 0
    schemes = [n for n, k in (("v1", "v1"), ("v2", "v2"), ("v3", "v3")) if out[k]]
    out["schemes"] = schemes
    return out


# ---------------------------------------------------------------- 加固特征
PACKER_MARKS = [
    ("360 加固", ("libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so", "com/qihoo/util/")),
    ("腾讯乐固", ("libshell.so", "libshella.so", "com/tencent/StubShell", "0OO00l111l1l")),
    ("梆梆加固", ("libsecexe.so", "libsecmain.so", "libDexHelper.so", "com/secneo/apkwrapper")),
    ("爱加密", ("libexec.so", "libexecmain.so", "com/shell/MyWrapperProxyApplication", "ijiami.dat")),
    ("娜迦加固", ("libchaosvmp.so", "libddog.so", "libfdog.so", "libnagain")),
    ("阿里聚安全", ("libmobisec.so", "aliprotect.dat", "libfakejni.so")),
    ("百度加固", ("libbaiduprotect.so", "com/baidu/protect")),
    ("网易易盾", ("libnesec.so", "libyidun.so", "com/netease/nis")),
    ("通付盾", ("libegis.so", "com/payegis")),
    ("腾讯御安全", ("libtup.so", "com/tencent/wxpay")),
]


def inspect(path: str, tools=None) -> dict:
    """解析 APK 结构、清单、签名与加固特征。"""
    if not os.path.isfile(path):
        raise ApkError("文件不存在")
    size = os.path.getsize(path)
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ApkError("不是有效的 APK（zip 解析失败）")

    with zf:
        names = zf.namelist()
        if "AndroidManifest.xml" not in names:
            raise ApkError("APK 内缺少 AndroidManifest.xml")
        raw_manifest = zf.read("AndroidManifest.xml")
        try:
            doc = axml.Document.parse(raw_manifest)
            info = axml.manifest_info(doc)
        except axml.AxmlError as exc:
            raise ApkError(f"清单解析失败：{exc}")

        dexes = []
        for n in names:
            if re.match(r"^classes\d*\.dex$", n):
                data = zf.read(n)
                try:
                    h = dex_header(data)
                except ApkError:
                    h = {}
                h.update(name=n, size=len(data))
                dexes.append(h)
        dexes.sort(key=lambda d: d["name"])

        abis = {}
        for n in names:
            m = re.match(r"^lib/([^/]+)/(.+)$", n)
            if m:
                abis.setdefault(m.group(1), []).append(m.group(2))

        assets = [n for n in names if n.startswith("assets/") and not n.endswith("/")]
        packers = []
        joined = "\n".join(names)
        for label, marks in PACKER_MARKS:
            if any(m in joined for m in marks):
                packers.append(label)

        total_dex = sum(d.get("size", 0) for d in dexes)
        entry = {"count": len(names), "dex_bytes": total_dex,
                 "asset_count": len(assets), "compressed": size}

    sig = _signature_info(path, tools or find_tools())
    warnings = []
    if info["debuggable"]:
        warnings.append("清单开启了 android:debuggable")
    if info["allow_backup"]:
        warnings.append("允许 adb backup（android:allowBackup=true）")
    if not dexes:
        warnings.append("未发现 classes.dex")
    if info["min_sdk"] and info["min_sdk"] < 21:
        warnings.append(f"minSdkVersion={info['min_sdk']}，低于 21 的机型兼容性风险较高")
    if packers:
        warnings.append("检测到已有加固特征：" + "、".join(packers))

    return {
        "name": os.path.basename(path), "size": size,
        "package": info["package"], "version_name": info["version_name"],
        "version_code": info["version_code"], "min_sdk": info["min_sdk"],
        "target_sdk": info["target_sdk"], "app_class": info["app_class"],
        "label": info["label"], "permissions": info["permissions"],
        "activities": info["activities"], "services": info["services"],
        "receivers": info["receivers"], "providers": info["providers"],
        "debuggable": info["debuggable"], "allow_backup": info["allow_backup"],
        "dexes": dexes, "abis": {k: len(v) for k, v in abis.items()},
        "entry": entry, "signature": sig, "packers": packers,
        "warnings": warnings,
    }


# ---------------------------------------------------------------- 壳源码
STUB_TEMPLATE = r"""package @PKG@;

import android.app.Application;
import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class @CLS@ extends Application {
    private static final String[] PARTS = new String[]{@PARTS@};
    // 密钥材料拆成八组常量，前四组与后四组异或后才成形，单独一组无意义
    private static final int[][] KT = new int[][]{@KT@};
    private static final byte[] SL = new byte[]{@SL@};
    private static final byte[] SP = new byte[]{@SP@};
    private static final byte[] RS = new byte[]{@RS@};
    private static final byte[] RK = new byte[]{@RK@};
    private static final byte[] WS = new byte[]{@WS@};
    private static final byte[] WK = new byte[]{@WK@};
    private static final String DIR = "@DIR@";
    private static final int TAIL = 24;
    private Application inner;
    private boolean ready;

    //DBG private static void dbg(String s) { android.util.Log.i("PSH", s); }

    private static String unxor(byte[] s, byte[] k) {
        if (s.length == 0 || k.length == 0) {
            return "";
        }
        byte[] b = new byte[s.length];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) (s[i] ^ k[i % k.length]);
        }
        return new String(b);
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        try {
            boot(base);
        } catch (Throwable t) {
            ready = false;
            //DBG dbg("boot fail: " + t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        String real = unxor(RS, RK);
        if (!ready || real.length() == 0) {
            return;
        }
        try {
            Application app = build(real);
            if (app == null) {
                return;
            }
            inner = app;
            // 先把框架侧的实例换成真实对象，再执行它自己的 onCreate，
            // 这样 onCreate 里调用 getApplication() 也能拿到正确的对象。
            swap(app);
            app.onCreate();
            //DBG dbg("delegate onCreate done");
        } catch (Throwable t) {
            //DBG dbg("delegate fail: " + t);
        }
    }

    private void boot(Context ctx) throws Throwable {
        byte[] root = key();
        byte[][] plain = new byte[PARTS.length][];
        for (int i = 0; i < PARTS.length; i++) {
            plain[i] = unseal(ctx, PARTS[i], root, i);
            //DBG dbg("part " + i + " -> " + plain[i].length);
            if (plain[i].length == 0) {
                return;
            }
        }
        String want = unxor(WS, WK);
        if (want.length() > 0) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < plain.length; i++) {
                md.update(plain[i]);
            }
            byte[] d = md.digest();
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (int i = 0; i < d.length; i++) {
                int v = d[i] & 0xFF;
                if (v < 16) {
                    sb.append('0');
                }
                sb.append(Integer.toHexString(v));
            }
            if (!sb.toString().equals(want)) {
                //DBG dbg("digest mismatch");
                return;
            }
        }
        ClassLoader extra;
        int sdk = android.os.Build.VERSION.SDK_INT;
        if (sdk >= 29) {
            // API 29+：整包内存加载，明文 dex 不落盘
            java.nio.ByteBuffer[] bufs = new java.nio.ByteBuffer[plain.length];
            for (int i = 0; i < plain.length; i++) {
                bufs[i] = java.nio.ByteBuffer.wrap(plain[i]);
            }
            extra = new dalvik.system.InMemoryDexClassLoader(bufs, getClassLoader());
        } else if (sdk >= 26 && plain.length == 1) {
            extra = new dalvik.system.InMemoryDexClassLoader(
                    java.nio.ByteBuffer.wrap(plain[0]), getClassLoader());
        } else {
            // API 21-25：落盘为只读文件后再加载
            File dir = new File(ctx.getCodeCacheDir(), DIR);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            StringBuilder cp = new StringBuilder();
            for (int i = 0; i < plain.length; i++) {
                File f = new File(dir, DIR + i + ".d");
                if (f.exists()) {
                    f.delete();
                }
                FileOutputStream fo = new FileOutputStream(f);
                fo.write(plain[i]);
                fo.flush();
                fo.close();
                f.setReadOnly();
                if (i > 0) {
                    cp.append(File.pathSeparator);
                }
                cp.append(f.getAbsolutePath());
            }
            extra = new dalvik.system.DexClassLoader(
                    cp.toString(), dir.getAbsolutePath(), null, getClassLoader());
        }
        plain = null;
        inject(extra);
        ready = true;
        //DBG dbg("ready");
    }

    private static byte[] key() throws Throwable {
        byte[] raw = new byte[64];
        int p = 0;
        for (int g = 0; g < 4; g++) {
            for (int i = 0; i < 4; i++) {
                int v = KT[g][i] ^ KT[g + 4][i];
                raw[p++] = (byte) (v >>> 24);
                raw[p++] = (byte) (v >>> 16);
                raw[p++] = (byte) (v >>> 8);
                raw[p++] = (byte) v;
            }
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(SL, "HmacSHA256"));
        byte[] out = mac.doFinal(raw);
        java.util.Arrays.fill(raw, (byte) 0);
        return out;
    }

    private static byte[] sub(byte[] root, int i) throws Throwable {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(root, "HmacSHA256"));
        byte[] a = mac.doFinal(new byte[]{0x11, (byte) (i >>> 8), (byte) i});
        mac.init(new SecretKeySpec(a, "HmacSHA256"));
        byte[] out = mac.doFinal(SP);
        java.util.Arrays.fill(a, (byte) 0);
        return out;
    }

    private static byte[] unseal(Context ctx, String name, byte[] root, int idx) throws Throwable {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        byte[] tmp = new byte[8192];
        int n;
        while ((n = in.read(tmp)) > 0) {
            buf.write(tmp, 0, n);
        }
        in.close();
        byte[] all = buf.toByteArray();
        if (all.length <= TAIL) {
            return new byte[0];
        }
        int len = all.length - TAIL;
        byte[] nonce = new byte[16];
        System.arraycopy(all, len, nonce, 0, 16);
        byte[] k = sub(root, idx);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(k, "HmacSHA256"));
        mac.update((byte) 0x74);
        mac.update(nonce);
        mac.update(all, 0, len);
        byte[] tg = mac.doFinal();
        for (int j = 0; j < 8; j++) {
            if (tg[j] != all[len + 16 + j]) {
                //DBG dbg("part " + idx + " tag mismatch");
                return new byte[0];
            }
        }
        byte[] ctr = new byte[8];
        byte[] out = new byte[len];
        long c = 0;
        int p = 0;
        while (p < len) {
            mac.reset();
            mac.update(nonce);
            for (int j = 7; j >= 0; j--) {
                ctr[j] = (byte) (c >>> ((7 - j) * 8));
            }
            mac.update(ctr);
            byte[] b = mac.doFinal();
            int take = Math.min(32, len - p);
            for (int j = 0; j < take; j++) {
                out[p + j] = (byte) (all[p + j] ^ b[j]);
            }
            p += take;
            c++;
        }
        return out;
    }

    private void inject(ClassLoader extra) throws Throwable {
        ClassLoader cl = getClassLoader();
        //DBG dbg("inject cl=" + cl);
        Field plf = find(cl.getClass(), "pathList");
        if (plf == null) {
            //DBG dbg("no pathList");
            return;
        }
        Object pathList = plf.get(cl);
        if (pathList == null) {
            //DBG dbg("pathList null");
            return;
        }
        Field epf = find(extra.getClass(), "pathList");
        if (epf == null) {
            //DBG dbg("no extra pathList");
            return;
        }
        Object extraList = epf.get(extra);
        if (extraList == null) {
            //DBG dbg("extraList null");
            return;
        }
        Field ef = find(extraList.getClass(), "dexElements");
        Field of = find(pathList.getClass(), "dexElements");
        if (ef == null || of == null) {
            //DBG dbg("no dexElements");
            return;
        }
        Object[] add = (Object[]) ef.get(extraList);
        Object[] old = (Object[]) of.get(pathList);
        if (add == null || add.length == 0 || old == null) {
            //DBG dbg("empty elements");
            return;
        }
        Object[] merged = (Object[]) Array.newInstance(
                old.getClass().getComponentType(), add.length + old.length);
        System.arraycopy(add, 0, merged, 0, add.length);
        System.arraycopy(old, 0, merged, add.length, old.length);
        of.set(pathList, merged);
        //DBG dbg("merged " + merged.length + " elems");
    }

    private Application build(String real) throws Throwable {
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object th = at.getMethod("currentActivityThread").invoke(null);
            Field f = find(at, "mInstrumentation");
            if (f != null) {
                Object instr = f.get(th);
                Class<?> ic = Class.forName("android.app.Instrumentation");
                Method m = ic.getMethod("newApplication", ClassLoader.class,
                        String.class, Context.class);
                Object app = m.invoke(instr, getClassLoader(), real, getBaseContext());
                if (app instanceof Application) {
                    return (Application) app;
                }
            }
        } catch (Throwable t) {
        }
        Class<?> c = Class.forName(real, true, getClassLoader());
        Application app = (Application) c.newInstance();
        try {
            Method a = Application.class.getDeclaredMethod("attach", Context.class);
            a.setAccessible(true);
            a.invoke(app, getBaseContext());
        } catch (Throwable t) {
        }
        return app;
    }

    private void swap(Application app) {
        try {
            Context bc = getBaseContext();
            Field pf = find(bc.getClass(), "mPackageInfo");
            if (pf != null) {
                Object lp = pf.get(bc);
                if (lp != null) {
                    Field af = find(lp.getClass(), "mApplication");
                    if (af != null) {
                        af.set(lp, app);
                    }
                }
            }
        } catch (Throwable t) {
        }
        try {
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object th = at.getMethod("currentActivityThread").invoke(null);
            Field f = find(at, "mInitialApplication");
            if (f != null) {
                f.set(th, app);
            }
            Field g = find(at, "mAllApplications");
            if (g != null) {
                Object list = g.get(th);
                if (list instanceof java.util.ArrayList) {
                    java.util.ArrayList l = (java.util.ArrayList) list;
                    for (int i = 0; i < l.size(); i++) {
                        if (l.get(i) == this) {
                            l.set(i, app);
                        }
                    }
                }
            }
        } catch (Throwable t) {
        }
    }

    private static Field find(Class<?> c, String name) {
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f;
            } catch (Throwable t) {
                c = c.getSuperclass();
            }
        }
        return null;
    }
}
"""


def _rand_ident(rng, n=10):
    first = rng.choice("abcdefghijklmnopqrstuvwxyz")
    rest = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return first + "".join(rng.choice(rest) for _ in range(n - 1))


def _blit(data: bytes) -> str:
    """把字节序列写成 Java 的 byte[] 字面量（有符号）。"""
    return ", ".join(str(b - 256 if b > 127 else b) for b in data)


def _s32(v: int) -> str:
    """Java 的 int 字面量没有无符号形式，超过 2^31 要写成负数。"""
    return str(v - (1 << 32) if v >= (1 << 31) else v)


def _obf(text: str, rng):
    """把字符串拆成 XOR 掩码数组，避免明文常量出现在壳 dex 的字符串表里。"""
    if not text:
        return "", ""
    raw = text.encode("utf-8")
    key = rng.randbytes(8)
    enc = bytes(c ^ key[i % 8] for i, c in enumerate(raw))
    return _blit(enc), _blit(key)


@dataclass
class ApkOptions:
    level: str = "standard"          # compat | standard | strong
    strip_debug: bool = True
    harden_backup: bool = True
    keystore: str = ""
    ks_alias: str = ""
    ks_pass: str = ""
    key_pass: str = ""
    v1: bool = False
    seed: int = 0
    extra: dict = field(default_factory=dict)


def _default_keystore(log=None, keytool: str = "") -> tuple[str, str, str]:
    """获取（必要时生成）默认签名密钥库，返回 (路径, 别名, 密码)。

    别名随机生成并记录在旁挂文件里：apksigner 用别名给 META-INF 下的 v1 签名块
    命名，固定别名等于在每个产物里写下工具指纹，会被静态特征直接命中。
    """
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, "CyrilShield")
    os.makedirs(d, exist_ok=True)
    ks = os.path.join(d, "android_default.jks")
    meta = os.path.join(d, "android_default.key.json")
    pwd = "cyrilshield2026"
    keytool = keytool or shutil.which("keytool") or ""

    # 旧版本的密钥库在 PEShieldStudio 目录下。它的证书主体是 CN=PEShield Studio，
    # 会原样印在每一个产物的签名里，所以不能直接继承；只留一份副本备查，
    # 需要复用它签名时在界面上手工指定密钥库路径即可。
    old_dir = os.path.join(base, "PEShieldStudio")
    old_ks = os.path.join(old_dir, "android_default.jks")
    legacy = os.path.join(d, "android_legacy.jks")
    if os.path.isfile(old_ks) and not os.path.isfile(legacy):
        try:
            shutil.copy2(old_ks, legacy)
        except Exception:
            pass

    if os.path.isfile(meta):
        try:
            with open(meta, "r", encoding="utf-8") as fh:
                info = json.load(fh)
            alias = str(info["alias"])
            if os.path.isfile(ks):
                return ks, alias, str(info.get("store_pass") or pwd)
        except Exception:
            pass

    # 每次安装只随机一次，之后复用，保证同一台机器上产物可连续升级
    alias = "k" + "".join(random.SystemRandom().choice(string.ascii_lowercase + string.digits)
                          for _ in range(7))

    if os.path.isfile(ks) and os.path.getsize(ks) > 0:
        # 旧版本生成的密钥库：把固定别名换掉，密钥本身不变，已发布应用的升级链不受影响
        done = False
        if keytool:
            rc, _ = _run([keytool, "-changealias", "-keystore", ks, "-alias", "cyrilshield",
                          "-destalias", alias, "-storepass", pwd,
                          "-keypass", pwd], log=None)
            done = rc == 0
        if done and log:
            log("默认密钥库别名已随机化（密钥不变）", "DIM")
        if not done:
            if log:
                log("沿用默认密钥库的既有别名", "WARN")
            return ks, "cyrilshield", pwd
    else:
        if not keytool:
            raise ApkError("找不到 keytool，无法生成签名密钥库")
        rc, txt = _run([keytool, "-genkeypair", "-keystore", ks, "-storetype", "JKS",
                        "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "10950", "-storepass", pwd, "-keypass", pwd,
                        "-dname", "CN=CyrilShield, O=Self Signed, C=CN"], log=log)
        if rc != 0 or not os.path.isfile(ks):
            raise ApkError("生成签名密钥库失败：" + txt[-300:])
        if log:
            log(f"已生成默认签名密钥库：{ks}", "WARN")
            log("该密钥为工具自带默认值，正式发布请换用你自己的密钥库", "WARN")

    try:
        with open(meta, "w", encoding="utf-8") as fh:
            json.dump({"alias": alias, "store_pass": pwd}, fh)
    except Exception:
        pass
    return ks, alias, pwd


def _payload_asset(rng):
    """生成随机资产路径。返回 (zip 内完整路径, 资产管理器相对路径)。"""
    rel = _rand_ident(rng, 6) + "/" + _rand_ident(rng, 8) + ".dat"
    return "assets/" + rel, rel


def protect(path: str, out_path: str, opts: ApkOptions, log=print) -> dict:
    """对 APK 执行加固，返回结果摘要。"""
    t0 = time.time()
    rng = random.Random(opts.seed or int(time.time() * 1000) ^ os.getpid())
    tools = find_tools()
    if not tools["ok"]:
        raise ApkError("Android 工具链不完整，缺少：" + "、".join(tools["missing"]))
    # d8.bat / apksigner.bat 靠 JAVA_HOME 找 java，一律指向刚探测到的那套 JRE，
    # 避免被机器上残留的、缺少 javac 的旧 JAVA_HOME 带偏
    if tools["java_home"]:
        os.environ["JAVA_HOME"] = tools["java_home"]

    where = "内置" if tools.get("bundled") else "本机"
    log(f"工具链（{where}）：build-tools {os.path.basename(tools['build_tools'])} · "
        f"platform {tools['platform']} · JRE {tools['java_home']}", "DIM")

    meta = inspect(path, tools)
    if not meta["dexes"]:
        raise ApkError("APK 内没有 classes.dex，无法加固")
    if meta["packers"]:
        raise ApkError("该 APK 已加固（" + "、".join(meta["packers"]) +
                       "），需先脱壳取得原始 dex 才能处理")
    min_sdk = meta["min_sdk"] or 21
    if min_sdk < 19:
        log(f"minSdkVersion={min_sdk} 偏低，壳依赖的类加载器接口可能不存在", "WARN")

    tmp = tempfile.mkdtemp(prefix="cyrilshield_apk_")
    try:
        return _protect_inner(path, out_path, opts, rng, tools, meta, min_sdk, tmp, log, t0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _protect_inner(path, out_path, opts, rng, tools, meta, min_sdk, tmp, log, t0):
    level = opts.level if opts.level in ("compat", "standard", "strong") else "standard"
    with zipfile.ZipFile(path) as zf:
        entries = [(i, zf.read(i.filename)) for i in zf.infolist()]

    orig_app = meta["app_class"] or ""
    pkg = meta["package"]
    if not pkg:
        raise ApkError("清单缺少 package 属性")

    # ---- 1. 清单改写
    log("解析并改写 AndroidManifest.xml", "DIM")
    raw_manifest = dict((i.filename, d) for i, d in entries)["AndroidManifest.xml"]
    doc = axml.Document.parse(raw_manifest)
    app_node = doc.app_node()
    if app_node is None:
        raise ApkError("清单缺少 <application> 节点")

    if level == "compat":
        stub_pkg = stub_cls = stub_full = ""
    else:
        stub_pkg = pkg + ".ps" + _rand_ident(rng, 5)
        stub_cls = _rand_ident(rng, 11)
        stub_full = stub_pkg + "." + stub_cls
        doc.set_android_attr(app_node, axml.ATTR_NAME, string=stub_full, attr_name="name")

    if opts.strip_debug:
        if doc.remove_attr(app_node, axml.ATTR_DEBUGGABLE, "debuggable"):
            log("已移除 android:debuggable", "DIM")
    if opts.harden_backup:
        doc.set_android_attr(app_node, axml.ATTR_ALLOW_BACKUP, boolean=False, attr_name="allowBackup")
        log("已设置 android:allowBackup=false", "DIM")
    new_manifest = doc.to_bytes()
    # 立即回读校验
    check = axml.manifest_info(axml.Document.parse(new_manifest))
    if check["package"] != pkg:
        raise ApkError("清单改写后包名异常，已中止")
    if stub_full and check["app_class"] != stub_full:
        raise ApkError("壳类名写入失败，已中止")

    # ---- 2. dex 加密
    payloads = {}
    want_sha = hashlib.sha256()
    total_plain = 0
    if level == "compat":
        log("兼容模式：不抽取 dex，仅重打包与重签名", "WARN")
    else:
        # 八组常量 → 前四组与后四组异或出 64 字节材料 → HMAC 压成根密钥
        rows = [[rng.getrandbits(32) for _ in range(4)] for _ in range(8)]
        material = b"".join(
            (rows[g][i] ^ rows[g + 4][i]).to_bytes(4, "big")
            for g in range(4) for i in range(4))
        salt_root = rng.randbytes(32)
        salt_part = rng.randbytes(32)
        root = _stream.root_key(salt_root, material)

        dex_names = [d["name"] for d in meta["dexes"]]
        log(f"抽取 {len(dex_names)} 个 dex：{', '.join(dex_names)}", "DIM")
        part_names = []
        for idx, name in enumerate(dex_names):
            plain = dict((i.filename, d) for i, d in entries)[name]
            want_sha.update(plain)
            total_plain += len(plain)
            part_key = _stream.sub_key(root, salt_part, idx)
            nonce = rng.randbytes(_stream.NONCE)
            zip_path, rel_path = _payload_asset(rng)
            payloads[zip_path] = _stream.seal(part_key, nonce, plain)
            part_names.append(rel_path)
            log(f"  {name} {len(plain):,} 字节 → {zip_path}", "DIM")

        # ---- 3. 生成并编译壳类
        log("生成壳 Application 源码", "DIM")
        want = want_sha.hexdigest() if level == "strong" else ""
        real_name = orig_app if not orig_app.startswith(".") else pkg + orig_app
        rs, rk = _obf(real_name, rng)
        ws, wk = _obf(want, rng)
        kt = ", ".join("new int[]{%s}" % ", ".join(_s32(v) for v in row) for row in rows)
        src = (STUB_TEMPLATE
               .replace("@PKG@", stub_pkg)
               .replace("@CLS@", stub_cls)
               .replace("@PARTS@", ",".join('"%s"' % n for n in part_names))
               .replace("@KT@", kt)
               .replace("@SL@", _blit(salt_root))
               .replace("@SP@", _blit(salt_part))
               .replace("@RS@", rs)
               .replace("@RK@", rk)
               .replace("@WS@", ws)
               .replace("@WK@", wk)
               .replace("@DIR@", "." + _rand_ident(rng, 7)))
        # 调试构建保留诊断日志；正式构建把 //DBG 整行剔除，产物里不留字符串
        if opts.extra.get("debug"):
            src = re.sub(r"(?m)^[ \t]*//DBG ?", "", src)
        else:
            src = re.sub(r"(?m)^[ \t]*//DBG[^\n]*\n?", "", src)
        src_dir = os.path.join(tmp, "src", *stub_pkg.split("."))
        os.makedirs(src_dir, exist_ok=True)
        java_file = os.path.join(src_dir, stub_cls + ".java")
        with open(java_file, "w", encoding="utf-8") as fh:
            fh.write(src)

        obj = os.path.join(tmp, "obj")
        os.makedirs(obj, exist_ok=True)
        rc, txt = _run([tools["javac"], "-J-Duser.language=en", "-J-Duser.country=US",
                        "-nowarn", "-encoding", "UTF-8", "-source", "8", "-target", "8",
                        "-cp", tools["android_jar"], "-d", obj, java_file], log=log)
        if rc != 0:
            raise ApkError("壳类编译失败：" + txt[-400:])
        classes = []
        for root, _d, files in os.walk(obj):
            for f in files:
                if f.endswith(".class"):
                    classes.append(os.path.join(root, f))
        if not classes:
            raise ApkError("壳类编译未产出 class 文件")
        dexdir = os.path.join(tmp, "dex")
        os.makedirs(dexdir, exist_ok=True)
        api = max(21, min_sdk)
        rc, txt = _run([tools["d8"], "--release", "--min-api", str(api),
                        "--lib", tools["android_jar"], "--output", dexdir] + classes, log=log)
        if rc != 0:
            raise ApkError("dex 生成失败：" + txt[-400:])
        stub_dex = os.path.join(dexdir, "classes.dex")
        if not os.path.isfile(stub_dex):
            raise ApkError("d8 未产出 classes.dex")
        stub_bytes = open(stub_dex, "rb").read()
        log(f"壳 dex：{len(stub_bytes):,} 字节，{len(part_names)} 段载荷", "DIM")

    # ---- 4. 重打包
    log("重打包 APK", "DIM")
    unsigned = os.path.join(tmp, "unsigned.apk")
    drop_dex = {d["name"] for d in meta["dexes"]} if level != "compat" else set()
    with zipfile.ZipFile(unsigned, "w") as zo:
        for info, data in entries:
            name = info.filename
            if SIG_FILE_RE.match(name) or name.upper() == "META-INF/MANIFEST.MF":
                continue
            if name == "AndroidManifest.xml":
                continue
            if name in drop_dex:
                continue
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zo.writestr(zi, data)
        zi = zipfile.ZipInfo("AndroidManifest.xml", date_time=(2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zo.writestr(zi, new_manifest)
        if level != "compat":
            zi = zipfile.ZipInfo("classes.dex", date_time=(2026, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zo.writestr(zi, stub_bytes)
            for name, data in payloads.items():
                zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                zo.writestr(zi, data)

    # ---- 5. 对齐 + 签名
    aligned = os.path.join(tmp, "aligned.apk")
    log("zipalign 4 字节对齐", "DIM")
    rc, txt = _run([tools["zipalign"], "-f", "-p", "4", unsigned, aligned], log=log)
    if rc != 0 or not os.path.isfile(aligned):
        raise ApkError("对齐失败：" + txt[-300:])

    if opts.keystore:
        ks, alias, pwd, kpwd = opts.keystore, opts.ks_alias or "key0", opts.ks_pass, opts.key_pass or opts.ks_pass
        if not os.path.isfile(ks):
            raise ApkError("指定的密钥库不存在")
    else:
        ks, alias, pwd = _default_keystore(log, tools.get("keytool", ""))
        kpwd = pwd

    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    log("apksigner 签名", "DIM")
    # Android 7.0 以下没有 v2 校验，minSdk < 24 必须同时启用 v1，否则安装失败
    use_v1 = True if min_sdk < 24 else bool(opts.v1)
    if use_v1:
        log(f"minSdkVersion={min_sdk} < 24，自动启用 v1 签名", "DIM")
    rc, txt = _run([tools["apksigner"], "sign", "--ks", ks, "--ks-key-alias", alias,
                    "--ks-pass", "pass:" + pwd, "--key-pass", "pass:" + kpwd,
                    "--v1-signing-enabled", "true" if use_v1 else "false",
                    "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                    # v4 会额外吐一个 .idsig 旁路文件，只有 adb 增量安装才用得上，
                    # 普通安装/分发反而多一个让人困惑的产物，关掉。
                    "--v4-signing-enabled", "false",
                    "--out", out_path, aligned], log=log)
    if rc != 0 or not os.path.isfile(out_path):
        raise ApkError("签名失败：" + txt[-400:])

    rc, txt = _run([tools["apksigner"], "verify", "--print-certs", out_path], timeout=180)
    verified = rc == 0
    cert_dn = ""
    for line in txt.splitlines():
        if "certificate DN" in line:
            cert_dn = line.split(":", 1)[1].strip()
            break
    if not verified:
        raise ApkError("签名校验未通过：" + txt[-300:])

    # ---- 6. 产物自检
    with zipfile.ZipFile(out_path) as zf:
        names = zf.namelist()
        out_manifest = zf.read("AndroidManifest.xml")
        out_dex = {n: hashlib.sha256(zf.read(n)).hexdigest()
                   for n in names if re.match(r"^classes\d*\.dex$", n)}
    out_info = axml.manifest_info(axml.Document.parse(out_manifest))
    orig_dex_hash = {d["name"]: hashlib.sha256(
        dict((i.filename, x) for i, x in entries)[d["name"]]).hexdigest()
        for d in meta["dexes"]}
    new_sig = _signature_info(out_path, tools)
    checks = {
        "包名一致": out_info["package"] == pkg,
        "版本号一致": out_info["version_code"] == meta["version_code"],
        "壳类已注入": (out_info["app_class"] == stub_full) if level != "compat" else True,
        "原 dex 已替换": not (set(out_dex.values()) & set(orig_dex_hash.values()))
                      if level != "compat" else True,
        "签名有效": verified,
    }
    if not all(checks.values()):
        failed = [k for k, v in checks.items() if not v]
        raise ApkError("产物自检失败：" + "、".join(failed))

    elapsed = time.time() - t0
    out_size = os.path.getsize(out_path)
    log(f"完成：{meta['size']:,} → {out_size:,} 字节，用时 {elapsed:.1f}s", "OK")
    return {
        "path": out_path, "name": os.path.basename(out_path),
        "package": pkg, "level": level, "size_before": meta["size"],
        "size_after": out_size, "elapsed": round(elapsed, 1),
        "stub_class": stub_full, "payload_parts": len(payloads),
        "dex_bytes": total_plain, "checks": checks, "cert_dn": cert_dn,
        "cert_changed": bool(meta["signature"].get("sha256")) and
                        new_sig.get("sha256") != meta["signature"].get("sha256"),
        "schemes": new_sig.get("schemes", []),
        "keystore": ks, "min_sdk": min_sdk,
    }
