# -*- coding: utf-8 -*-
"""CyrilShield 自检脚本（无需图形界面）。

用法：python selftest.py  [目标EXE路径]
不传参数时默认使用 C:\\Windows\\System32\\notepad.exe 作为样本。
"""
from __future__ import annotations

import hashlib
import os
import random
import shutil
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cyrilshield import _stream, apk, axml, pe, upx, vmgen  # noqa: E402

PASS, FAIL, SKIP = "[ OK ]", "[FAIL]", "[SKIP]"
results = []
skipped = []


def check(name, fn):
    try:
        detail = fn()
        results.append(True)
        print(f"{PASS} {name}" + (f" — {detail}" if detail else ""))
    except Exception as exc:
        results.append(False)
        print(f"{FAIL} {name} — {type(exc).__name__}: {exc}")


def skip(name, why):
    skipped.append(name)
    print(f"{SKIP} {name} — {why}")


def main():
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    positional = [a for a in sys.argv[1:] if not a.startswith("--")]
    sample = positional[0] if positional else r"C:\Windows\System32\notepad.exe"
    if not os.path.isfile(sample):
        print(f"样本不存在：{sample}")
        return 1
    tmp = tempfile.mkdtemp(prefix="cyrilshield_selftest_")
    print("样本:", sample)
    print("临时目录:", tmp, "\n")

    f = None

    def t_pe():
        nonlocal f
        f = pe.load(sample)
        s = f.summary()
        return f"{s['machine']} / {s['pe_type']} / {len(s['sections'])} 节区"
    check("PE 头解析", t_pe)

    def t_icons():
        groups = f.extract_icon_groups()
        out = os.path.join(tmp, "icons")
        files = pe.export_icons(f, out, True, True, log=lambda *_: None)
        assert files, "未导出任何文件"
        return f"{len(groups)} 组图标 → {len(files)} 个文件"
    check("图标提取（ICO + PNG）", t_icons)

    def t_png():
        from PIL import Image
        pngs = [os.path.join(r, x) for r, _, fs in os.walk(os.path.join(tmp, "icons"))
                for x in fs if x.lower().endswith(".png")]
        for p in pngs:
            Image.open(p).verify()
        return f"{len(pngs)} 张 PNG 全部可解码" if pngs else "无 PNG（样本可能无图标）"
    try:
        import PIL  # noqa: F401
        check("PNG 图像有效性", t_png)
    except ImportError:
        print("[SKIP] PNG 图像有效性 — 未安装 Pillow")

    tool = upx.find_upx()
    packed = os.path.join(tmp, "packed.exe")
    restored = os.path.join(tmp, "restored.exe")

    def t_upx():
        assert tool, "未找到 upx.exe"
        opt = upx.PackOptions(level=7, force=True)
        rc, _, _ = upx.execute("pack", tool, sample, packed, opt,
                               on_line=lambda *_: None)
        assert rc == 0 and os.path.isfile(packed), "压缩失败"
        a, b = os.path.getsize(sample), os.path.getsize(packed)
        return f"{a:,} → {b:,} 字节（{upx.version(tool).splitlines()[0]}）"
    check("UPX 压缩加壳", t_upx)

    def t_upt():
        rc, _, _ = upx.execute("test", tool, packed, on_line=lambda *_: None)
        assert rc == 0, "完整性测试失败"
        return "-t 通过"
    check("UPX 完整性测试", t_upt)

    def t_upd():
        rc, _, _ = upx.execute("unpack", tool, packed, restored,
                               on_line=lambda *_: None)
        assert rc == 0, "脱壳失败"
        # UPX 会重建 PE 头，因此不保证与原文件逐字节一致，只校验结构与量级
        r = pe.load(restored).summary()
        o = pe.load(sample).summary()
        assert r["machine"] == o["machine"] and r["pe_type"] == o["pe_type"], "还原后 PE 结构不一致"
        a, b = o["size"], r["size"]
        assert abs(a - b) <= max(8192, a * 0.15), f"还原大小异常：{a:,} → {b:,}"
        return f"还原为有效 PE，{a:,} → {b:,} 字节（UPX 不保证逐字节相同）"
    check("UPX 脱壳还原有效性", t_upd)

    def t_vmprog():
        plain = open(sample, "rb").read()
        rng = random.SystemRandom()
        key = rng.randbytes(32)
        prog, ops, plan = vmgen.make_program(key, 2, rng)
        payload = os.path.join(tmp, plan.payload_name)
        with open(payload, "wb") as fh:
            fh.write(vmgen.pack_payload(plain, key, vmgen.FLAG_VERIFY,
                                        os.path.basename(sample), "", plan))
        outdir = os.path.join(tmp, "vmcheck")
        os.makedirs(outdir, exist_ok=True)
        assert vmgen.selftest(prog, ops, plan, payload, outdir), "字节码执行失败"
        h1 = hashlib.sha256(plain).hexdigest()
        h2 = hashlib.sha256(open(os.path.join(outdir, "restored.exe"), "rb").read()).hexdigest()
        assert h1 == h2, "解密还原内容不一致"
        return f"{len(prog) // 8} 条虚拟指令，还原哈希一致"
    check("VM 字节码 / 载荷加解密", t_vmprog)

    def t_poly():
        rng = random.SystemRandom()
        key = rng.randbytes(32)
        a = vmgen.make_program(key, 1, rng)
        b = vmgen.make_program(key, 1, rng)
        assert a[0] != b[0], "两次构建字节码相同"
        assert a[1] != b[1], "两次构建操作码映射相同"
        pa, pb = a[2], b[2]
        assert pa.magic != pb.magic, "载荷魔数未随机化"
        assert pa.salt != pb.salt, "密钥盐未随机化"
        assert len(a[2].names) == len(set(a[2].names.values())), "符号名重复"
        return f"魔数/盐/字段排列/符号名均随机（{pa.order} vs {pb.order}）"
    check("VM 多态随机化", t_poly)

    def t_upxb():
        tool = upx.find_upx()
        assert tool, "未找到内置 upx.exe"
        root = os.path.dirname(os.path.dirname(os.path.abspath(upx.__file__)))
        assert os.path.abspath(tool).startswith(root), f"UPX 不是内置副本：{tool}"
        return os.path.relpath(tool, root)
    check("内置 UPX", t_upxb)

    def t_web():
        from cyrilshield import server
        wd = server.web_dir()
        for n in ("index.html", "app.css", "app.js"):
            assert os.path.isfile(os.path.join(wd, n)), f"缺少界面资源 {n}"
        return wd
    check("Web 界面资源", t_web)

    def t_backend():
        ok, info = vmgen.check_backend()
        return info
    check("VM 构建后端", t_backend)

    # ---------------- APK 加固 ----------------
    apk_sample = next((a for a in positional if a.lower().endswith(".apk")
                       and os.path.isfile(a)), None)
    if not apk_sample:
        cand = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "tests", "sample.apk")
        if os.path.isfile(cand):
            apk_sample = cand
    tools = apk.find_tools()

    def t_seal():
        rng = random.Random(2026)
        rows = [[rng.getrandbits(32) for _ in range(4)] for _ in range(8)]
        mat = b"".join((rows[g][i] ^ rows[g + 4][i]).to_bytes(4, "big")
                       for g in range(4) for i in range(4))
        sr, sp = rng.randbytes(32), rng.randbytes(32)
        root = _stream.root_key(sr, mat)
        k0 = _stream.sub_key(root, sp, 0)
        k1 = _stream.sub_key(root, sp, 1)
        assert k0 != k1, "不同段的子密钥不应相同"
        assert _stream.root_key(sr, mat) == root, "根密钥派生不稳定"
        assert _stream.root_key(sp, mat) != root, "换盐应得到不同根密钥"
        plain = b"dex\n035\x00" + bytes(range(256)) * 40
        nonce = rng.randbytes(_stream.NONCE)
        blob = _stream.seal(k0, nonce, plain)
        assert len(blob) == len(plain) + _stream.TRAILER, "封装后长度异常"
        assert blob[:4] != b"PSPL" and blob[:4] != b"dex\n", "载荷不应带可识别头部"
        assert _stream.open_sealed(k0, blob) == plain, "往返解密不一致"
        assert _stream.open_sealed(k1, blob) == b"", "错误子密钥应拒绝解密"
        bad = bytearray(blob)
        bad[len(bad) // 3] ^= 0x01
        assert _stream.open_sealed(k0, bytes(bad)) == b"", "篡改密文未被检出"
        trunc = blob[:-1]
        assert _stream.open_sealed(k0, trunc) == b"", "截断载荷未被检出"
        return (f"{len(blob):,} 字节 · 尾部 {_stream.TRAILER} 字节元数据 · "
                f"篡改/截断可检出")
    check("载荷容器封装", t_seal)

    root = apk.bundled_toolchain()

    def t_bundled():
        t = apk._tools_from_bundled(root)
        assert t["ok"], "缺少：" + "、".join(t["missing"])
        assert t["bundled"], "未标记为内置"
        total = 0
        for base, _d, files in os.walk(root):
            for f in files:
                total += os.path.getsize(os.path.join(base, f))
        return (f"{total / 1048576:.0f} MB · JRE {os.path.basename(t['java_home'])} · "
                f"platform {t['platform']}")
    if root:
        check("内置工具链（便携版）", t_bundled)
    else:
        skip("内置工具链（便携版）", "未生成 toolchain/，可用 build_portable.py 生成")

    if not apk_sample:
        skip("AXML 清单改写", "未提供 APK 样本")
        skip("APK 结构解析", "未提供 APK 样本")
        skip("APK 加固构建", "未提供 APK 样本")
    else:
        def t_axml():
            raw = zipfile.ZipFile(apk_sample).read("AndroidManifest.xml")
            doc = axml.Document.parse(raw)
            same = doc.to_bytes() == raw
            assert same, "未改动时序列化结果应与原文件逐字节相同"
            info = axml.manifest_info(doc)
            doc2 = axml.Document.parse(raw)
            axml.set_application_class(doc2, "com.test.ShellApp")
            out = doc2.to_bytes()
            info2 = axml.manifest_info(axml.Document.parse(out))
            assert info2["app_class"] == "com.test.ShellApp", "壳类名未写入"
            assert info2["package"] == info["package"], "包名被破坏"
            n1 = len(axml.Document.parse(raw).resource_ids)
            n2 = len(axml.Document.parse(out).resource_ids)
            assert n2 == n1, "资源映射表被破坏"
            return f"{len(doc.pool.strings)} 条字符串 / {n1} 条资源映射，往返逐字节一致"
        check("AXML 清单改写", t_axml)

        def t_apkinspect():
            d = apk.inspect(apk_sample, tools)
            assert d["package"], "未解析出包名"
            assert d["dexes"], "未解析出 dex"
            return (f"{d['package']} · {len(d['dexes'])} 个 dex · "
                    f"签名 {'+'.join(d['signature']['schemes']) or '无'}")
        check("APK 结构解析", t_apkinspect)

        if not tools["ok"]:
            skip("APK 加固构建", "缺少 " + "、".join(tools["missing"]))
        else:
            def t_apkbuild():
                out = os.path.join(tmp, "protected.apk")
                r = apk.protect(apk_sample, out, apk.ApkOptions(level="strong", seed=42),
                                log=lambda *_: None)
                assert os.path.isfile(out), "未生成 APK"
                assert all(r["checks"].values()), "产物自检未通过"
                names = zipfile.ZipFile(out).namelist()
                assert not any(n.endswith(".dex") and n != "classes.dex" for n in names), \
                    "原始 dex 未被移除"
                return (f"{r['size_before']:,} → {r['size_after']:,} 字节 · "
                        f"{r['payload_parts']} 段载荷 · 壳类 {r['stub_class']}")
            check("APK 加固构建", t_apkbuild)

            def t_apkcompat():
                out = os.path.join(tmp, "compat.apk")
                r = apk.protect(apk_sample, out, apk.ApkOptions(level="compat", seed=7),
                                log=lambda *_: None)
                names = zipfile.ZipFile(out).namelist()
                assert "classes.dex" in names, "兼容模式不应移除 dex"
                return f"{r['size_after']:,} 字节，dex 原样保留"
            check("APK 兼容模式", t_apkcompat)

    if "--full" in flags:
        def t_vmbuild():
            out = os.path.join(tmp, "vm_protected.exe")
            r = vmgen.build(sample, out, vmgen.VMOptions(junk_level=1),
                            on_line=lambda *_: None)
            assert os.path.isfile(out), "未生成 EXE"
            return f"输出 {r.output_size:,} 字节 / {r.program_size} 条虚拟指令"
        check("VM 壳完整构建", t_vmbuild)

    print("\n" + "=" * 60)
    line = f"结果：{sum(results)}/{len(results)} 项通过"
    if skipped:
        line += f"（{len(skipped)} 项跳过）"
    print(line)
    if "--keep" not in flags:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("临时产物保留于:", tmp)
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
