# -*- coding: utf-8 -*-
"""
PE 文件解析与图标资源提取。

不依赖任何第三方库即可完成 PE 资源目录遍历、RT_GROUP_ICON / RT_ICON
解析和 .ico 重建；导出 PNG 时可选使用 Pillow。
"""
from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

RT_ICON = 3
RT_GROUP_ICON = 14
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

MACHINE_NAMES = {
    0x014C: "x86 (I386)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x0200: "IA64",
}


class PEError(Exception):
    """PE 格式错误或不支持的结构。"""


def _u16(data: bytes, off: int) -> int:
    if off + 2 > len(data):
        raise PEError("文件被截断（读取 2 字节失败）")
    return struct.unpack_from("<H", data, off)[0]


def _i32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise PEError("文件被截断（读取 4 字节失败）")
    return struct.unpack_from("<i", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off + 4 > len(data):
        raise PEError("文件被截断（读取 4 字节失败）")
    return struct.unpack_from("<I", data, off)[0]


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int


@dataclass
class IconEntry:
    """一个图标组中的单张图片。"""
    width: int
    height: int
    color_count: int
    planes: int
    bit_count: int
    res_id: int
    lang: int
    data: bytes = b""

    @property
    def size_label(self) -> str:
        return f"{self.width or 256}x{self.height or 256}"

    @property
    def kind(self) -> str:
        return "PNG" if self.data.startswith(PNG_MAGIC) else "DIB/BMP"

    @property
    def label(self) -> str:
        return f"{self.size_label} · {self.bit_count}bit · {self.kind}"


@dataclass
class IconGroup:
    name: str
    lang: int
    entries: list[IconEntry] = field(default_factory=list)

    def to_ico(self) -> bytes:
        """把组内所有图片重新封装为完整 .ico 文件。"""
        count = len(self.entries)
        if count == 0:
            raise PEError("图标组为空")
        header = struct.pack("<HHH", 0, 1, count)
        offset = 6 + 16 * count
        dir_bytes = bytearray()
        body = bytearray()
        for e in self.entries:
            w = 0 if e.width >= 256 else e.width
            h = 0 if e.height >= 256 else e.height
            dir_bytes += struct.pack(
                "<BBBBHHII",
                w, h, e.color_count, 0,
                e.planes, e.bit_count, len(e.data), offset,
            )
            body += e.data
            offset += len(e.data)
        return header + bytes(dir_bytes) + bytes(body)


class PEFile:
    """只读 PE 解析器。"""

    def __init__(self, data: bytes, path: str = ""):
        self.data = data
        self.path = path
        self.sections: list[Section] = []
        self.machine = 0
        self.entry_point = 0
        self.image_base = 0
        self.subsystem = 0
        self.characteristics = 0
        self.timestamp = 0
        self.is_pe32_plus = False
        self.resource_rva = 0
        self.resource_size = 0
        self.is_dotnet = False
        self._parse_headers()

    # ---------- 头部 ----------
    def _parse_headers(self) -> None:
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("不是有效的 PE 文件（缺少 MZ 标志）")
        pe_off = _u32(d, 0x3C)
        if pe_off + 24 > len(d) or d[pe_off:pe_off + 4] != b"PE\0\0":
            raise PEError("不是有效的 PE 文件（缺少 PE 签名）")
        coff = pe_off + 4
        self.machine = _u16(d, coff)
        nsections = _u16(d, coff + 2)
        self.timestamp = _u32(d, coff + 4)
        opt_size = _u16(d, coff + 16)
        self.characteristics = _u16(d, coff + 18)
        opt = coff + 20
        magic = _u16(d, opt)
        if magic == 0x10B:
            self.is_pe32_plus = False
            dd_off = opt + 96
            self.image_base = _u32(d, opt + 28)
        elif magic == 0x20B:
            self.is_pe32_plus = True
            dd_off = opt + 112
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        else:
            raise PEError(f"不支持的 Optional Header Magic: 0x{magic:X}")
        self.entry_point = _u32(d, opt + 16)
        self.subsystem = _u16(d, opt + 68)
        ndd = _u32(d, opt + (92 if not self.is_pe32_plus else 108))
        if ndd > 2:
            self.resource_rva = _u32(d, dd_off + 2 * 8)
            self.resource_size = _u32(d, dd_off + 2 * 8 + 4)
        if ndd > 14:
            clr_rva = _u32(d, dd_off + 14 * 8)
            self.is_dotnet = clr_rva != 0

        sec = opt + opt_size
        for i in range(nsections):
            p = sec + i * 40
            if p + 40 > len(d):
                break
            raw_name = d[p:p + 8].split(b"\0", 1)[0]
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError:
                name = raw_name.decode("ascii", "replace")
            self.sections.append(Section(
                name=name,
                virtual_size=_u32(d, p + 8),
                virtual_address=_u32(d, p + 12),
                raw_size=_u32(d, p + 16),
                raw_offset=_u32(d, p + 20),
            ))

    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            span = max(s.virtual_size, s.raw_size)
            if s.virtual_address <= rva < s.virtual_address + span:
                delta = rva - s.virtual_address
                if delta < s.raw_size:
                    return s.raw_offset + delta
                return None
        # 头部内的 RVA 直接映射
        if rva and rva < (self.sections[0].virtual_address if self.sections else 0x1000):
            return rva
        return None

    # ---------- 资源目录 ----------
    def _res_string(self, offset: int) -> str:
        try:
            n = _u16(self.data, offset)
            return self.data[offset + 2: offset + 2 + n * 2].decode("utf-16-le", "replace")
        except PEError:
            return ""

    def _res_entries(self, dir_off: int, base: int):
        """返回 [(name, target_file_offset, is_subdir), ...]"""
        d = self.data
        if dir_off + 16 > len(d):
            return []
        named = _u16(d, dir_off + 12)
        ids = _u16(d, dir_off + 14)
        out = []
        for i in range(named + ids):
            p = dir_off + 16 + i * 8
            if p + 8 > len(d):
                break
            name_raw = _u32(d, p)
            target_raw = _u32(d, p + 4)
            name = (self._res_string(base + (name_raw & 0x7FFFFFFF))
                    if name_raw & 0x80000000 else (name_raw & 0xFFFF))
            is_dir = bool(target_raw & 0x80000000)
            out.append((name, base + (target_raw & 0x7FFFFFFF), is_dir))
        return out

    def _res_data(self, entry_off: int) -> bytes:
        d = self.data
        rva = _u32(d, entry_off)
        size = _u32(d, entry_off + 4)
        off = self.rva_to_offset(rva)
        if off is None or off + size > len(d):
            return b""
        return d[off:off + size]

    def extract_icon_groups(self) -> list[IconGroup]:
        """解析全部 RT_GROUP_ICON，并绑定对应的 RT_ICON 数据。"""
        if not self.resource_rva:
            return []
        base = self.rva_to_offset(self.resource_rva)
        if base is None:
            return []
        icons: dict[tuple, bytes] = {}
        groups: list[IconGroup] = []
        try:
            for type_id, type_dir, is_dir in self._res_entries(base, base):
                if not is_dir or type_id not in (RT_ICON, RT_GROUP_ICON):
                    continue
                for name_id, name_dir, is_dir2 in self._res_entries(type_dir, base):
                    if not is_dir2:
                        continue
                    for lang, data_entry, is_dir3 in self._res_entries(name_dir, base):
                        if is_dir3:
                            continue
                        blob = self._res_data(data_entry)
                        if not blob:
                            continue
                        if type_id == RT_ICON:
                            icons[(name_id, lang)] = blob
                        else:
                            grp = self._parse_group(name_id, lang, blob)
                            if grp:
                                groups.append(grp)
        except PEError:
            return groups

        for grp in groups:
            for e in grp.entries:
                blob = icons.get((e.res_id, grp.lang))
                if blob is None:
                    # 语言不匹配时退化为同 ID 的任意语言
                    blob = next((v for (rid, _), v in icons.items() if rid == e.res_id), b"")
                e.data = blob
        return groups

    def _parse_group(self, name, lang, blob: bytes) -> Optional[IconGroup]:
        if len(blob) < 6:
            return None
        count = _u16(blob, 4)
        if count <= 0 or count > 256:
            return None
        grp = IconGroup(name=self._group_name(name), lang=lang)
        for i in range(count):
            p = 6 + i * 14
            if p + 14 > len(blob):
                break
            w, h, colors, _reserved = blob[p], blob[p + 1], blob[p + 2], blob[p + 3]
            planes = _u16(blob, p + 4)
            bits = _u16(blob, p + 6)
            res_id = _u16(blob, p + 12)
            grp.entries.append(IconEntry(
                width=w, height=h, color_count=colors, planes=planes,
                bit_count=bits, res_id=res_id, lang=lang,
            ))
        return grp

    @staticmethod
    def _group_name(name) -> str:
        if isinstance(name, str):
            return name
        return f"图标组 #{name}"

    # ---------- 概要信息 ----------
    def is_upx_packed(self) -> bool:
        names = {s.name.upper() for s in self.sections}
        if "UPX0" in names or "UPX1" in names:
            return True
        return b"UPX!" in self.data[:0x2000] or b"$Info: This file is packed with the UPX" in self.data

    def summary(self) -> dict:
        return {
            "path": self.path,
            "size": len(self.data),
            "machine": MACHINE_NAMES.get(self.machine, f"0x{self.machine:04X}"),
            "pe_type": "PE32+" if self.is_pe32_plus else "PE32",
            "entry_point": f"0x{self.entry_point:X}",
            "image_base": f"0x{self.image_base:X}",
            "sections": [s.name for s in self.sections],
            "dotnet": self.is_dotnet,
            "upx": self.is_upx_packed(),
            "resource": bool(self.resource_rva),
        }


# ---------- DIB -> RGBA ----------
def dib_to_rgba(data: bytes):
    """把图标 DIB（BITMAPINFOHEADER）转换成 (w, h, RGBA bytes)。

    返回 None 表示 data 本身已经是 PNG。
    """
    if data.startswith(PNG_MAGIC):
        return None
    if len(data) < 40:
        raise PEError("图标 DIB 数据过短")
    hdr_size = _u32(data, 0)
    w = _i32(data, 4)
    h2 = _i32(data, 8)
    h = abs(h2) // 2
    bpp = _u16(data, 14)
    comp = _u32(data, 16)
    if w <= 0 or h <= 0 or w > 1024 or h > 1024 or bpp not in (1, 2, 4, 8, 16, 24, 32):
        raise PEError(f"不支持的图标 DIB 参数: {w}x{h} {bpp}bpp")

    palette_count = 0
    if bpp <= 8:
        used = _u32(data, 32)
        palette_count = used if used else (1 << bpp)
    pixel_off = hdr_size + palette_count * 4
    if comp == 3 and hdr_size == 40 and bpp in (16, 32):
        pixel_off += 12  # BI_BITFIELDS 的三个掩码

    palette = []
    for i in range(palette_count):
        p = hdr_size + i * 4
        if p + 4 > len(data):
            break
        b, g, r = data[p], data[p + 1], data[p + 2]
        palette.append((r, g, b, 255))

    xor_stride = ((w * bpp + 31) // 32) * 4
    and_stride = ((w + 31) // 32) * 4
    xor_size = xor_stride * h
    xor = data[pixel_off: pixel_off + xor_size]
    and_mask = data[pixel_off + xor_size: pixel_off + xor_size + and_stride * h]
    if len(xor) < xor_size:
        xor = xor.ljust(xor_size, b"\0")
    if len(and_mask) < and_stride * h:
        and_mask = and_mask.ljust(and_stride * h, b"\0")

    has_alpha_channel = False
    if bpp == 32:
        for y in range(h):
            row = xor[y * xor_stride:(y + 1) * xor_stride]
            if any(row[i + 3] for i in range(0, w * 4, 4)):
                has_alpha_channel = True
                break

    out = bytearray(w * h * 4)
    for y in range(h):
        src_row = xor[y * xor_stride:(y + 1) * xor_stride]
        mask_row = and_mask[y * and_stride:(y + 1) * and_stride]
        dst_y = h - 1 - y  # DIB 自下而上
        for x in range(w):
            if bpp == 32:
                b, g, r, a = src_row[x * 4:x * 4 + 4]
                alpha = a if has_alpha_channel else 255
            elif bpp == 24:
                b, g, r = src_row[x * 3:x * 3 + 3]
                alpha = 255
            elif bpp == 16:
                v = src_row[x * 2] | (src_row[x * 2 + 1] << 8)
                r = ((v >> 10) & 31) * 255 // 31
                g = ((v >> 5) & 31) * 255 // 31
                b = (v & 31) * 255 // 31
                alpha = 255
            else:
                if bpp == 8:
                    idx = src_row[x]
                elif bpp == 4:
                    idx = (src_row[x // 2] >> (4 if x % 2 == 0 else 0)) & 0xF
                elif bpp == 2:
                    idx = (src_row[x // 4] >> (6 - 2 * (x % 4))) & 0x3
                else:
                    idx = (src_row[x // 8] >> (7 - (x % 8))) & 1
                r, g, b, alpha = palette[idx] if idx < len(palette) else (0, 0, 0, 255)
            bit = (mask_row[x // 8] >> (7 - (x % 8))) & 1 if x // 8 < len(mask_row) else 0
            if bit:
                alpha = 0
            p = (dst_y * w + x) * 4
            out[p:p + 4] = bytes((r, g, b, alpha))
    return w, h, bytes(out)


def entry_to_png_bytes(entry: IconEntry) -> bytes:
    """把单张图标转换为 PNG 字节流。"""
    from PIL import Image  # 延迟导入，提取 ICO 时无需 Pillow

    if entry.data.startswith(PNG_MAGIC):
        return entry.data
    conv = dib_to_rgba(entry.data)
    if conv is None:
        return entry.data
    w, h, rgba = conv
    img = Image.frombytes("RGBA", (w, h), rgba)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def entry_to_pillow_image(entry: IconEntry):
    """返回 Pillow Image，用于 GUI 预览。"""
    from PIL import Image

    return Image.open(io.BytesIO(entry_to_png_bytes(entry))).convert("RGBA")


# ---------- 高层导出 ----------
def export_icons(pe: PEFile, out_dir: str, want_ico: bool = True,
                 want_png: bool = True, log=print) -> list[str]:
    """导出全部图标组，返回生成的文件路径列表。"""
    groups = pe.extract_icon_groups()
    if not groups:
        raise PEError("该 PE 文件没有可提取的图标资源（RT_GROUP_ICON）")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(pe.path or "icon"))[0] or "icon"
    written: list[str] = []

    def safe(s: str) -> str:
        return "".join(c if c.isalnum() or c in "-_#" else "_" for c in str(s))

    for gi, grp in enumerate(groups):
        tag = safe(grp.name)
        if len(groups) == 1:
            stem = base
        else:
            stem = f"{base}_{gi + 1}_{tag}"
        if want_ico:
            p = os.path.join(out_dir, stem + ".ico")
            with open(p, "wb") as f:
                f.write(grp.to_ico())
            written.append(p)
            log(f"  [ICO] {os.path.basename(p)}  ({len(grp.entries)} 个尺寸)")
        if want_png:
            for e in grp.entries:
                if not e.data:
                    continue
                p = os.path.join(out_dir, f"{stem}_{e.size_label}.png")
                try:
                    with open(p, "wb") as f:
                        f.write(entry_to_png_bytes(e))
                    written.append(p)
                except Exception as exc:  # 单张失败不影响其它
                    log(f"  [跳过] {e.label}: {exc}")
            log(f"  [PNG] {stem} 导出 {len(grp.entries)} 个尺寸")
    return written


def load(path: str) -> PEFile:
    with open(path, "rb") as f:
        return PEFile(f.read(), path)
