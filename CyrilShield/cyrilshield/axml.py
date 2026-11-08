"""Android 二进制资源（AXML / AndroidManifest.xml）解析与改写。

纯结构实现：解析字符串池与 XML 节点，支持在 ``<application>`` 上设置
``android:name``（注入壳的 Application 类）、增删属性、关闭调试标志。

改写策略：保持原字符串池顺序不变，仅"追加"新字符串，因此既有的字符串索引
与 resource map 全部保持有效，只重排后续 chunk 偏移。
"""

from __future__ import annotations

import struct

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# android 框架属性资源 ID
ATTR_LABEL = 0x01010001
ATTR_ICON = 0x01010002
ATTR_NAME = 0x01010003
ATTR_PERMISSION = 0x01010006
ATTR_DEBUGGABLE = 0x0101000F
ATTR_EXPORTED = 0x01010010
ATTR_THEME = 0x01010000
ATTR_MIN_SDK = 0x0101020C
ATTR_VERSION_CODE = 0x0101021B
ATTR_VERSION_NAME = 0x0101021C
ATTR_TARGET_SDK = 0x01010270
ATTR_ALLOW_BACKUP = 0x01010280
ATTR_EXTRACT_NATIVE_LIBS = 0x010104EA

ATTR_NAMES = {
    ATTR_LABEL: "label",
    ATTR_ICON: "icon",
    ATTR_NAME: "name",
    ATTR_PERMISSION: "permission",
    ATTR_DEBUGGABLE: "debuggable",
    ATTR_EXPORTED: "exported",
    ATTR_THEME: "theme",
    ATTR_MIN_SDK: "minSdkVersion",
    ATTR_VERSION_CODE: "versionCode",
    ATTR_VERSION_NAME: "versionName",
    ATTR_TARGET_SDK: "targetSdkVersion",
    ATTR_ALLOW_BACKUP: "allowBackup",
    ATTR_EXTRACT_NATIVE_LIBS: "extractNativeLibs",
}


class AxmlError(Exception):
    pass


def _read_len8(data, p):
    """AXML 的 UTF-8 变长长度：1 字节，最高位为续位标志。"""
    n = data[p]
    p += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | data[p]
        p += 1
    return n, p


def _read_len16(data, p):
    """AXML 的 UTF-16 变长长度（以 16 位字符为单位）。"""
    n, = struct.unpack_from("<H", data, p)
    p += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
        p += 2
    return n, p


def _write_len8(n):
    if n > 0x7F:
        return bytes([0x80 | ((n >> 8) & 0x7F), n & 0xFF])
    return bytes([n])


def _write_len16(n):
    if n > 0x7FFF:
        return struct.pack("<HH", 0x8000 | ((n >> 16) & 0x7FFF), n & 0xFFFF)
    return struct.pack("<H", n)


# ---------------------------------------------------------------- 字符串池
class StringPool:
    """AXML 字符串池。"""

    def __init__(self, strings=None, utf8=True):
        self.strings = list(strings or [])
        self.utf8 = utf8
        self._map = {}
        for i, s in enumerate(self.strings):
            self._map.setdefault(s, i)

    # -------------------------------------------------- 读
    @classmethod
    def parse(cls, data, off, size):
        if size < 28:
            raise AxmlError("字符串池过短")
        (_t, header_size, _size, count, style_count, flags,
         strings_start, _styles_start) = struct.unpack_from("<HHIIIIII", data, off)
        if count > 200000:
            raise AxmlError("字符串数量异常")
        if strings_start == 0 or strings_start > size:
            raise AxmlError("字符串池偏移非法")
        pool = cls([], utf8=bool(flags & (1 << 8)))
        base = off + strings_start
        end = off + size
        for i in range(count):
            so, = struct.unpack_from("<I", data, off + header_size + i * 4)
            p = base + so
            if p >= end:
                pool.strings.append("")
                continue
            try:
                if pool.utf8:
                    n, p = _read_len8(data, p)
                    blen, p = _read_len8(data, p)
                    pool.strings.append(data[p:p + blen].decode("utf-8", "replace"))
                else:
                    n, p = _read_len16(data, p)
                    pool.strings.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
            except Exception:
                pool.strings.append("")
        pool._map = {}
        for i, s in enumerate(pool.strings):
            pool._map.setdefault(s, i)
        return pool

    # -------------------------------------------------- 写
    def index(self, text):
        """返回字符串索引；不存在则追加（原索引保持不变）。"""
        if text in self._map:
            return self._map[text]
        self._map[text] = len(self.strings)
        self.strings.append(text)
        return self._map[text]

    def get(self, idx):
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""

    def to_bytes(self):
        enc = []
        for s in self.strings:
            if self.utf8:
                b = s.encode("utf-8")
                enc.append(_write_len8(len(s)) + _write_len8(len(b)) + b + b"\x00")
            else:
                b = s.encode("utf-16-le")
                enc.append(_write_len16(len(b) // 2) + b + b"\x00\x00")
        count = len(enc)
        header_size = 28
        strings_start = header_size + count * 4
        offsets = []
        pos = 0
        blob = bytearray()
        for e in enc:
            offsets.append(pos)
            blob += e
            pos += len(e)
        # 4 字节对齐
        while len(blob) % 4:
            blob += b"\x00"
        total = strings_start + len(blob)
        out = bytearray()
        # flags 清掉 SORTED，避免追加非有序字符串破坏二分查找
        flags = (1 << 8) if self.utf8 else 0
        out += struct.pack("<HHIIIIII", RES_STRING_POOL_TYPE, header_size, total,
                           count, 0, flags, strings_start, 0)
        out += b"".join(struct.pack("<I", o) for o in offsets)
        out += blob
        return bytes(out)


# ---------------------------------------------------------------- 节点模型
class Attr:
    __slots__ = ("ns", "name", "raw", "vtype", "vdata")

    def __init__(self, ns, name, raw, vtype, vdata):
        self.ns = ns
        self.name = name
        self.raw = raw
        self.vtype = vtype
        self.vdata = vdata

    def as_str(self, pool):
        if self.vtype == TYPE_STRING:
            return pool.get(self.vdata)
        if self.raw >= 0:
            return pool.get(self.raw)
        return None

    def as_int(self, pool):
        if self.vtype in (TYPE_INT_DEC, TYPE_INT_HEX):
            return self.vdata
        if self.vtype == TYPE_STRING:
            try:
                return int(pool.get(self.vdata))
            except Exception:
                return None
        return None


class Node:
    __slots__ = ("ctype", "line", "comment", "ns", "name", "attrs", "id_index",
                 "class_index", "style_index", "data", "vtype", "vdata")

    def __init__(self, ctype):
        self.ctype = ctype
        self.line = 0
        self.comment = 0xFFFFFFFF
        self.ns = 0xFFFFFFFF
        self.name = 0xFFFFFFFF
        self.attrs = []
        self.id_index = 0
        self.class_index = 0
        self.style_index = 0
        self.data = 0xFFFFFFFF
        self.vtype = 0
        self.vdata = 0


class Document:
    """一份解析后的 AXML 文档。"""

    def __init__(self):
        self.pool = StringPool([], True)
        self.resource_ids = []
        self.nodes = []

    # -------------------------------------------------- 解析
    @classmethod
    def parse(cls, data):
        if len(data) < 8:
            raise AxmlError("文件过短")
        rtype, header_size, total = struct.unpack_from("<HHI", data, 0)
        if rtype != RES_XML_TYPE:
            raise AxmlError("不是二进制 XML（type=0x%04x）" % rtype)
        end = min(total, len(data)) if total else len(data)
        doc = cls()
        off = header_size
        first_pool = True
        while off + 8 <= end:
            ctype, chdr, csize = struct.unpack_from("<HHI", data, off)
            if csize < 8 or off + csize > end:
                break
            if ctype == RES_STRING_POOL_TYPE and first_pool:
                doc.pool = StringPool.parse(data, off, csize)
                first_pool = False
            elif ctype == RES_XML_RESOURCE_MAP_TYPE:
                n = (csize - chdr) // 4
                doc.resource_ids = list(struct.unpack_from("<%dI" % n, data, off + chdr))
            elif ctype in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
                node = Node(ctype)
                node.line, node.comment = struct.unpack_from("<II", data, off + 8)
                node.ns, node.name = struct.unpack_from("<II", data, off + chdr)
                doc.nodes.append(node)
            elif ctype == RES_XML_START_ELEMENT_TYPE:
                node = Node(ctype)
                node.line, node.comment = struct.unpack_from("<II", data, off + 8)
                ext = off + chdr
                (node.ns, node.name, astart, asize, acount,
                 node.id_index, node.class_index, node.style_index) = struct.unpack_from(
                    "<IIHHHHHH", data, ext)
                for i in range(acount):
                    ap = ext + astart + i * asize
                    if ap + 20 > off + csize:
                        break
                    ans, aname, raw, vsize, res0, vtype, vdata = struct.unpack_from(
                        "<IIIHBBI", data, ap)
                    node.attrs.append(Attr(ans, aname, raw, vtype, vdata))
                doc.nodes.append(node)
            elif ctype == RES_XML_END_ELEMENT_TYPE:
                node = Node(ctype)
                node.line, node.comment = struct.unpack_from("<II", data, off + 8)
                node.ns, node.name = struct.unpack_from("<II", data, off + chdr)
                doc.nodes.append(node)
            elif ctype == RES_XML_CDATA_TYPE:
                node = Node(ctype)
                node.line, node.comment = struct.unpack_from("<II", data, off + 8)
                node.data, _vsize, _res0, node.vtype, node.vdata = struct.unpack_from(
                    "<IHBBI", data, off + chdr)
                doc.nodes.append(node)
            off += csize
        if not doc.nodes:
            raise AxmlError("未解析到任何节点")
        return doc

    # -------------------------------------------------- 序列化
    def to_bytes(self):
        pool = self.pool
        parts = [pool.to_bytes()]
        if self.resource_ids:
            n = len(self.resource_ids)
            body = struct.pack("<%dI" % n, *self.resource_ids)
            parts.append(struct.pack("<HHI", RES_XML_RESOURCE_MAP_TYPE,
                                     8, 8 + len(body)) + body)
        for nd in self.nodes:
            parts.append(self._node_bytes(nd))
        body = b"".join(parts)
        return struct.pack("<HHI", RES_XML_TYPE, 8, 8 + len(body)) + body

    @staticmethod
    def _node_bytes(nd):
        if nd.ctype in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            ext = struct.pack("<II", nd.ns, nd.name)
        elif nd.ctype == RES_XML_START_ELEMENT_TYPE:
            ext = struct.pack("<IIHHHHHH", nd.ns, nd.name, 20, 20,
                              len(nd.attrs), nd.id_index, nd.class_index, nd.style_index)
            for a in nd.attrs:
                ext += struct.pack("<IIIHBBI", a.ns, a.name, a.raw,
                                   8, 0, a.vtype, a.vdata)
        elif nd.ctype == RES_XML_END_ELEMENT_TYPE:
            ext = struct.pack("<II", nd.ns, nd.name)
        elif nd.ctype == RES_XML_CDATA_TYPE:
            ext = struct.pack("<IHBBI", nd.data, 8, 0, nd.vtype, nd.vdata)
        else:
            ext = b""
        total = 16 + len(ext)
        return struct.pack("<HHI", nd.ctype, 16, total) + struct.pack(
            "<II", nd.line, nd.comment) + ext

    # -------------------------------------------------- 查询
    def attr_name(self, attr):
        """返回属性的可读名（优先 resource id 映射，其次字符串）。"""
        if attr.name < len(self.resource_ids):
            rid = self.resource_ids[attr.name]
            if rid in ATTR_NAMES:
                return ATTR_NAMES[rid]
            if rid:
                return "0x%08x" % rid
        return self.pool.get(attr.name)

    def attr_res_id(self, attr):
        if attr.name < len(self.resource_ids):
            return self.resource_ids[attr.name]
        return 0

    def elements(self, name=None):
        """遍历起始元素，返回 (node, 父元素名)。"""
        stack = []
        out = []
        for nd in self.nodes:
            if nd.ctype == RES_XML_START_ELEMENT_TYPE:
                parent = stack[-1] if stack else None
                nm = self.pool.get(nd.name)
                if name is None or nm == name:
                    out.append((nd, parent))
                stack.append(nm)
            elif nd.ctype == RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()
        return out

    def find(self, name):
        hits = self.elements(name)
        return hits[0][0] if hits else None

    def get_attr(self, node, res_id, name=None):
        for a in node.attrs:
            if res_id and self.attr_res_id(a) == res_id:
                return a
            if name and self.pool.get(a.name) == name:
                return a
        return None

    def app_node(self):
        return self.find("application")

    def android_ns_index(self):
        for nd in self.nodes:
            if nd.ctype == RES_XML_START_NAMESPACE_TYPE:
                if self.pool.get(nd.name) == ANDROID_NS:
                    return nd.name
        return 0xFFFFFFFF

    # -------------------------------------------------- 变更
    def set_android_attr(self, node, res_id, *, string=None, integer=None,
                         boolean=None, attr_name=None):
        """设置（必要时新增）一个 android: 属性。"""
        attr = self.get_attr(node, res_id, attr_name)
        if string is not None:
            vtype, vdata = TYPE_STRING, self.pool.index(string)
            raw = vdata
        elif integer is not None:
            vtype, vdata, raw = TYPE_INT_DEC, int(integer) & 0xFFFFFFFF, 0xFFFFFFFF
        elif boolean is not None:
            vtype, vdata = TYPE_INT_BOOLEAN, 0xFFFFFFFF if boolean else 0
            raw = 0xFFFFFFFF
        else:
            raise AxmlError("未指定属性值")
        if attr is not None:
            attr.vtype, attr.vdata, attr.raw = vtype, vdata, raw
            return
        ns = self.android_ns_index()
        name_idx = self.pool.index(attr_name or ATTR_NAMES.get(res_id, "name"))
        node.attrs.append(Attr(ns, name_idx, raw, vtype, vdata))
        # resource map 需要覆盖新增的 name 索引，否则运行时不认作 android: 属性
        if name_idx >= len(self.resource_ids):
            self.resource_ids.extend([0] * (name_idx - len(self.resource_ids) + 1))
        if res_id:
            self.resource_ids[name_idx] = res_id

    def remove_attr(self, node, res_id, name=None):
        for i, a in enumerate(node.attrs):
            if (res_id and self.attr_res_id(a) == res_id) or \
               (name and self.pool.get(a.name) == name):
                del node.attrs[i]
                if node.id_index > i:
                    node.id_index -= 1
                if node.class_index > i:
                    node.class_index -= 1
                if node.style_index > i:
                    node.style_index -= 1
                return True
        return False


# ---------------------------------------------------------------- 便捷入口
def parse_file(path):
    with open(path, "rb") as fh:
        return Document.parse(fh.read())


def manifest_info(doc: Document):
    """抽取常用清单信息。"""
    info = {
        "package": "", "version_name": "", "version_code": 0,
        "min_sdk": None, "target_sdk": None, "app_class": "",
        "label": None, "permissions": [], "activities": [],
        "services": [], "receivers": [], "providers": [],
        "debuggable": None, "allow_backup": None, "features": [],
    }
    root = doc.find("manifest")
    if root is None:
        raise AxmlError("缺少 manifest 根节点")
    a = doc.get_attr(root, 0, "package")
    if a is not None:
        info["package"] = doc.pool.get(a.vdata) if a.vtype == TYPE_STRING else ""
    a = doc.get_attr(root, ATTR_VERSION_NAME, "versionName")
    if a is not None:
        s = a.as_str(doc.pool)
        info["version_name"] = s if s is not None else str(a.as_int(doc.pool) or "")
    a = doc.get_attr(root, ATTR_VERSION_CODE, "versionCode")
    if a is not None:
        info["version_code"] = a.as_int(doc.pool) or 0

    for tag, key in (("uses-permission", "permissions"), ("uses-feature", "features"),
                     ("activity", "activities"), ("service", "services"),
                     ("receiver", "receivers"), ("provider", "providers")):
        for nd, _p in doc.elements(tag):
            nm = doc.get_attr(nd, ATTR_NAME, "name")
            if nm is not None:
                val = nm.as_str(doc.pool)
                if val:
                    info[key].append(val)

    use_sdk = doc.find("uses-sdk")
    if use_sdk is not None:
        a = doc.get_attr(use_sdk, ATTR_MIN_SDK, "minSdkVersion")
        if a is not None:
            info["min_sdk"] = a.as_int(doc.pool)
        a = doc.get_attr(use_sdk, ATTR_TARGET_SDK, "targetSdkVersion")
        if a is not None:
            info["target_sdk"] = a.as_int(doc.pool)

    app = doc.app_node()
    if app is not None:
        a = doc.get_attr(app, ATTR_NAME, "name")
        if a is not None:
            info["app_class"] = a.as_str(doc.pool) or ""
        a = doc.get_attr(app, ATTR_LABEL, "label")
        if a is not None:
            info["label"] = a.as_str(doc.pool)
        a = doc.get_attr(app, ATTR_DEBUGGABLE, "debuggable")
        if a is not None:
            info["debuggable"] = bool(a.vdata)
        a = doc.get_attr(app, ATTR_ALLOW_BACKUP, "allowBackup")
        if a is not None:
            info["allow_backup"] = bool(a.vdata)
    return info


def set_application_class(doc: Document, class_name: str):
    """把 <application android:name> 指向壳类。"""
    app = doc.app_node()
    if app is None:
        raise AxmlError("清单中没有 <application> 节点")
    doc.set_android_attr(app, ATTR_NAME, string=class_name, attr_name="name")
    return app
