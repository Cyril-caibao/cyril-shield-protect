"""HMAC-SHA256 计数器流加密 + 载荷容器。

Python 与 Java（javax.crypto.Mac）两侧逐字节一致：
    block_i = HMAC-SHA256(key, nonce || uint64_be(i))
    ct      = pt XOR ks

密钥派生也不是"一个数组就是密钥"，而是两级：
    root = HMAC-SHA256(salt_root, 64 字节材料)
    part = HMAC-SHA256(HMAC-SHA256(root, 0x11 || idx), salt_part)

载荷容器不带任何头部魔数，密文直接开头，nonce 与校验码附在尾部：
    [ cipher | nonce(16) | tag(8) ]
tag = HMAC-SHA256(key, 0x74 || nonce)[:8]，解包前先验，错包直接放弃。

只用 hashlib/hmac（底层是 C 实现），大文件也不会拖慢加固速度；
不引入第三方依赖，Java 侧只需 Mac + MessageDigest，全 API 可用。
"""

from __future__ import annotations

import hashlib
import hmac
import struct

BLOCK = 32
TRAILER = 24        # nonce(16) + tag(8)
NONCE = 16


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    base = hmac.new(key, nonce, hashlib.sha256)
    out = bytearray()
    ctr = 0
    while len(out) < length:
        h = base.copy()
        h.update(ctr.to_bytes(8, "big"))
        out += h.digest()
        ctr += 1
    return bytes(out[:length])


def _xor(data: bytes, key: bytes, nonce: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return b""
    ks = keystream(key, nonce, n)
    # 大整数异或在 C 层完成，几十 MB 也是毫秒级
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(n, "big")


def encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return _xor(data, key, nonce)


def decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return _xor(data, key, nonce)


def derive(master: bytes, label: bytes) -> bytes:
    return hmac.new(master, label, hashlib.sha256).digest()


# ------------------------------------------------------------ 密钥派生
def root_key(salt: bytes, material: bytes) -> bytes:
    """把随机材料压成根密钥。材料是运行期按组异或重建的，单看常量数组不构成密钥。"""
    return hmac.new(salt, material, hashlib.sha256).digest()


def sub_key(root: bytes, salt: bytes, idx: int) -> bytes:
    """根密钥 → 每一段载荷的独立子密钥（两级，互不可由兄弟段推出）。"""
    node = hmac.new(root, bytes([0x11]) + struct.pack(">H", idx & 0xFFFF),
                    hashlib.sha256).digest()
    return hmac.new(node, salt, hashlib.sha256).digest()


def tag(key: bytes, nonce: bytes, body: bytes = b"") -> bytes:
    """整段密文的完整性校验码（覆盖 nonce 与全部密文）。"""
    mac = hmac.new(key, bytes([0x74]) + nonce, hashlib.sha256)
    mac.update(body)
    return mac.digest()[:8]


# ------------------------------------------------------------ 载荷容器
def seal(key: bytes, nonce: bytes, plain: bytes) -> bytes:
    """封装一段载荷：密文在前，nonce 与校验码在尾部，无固定头部特征。"""
    if len(nonce) != NONCE:
        raise ValueError("nonce 长度必须是 16 字节")
    body = encrypt(key, nonce, plain)
    return body + nonce + tag(key, nonce, body)


def open_sealed(key: bytes, blob: bytes) -> bytes:
    """解开封装；长度不足或校验码不符时返回空，不做任何猜测性解密。"""
    if len(blob) <= TRAILER:
        return b""
    body = blob[:-TRAILER]
    nonce = blob[-TRAILER:-8]
    if not hmac.compare_digest(tag(key, nonce, body), blob[-8:]):
        return b""
    return decrypt(key, nonce, body)
