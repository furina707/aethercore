# SPDX-License-Identifier: MIT
# AetherCore - 纯 Python 零依赖 MaxMind DB (MMDB) 解析器与 GeoIP 引擎
#
# 功能：
#   - 原生读取与解析 geo/Country.mmdb 二进制树与数据段 (规范遵循 MaxMind DB 格式)
#   - 支持 IPv4 与 IPv6 查询
#   - 判定 IP 是否为国内目标 (CN) 或私有地址，供核心直连决策

import os
import socket
import struct
import ipaddress

class MMDBReader:
    """纯 Python MaxMind DB 二进制解析器 (零外部库依赖)"""

    def __init__(self, db_path: str):
        self.path = db_path
        with open(db_path, "rb") as f:
            self._data = f.read()

        idx = self._data.rfind(b"\xab\xcd\xefMaxMind.com")
        if idx == -1:
            raise ValueError(f"Invalid MMDB file (missing metadata marker): {db_path}")

        self._meta_start = idx + 14
        self.metadata, _ = self._decode(self._meta_start, self._meta_start)

        self.node_count = self.metadata.get("node_count", 0)
        self.record_size = self.metadata.get("record_size", 24)
        self.ip_version = self.metadata.get("ip_version", 6)

        # 节点字节大小计算：如 24 位 record = 3 字节，每个节点 2 个 record = 6 字节
        self.node_bytes = self.node_count * (self.record_size * 2 // 8)
        # 数据段紧随节点树之后，有 16 字节分隔符
        self.data_section_offset = self.node_bytes + 16

    def _decode(self, offset: int, base_offset: int) -> tuple:
        """递归解码 MMDB 数据字段，返回 (value, next_offset)"""
        if offset >= len(self._data):
            return None, len(self._data)

        ctrl = self._data[offset]
        offset += 1
        t = ctrl >> 5

        if t == 1:  # Pointer 指针类型
            ptype = (ctrl >> 3) & 0x03
            if ptype == 0:
                ptr = ((ctrl & 0x07) << 8) | self._data[offset]
                offset += 1
            elif ptype == 1:
                ptr = 2048 + (((ctrl & 0x07) << 16) | (self._data[offset] << 8) | self._data[offset + 1])
                offset += 2
            elif ptype == 2:
                ptr = 526336 + (((ctrl & 0x07) << 24) | (self._data[offset] << 16) |
                               (self._data[offset + 1] << 8) | self._data[offset + 2])
                offset += 3
            else:
                ptr = struct.unpack(">I", self._data[offset:offset + 4])[0]
                offset += 4
            val, _ = self._decode(base_offset + ptr, base_offset)
            return val, offset

        sz = ctrl & 0x1F
        if t == 0:  # 扩展类型
            t = 7 + self._data[offset]
            offset += 1

        if sz == 29:
            sz = 29 + self._data[offset]
            offset += 1
        elif sz == 30:
            sz = 285 + struct.unpack(">H", self._data[offset:offset + 2])[0]
            offset += 2
        elif sz == 31:
            sz = 65821 + struct.unpack(">I", b"\x00" + self._data[offset:offset + 3])[0]
            offset += 3

        if t == 2:  # UTF-8 string
            val = self._data[offset:offset + sz].decode("utf-8", errors="replace")
            return val, offset + sz
        elif t in (5, 9):  # unsigned int
            val = int.from_bytes(self._data[offset:offset + sz], "big") if sz else 0
            return val, offset + sz
        elif t == 6:  # signed 32-bit int
            val = int.from_bytes(self._data[offset:offset + sz], "big", signed=True) if sz else 0
            return val, offset + sz
        elif t == 7:  # map / dict
            res = {}
            for _ in range(sz):
                k, offset = self._decode(offset, base_offset)
                v, offset = self._decode(offset, base_offset)
                res[k] = v
            return res, offset
        elif t == 11:  # array
            res = []
            for _ in range(sz):
                v, offset = self._decode(offset, base_offset)
                res.append(v)
            return res, offset
        elif t == 14:  # boolean
            return sz > 0, offset

        # 其它未处理类型，跳过指定长度
        return None, offset + sz

    def lookup(self, ip_str: str) -> dict:
        """查询 IP 信息字典，未找到返回 None"""
        try:
            if ":" in ip_str:
                raw = socket.inet_pton(socket.AF_INET6, ip_str)
            else:
                if self.ip_version == 6:
                    # IPv4 映射为 IPv6：96 个零比特 + 32 位 IPv4
                    raw = b"\x00" * 12 + socket.inet_aton(ip_str)
                else:
                    raw = socket.inet_aton(ip_str)
        except Exception:
            return None

        node = 0
        node_count = self.node_count

        if self.record_size == 24:
            for byte in raw:
                for bit in range(7, -1, -1):
                    flag = (byte >> bit) & 1
                    off = node * 6 + (3 if flag else 0)
                    node = (self._data[off] << 16) | (self._data[off + 1] << 8) | self._data[off + 2]
                    if node >= node_count:
                        break
                if node >= node_count:
                    break
        elif self.record_size == 28:
            for byte in raw:
                for bit in range(7, -1, -1):
                    flag = (byte >> bit) & 1
                    off = node * 7
                    if flag:
                        node = ((self._data[off + 3] & 0x0F) << 24) | (self._data[off + 4] << 16) | (self._data[off + 5] << 8) | self._data[off + 6]
                    else:
                        node = ((self._data[off + 3] >> 4) << 24) | (self._data[off] << 16) | (self._data[off + 1] << 8) | self._data[off + 2]
                    if node >= node_count:
                        break
                if node >= node_count:
                    break
        else:
            return None

        if node == node_count:
            return None  # 记录为空

        val_offset = (node - node_count) - 16
        record, _ = self._decode(self.data_section_offset + val_offset, self.data_section_offset)
        return record


# ---- 全局单例与便捷接口 ----
_G_GEOIP = None
_G_LOADED = False

def get_geoip_instance(data_dir: str = None) -> MMDBReader:
    """获取或初始化 GeoIP 实例"""
    global _G_GEOIP, _G_LOADED
    if _G_LOADED:
        return _G_GEOIP

    candidates = []
    if data_dir:
        candidates.append(os.path.join(data_dir, "Country.mmdb"))
        candidates.append(os.path.join(data_dir, "..", "geo", "Country.mmdb"))
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates.append(os.path.join(script_dir, "..", "geo", "Country.mmdb"))
    candidates.append(os.path.join(os.getcwd(), "geo", "Country.mmdb"))

    for path in candidates:
        if os.path.exists(path):
            try:
                _G_GEOIP = MMDBReader(os.path.abspath(path))
                _G_LOADED = True
                return _G_GEOIP
            except Exception:
                continue

    _G_LOADED = True
    return None


def country_code(ip: str, data_dir: str = None) -> str:
    """获取 IP 所在国家 ISO 代码 (如 CN, US 等)，私网或未知返回空"""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback:
            return "PRIVATE"
    except Exception:
        return ""

    reader = get_geoip_instance(data_dir)
    if not reader:
        return ""

    rec = reader.lookup(ip)
    if rec and isinstance(rec, dict):
        country = rec.get("country", {})
        if isinstance(country, dict):
            return country.get("iso_code", "")
    return ""


def is_cn(ip: str, data_dir: str = None) -> bool:
    """判断 IP 是否为中国大陆地址 (或内网保留地址)"""
    code = country_code(ip, data_dir)
    return code in ("CN", "PRIVATE")
