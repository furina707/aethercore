# SPDX-License-Identifier: MIT
# AetherCore - 纯 Python WinTun TUN 虚拟网卡引擎 (替代 aether_tun.exe / tun_wintun.c)
#
# 功能：
#   - 使用 ctypes 加载 wintun.dll，创建/打开 Wintun 虚拟网卡
#   - 通过 iphlpapi.dll 原生配置 IP 地址、MTU、路由 (零子进程)
#   - 零拷贝环形缓冲区读写 (Ring Buffer)
#   - Fake-IP 路由注入 (198.18.0.0/15) + 默认路由接管 (v4/v6)
#   - 物理网卡探测 (防回环绑定源地址)
#
# 依赖:
#   - wintun.dll (位于当前目录或系统目录)
#   - 管理员权限 (创建网卡、配置路由需要)

import os
import sys
import ctypes
import ctypes.wintypes
import threading
import time
import struct
import socket
import ipaddress
from ctypes import wintypes

# Python 3.15+ 的 ctypes.wintypes 裁剪了部分类型，这里兜底补齐
wintypes.ULONG64 = getattr(wintypes, "ULONG64", ctypes.c_uint64)
wintypes.DWORD64 = getattr(wintypes, "DWORD64", ctypes.c_uint64)
wintypes.UINT8 = getattr(wintypes, "UINT8", ctypes.c_ubyte)

# ---- WinTUN DLL 函数类型定义 ----
# 参考 wintun.h 头文件

WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
WINTUN_SESSION_HANDLE = ctypes.c_void_p


class GUID(ctypes.Structure):
    """ctypes.wintypes.GUID 在部分 Python 版本缺失，自定义等价结构"""
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", wintypes.BYTE * 8),
    ]


# WINTUN_SET_LOGGER_FUNC
WINTUN_LOGGER_CALLBACK = ctypes.WINFUNCTYPE(
    None,
    wintypes.DWORD,         # Level
    wintypes.DWORD64,       # Timestamp
    wintypes.LPCWSTR,       # Message
)

WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF

# ---- 地址族常量 ----
AF_INET_WIN = 2
AF_INET6_WIN = 23

# Fake-IP 网段 (与 tun_dns.py / aether_core.py 保持一致)
FAKE_V4_NET = "198.18.0.0/15"
FAKE_V6_NET = "fdfe:dcba:9876::/48"
TUN_V4_IP = "198.18.0.1"
TUN_V4_MASK = "255.254.0.0"
TUN_V6_IP = "fdfe:dcba:9876::1"
TUN_V6_PREFIX = 126


def is_fake_v4(ip: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(FAKE_V4_NET)
    except Exception:
        return False


def is_fake_v6(ip: str) -> bool:
    try:
        return ipaddress.IPv6Address(ip) in ipaddress.IPv6Network(FAKE_V6_NET)
    except Exception:
        return False


def is_fake_ip(ip: str) -> bool:
    return is_fake_v4(ip) or is_fake_v6(ip)


# ---- WinTUN 引擎封装 ----
class WintunEngine:
    """加载 wintun.dll 并解析所有函数指针"""

    def __init__(self):
        self._module = None
        self._logger_cb = None

    def load(self, dll_path=None):
        """加载 wintun.dll"""
        if self._module:
            return True

        search_paths = []
        if dll_path:
            search_paths.append(dll_path)
        # 仅查找模块同级目录 (core/wintun.dll)
        search_paths.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "wintun.dll"))

        for path in search_paths:
            try:
                self._module = ctypes.WinDLL(path)
                break
            except OSError:
                continue

        if not self._module:
            return False

        mod = self._module
        try:
            mod.WintunCreateAdapter.restype = ctypes.c_void_p
            mod.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(GUID)]

            mod.WintunCloseAdapter.restype = None
            mod.WintunCloseAdapter.argtypes = [ctypes.c_void_p]

            mod.WintunOpenAdapter.restype = ctypes.c_void_p
            mod.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]

            mod.WintunGetAdapterLUID.restype = None
            mod.WintunGetAdapterLUID.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

            mod.WintunGetRunningDriverVersion.restype = wintypes.DWORD
            mod.WintunGetRunningDriverVersion.argtypes = []

            mod.WintunDeleteDriver.restype = wintypes.BOOL
            mod.WintunDeleteDriver.argtypes = []

            mod.WintunSetLogger.restype = None
            mod.WintunSetLogger.argtypes = [WINTUN_LOGGER_CALLBACK]

            mod.WintunStartSession.restype = ctypes.c_void_p
            mod.WintunStartSession.argtypes = [ctypes.c_void_p, wintypes.DWORD]

            mod.WintunEndSession.restype = None
            mod.WintunEndSession.argtypes = [ctypes.c_void_p]

            mod.WintunGetReadWaitEvent.restype = wintypes.HANDLE
            mod.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]

            mod.WintunReceivePacket.restype = ctypes.c_void_p
            mod.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]

            mod.WintunReleaseReceivePacket.restype = None
            mod.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

            mod.WintunAllocateSendPacket.restype = ctypes.c_void_p
            mod.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, wintypes.DWORD]

            mod.WintunSendPacket.restype = None
            mod.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        except AttributeError:
            self._module = None
            return False

        # 设置默认日志回调
        self._set_default_logger()
        return True

    def _set_default_logger(self):
        @WINTUN_LOGGER_CALLBACK
        def _log_cb(level, timestamp, message):
            level_map = {0: "[INFO]", 1: "[WARN]", 2: "[ERR ]"}
            prefix = level_map.get(level, "[INFO]")
            print(f"[Wintun] {prefix}: {message}", file=sys.stderr)

        self._logger_cb = _log_cb
        self._module.WintunSetLogger(_log_cb)

    def __getattr__(self, name):
        if self._module and hasattr(self._module, name):
            return getattr(self._module, name)
        raise AttributeError(f"WintunEngine has no attribute {name}")

    def unload(self):
        if self._module:
            self._module = None
            self._logger_cb = None


# 全局引擎实例
_g_engine = WintunEngine()


# ---- IP Helper API (iphlpapi.dll) 封装 ----
class NET_LUID(ctypes.Structure):
    _fields_ = [
        ("Value", wintypes.ULONG64),
    ]


class INET_ADDR(ctypes.Structure):
    _fields_ = [
        ("S_un", wintypes.ULONG),
    ]


class INET_ADDR6(ctypes.Structure):
    _fields_ = [
        ("Bytes", wintypes.BYTE * 16),
    ]


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", INET_ADDR),
        ("sin_zero", wintypes.BYTE * 8),
    ]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [
        ("sin6_family", wintypes.USHORT),
        ("sin6_port", wintypes.USHORT),
        ("sin6_flowinfo", wintypes.ULONG),
        ("sin6_addr", INET_ADDR6),
        ("sin6_scope_id", wintypes.ULONG),
    ]


# SOCKADDR_INET: 对齐 winsock2.h / ws2ipdef.h 中的联合体定义 (union)
class SOCKADDR_INET(ctypes.Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", wintypes.USHORT),
    ]


def sockaddr_inet_v4(ip_str: str) -> SOCKADDR_INET:
    """构造 AF_INET 的 SOCKADDR_INET"""
    sa = SOCKADDR_INET()
    sa.Ipv4.sin_family = AF_INET_WIN
    sa.Ipv4.sin_port = 0
    sa.Ipv4.sin_addr.S_un = struct.unpack("<I", socket.inet_aton(ip_str))[0]
    return sa


def sockaddr_inet_v6(ip_str: str) -> SOCKADDR_INET:
    """构造 AF_INET6 的 SOCKADDR_INET"""
    sa = SOCKADDR_INET()
    sa.Ipv6.sin6_family = AF_INET6_WIN
    sa.Ipv6.sin6_port = 0
    sa.Ipv6.sin6_addr.Bytes = (wintypes.BYTE * 16)(*socket.inet_pton(socket.AF_INET6, ip_str))
    return sa


class IP_ADDRESS_PREFIX(ctypes.Structure):
    _fields_ = [
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", wintypes.UINT8),
    ]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("SitePrefixLength", wintypes.UINT8),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("Metric", wintypes.ULONG),
        ("Protocol", wintypes.ULONG),
        ("Loopback", wintypes.BOOLEAN),
        ("AutoconfigureAddress", wintypes.BOOLEAN),
        ("Publish", wintypes.BOOLEAN),
        ("Immortal", wintypes.BOOLEAN),
        ("Age", wintypes.ULONG),
        ("Origin", wintypes.ULONG),
    ]


class MIB_UNICASTIPADDRESS_ROW(ctypes.Structure):
    _fields_ = [
        ("Address", SOCKADDR_INET),
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("PrefixOrigin", wintypes.ULONG),
        ("SuffixOrigin", wintypes.ULONG),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("OnLinkPrefixLength", wintypes.UINT8),
        ("SkipAsSource", wintypes.BOOLEAN),
        ("DadState", wintypes.ULONG),
        ("ScopeId", wintypes.ULONG),
        ("CreationTimeStamp", wintypes.ULONG64),
    ]


class MIB_IPINTERFACE_ROW(ctypes.Structure):
    _fields_ = [
        ("Family", wintypes.USHORT),
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("MaxReassemblySize", wintypes.ULONG),
        ("InterfaceIdentifier", wintypes.ULONG64),
        ("MinRouterAdvertisementInterval", wintypes.ULONG),
        ("MaxRouterAdvertisementInterval", wintypes.ULONG),
        ("AdvertisingEnabled", wintypes.BOOLEAN),
        ("ForwardingEnabled", wintypes.BOOLEAN),
        ("WeakHostSend", wintypes.BOOLEAN),
        ("WeakHostReceive", wintypes.BOOLEAN),
        ("UseAutomaticMetric", wintypes.BOOLEAN),
        ("UseNeighborUnreachabilityDetection", wintypes.BOOLEAN),
        ("ManagedAddressConfigurationSupported", wintypes.BOOLEAN),
        ("OtherStatefulConfigurationSupported", wintypes.BOOLEAN),
        ("AdvertiseDefaultRoute", wintypes.BOOLEAN),
        ("RouterDiscoveryBehavior", wintypes.ULONG),
        ("DadTransmits", wintypes.ULONG),
        ("BaseReachableTime", wintypes.ULONG),
        ("RetransmitTime", wintypes.ULONG),
        ("PathMtuDiscoveryTimeout", wintypes.ULONG),
        ("LinkLocalAddressBehavior", wintypes.ULONG),
        ("LinkLocalAddressTimeout", wintypes.ULONG),
        ("ZoneIndices", wintypes.ULONG * 16),
        ("SiteId", wintypes.ULONG),
        ("NlMtu", wintypes.ULONG),
        ("ReassemblySize", wintypes.ULONG),
        ("ReassembleTimeouts", wintypes.ULONG),
        ("DisableUnicastSourcePacketForwarding", wintypes.BOOLEAN),
        ("DisableMulticastSourcePacketForwarding", wintypes.BOOLEAN),
        ("DisableSourcePacketForwarding", wintypes.BOOLEAN),
        ("Protocol", wintypes.ULONG),
        ("MinMtu", wintypes.ULONG),
        ("Connected", wintypes.BOOLEAN),
        ("SupportsWakeUpPatterns", wintypes.BOOLEAN),
        ("SupportsNeighborDiscovery", wintypes.BOOLEAN),
        ("SupportsRouterDiscovery", wintypes.BOOLEAN),
        ("ReachableTime", wintypes.ULONG),
        ("TransmitOffload", wintypes.ULONG),
        ("ReceiveOffload", wintypes.ULONG),
        ("DisableDefaultRoutes", wintypes.BOOLEAN),
        ("NlMtuDiscoveryEnabled", wintypes.BOOLEAN),
        ("NlMtuDiscoveryBlackListTimeout", wintypes.ULONG),
        ("NlMtuDiscoveryMinimum", wintypes.ULONG),
    ]


# 旧式 MIB_IPFORWARDROW (GetBestRoute 使用)
class MIB_IPFORWARDROW(ctypes.Structure):
    _fields_ = [
        ("dwForwardDest", wintypes.DWORD),
        ("dwForwardMask", wintypes.DWORD),
        ("dwForwardPolicy", wintypes.DWORD),
        ("dwForwardNextHop", wintypes.DWORD),
        ("dwForwardIfIndex", wintypes.DWORD),
        ("dwForwardType", wintypes.DWORD),
        ("dwForwardProto", wintypes.DWORD),
        ("dwForwardAge", wintypes.DWORD),
        ("dwForwardNextHopAS", wintypes.DWORD),
        ("dwForwardMetric1", wintypes.DWORD),
        ("dwForwardMetric2", wintypes.DWORD),
        ("dwForwardMetric3", wintypes.DWORD),
        ("dwForwardMetric4", wintypes.DWORD),
        ("dwForwardMetric5", wintypes.DWORD),
    ]


MAX_ADAPTER_NAME_LENGTH = 256
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_ADDRESS_LENGTH = 8


class IP_ADDR_STRING(ctypes.Structure):
    pass


IP_ADDR_STRING._fields_ = [
    ("Next", ctypes.POINTER(IP_ADDR_STRING)),
    ("IpAddress", ctypes.c_char * 16),
    ("IpMask", ctypes.c_char * 16),
    ("Context", wintypes.DWORD),
]


class IP_ADAPTER_INFO(ctypes.Structure):
    pass


IP_ADAPTER_INFO._fields_ = [
    ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
    ("ComboIndex", wintypes.DWORD),
    ("AdapterName", ctypes.c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
    ("Description", ctypes.c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
    ("AddressLength", wintypes.UINT),
    ("Address", wintypes.BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("Index", wintypes.DWORD),
    ("Type", wintypes.UINT),
    ("DhcpEnabled", wintypes.UINT),
    ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
    ("IpAddressList", IP_ADDR_STRING),
    ("GatewayList", IP_ADDR_STRING),
    ("DhcpServer", IP_ADDR_STRING),
    ("HaveWins", wintypes.BOOL),
    ("PrimaryWinsServer", IP_ADDR_STRING),
    ("SecondaryWinsServer", IP_ADDR_STRING),
    ("LeaseObtained", ctypes.c_int64),
    ("LeaseExpires", ctypes.c_int64),
]


class _IPHLPAPI:
    """iphlpapi.dll 封装 (延迟加载)"""

    def __init__(self):
        self._dll = None
        self._ntdll = None

    def _ensure_loaded(self):
        if self._dll is not None:
            return True
        try:
            self._dll = ctypes.WinDLL("iphlpapi")
            self._ntdll = ctypes.WinDLL("ntdll")
        except OSError:
            return False
        return True

    def ipv4_string_to_addr(self, ip_str):
        addr = INET_ADDR()
        term = ctypes.c_char_p()
        ret = self._ntdll.RtlIpv4StringToAddressA(
            ip_str.encode("ascii"), True, ctypes.byref(term), ctypes.byref(addr))
        if ret != 0:
            raise ValueError(f"Invalid IP address: {ip_str}")
        return addr

    def inet_addr(self, ip_str):
        """'198.18.0.0' -> ULONG (网络字节序)"""
        addr = self.ipv4_string_to_addr(ip_str)
        return addr.S_un

    def set_mtu_and_metric(self, luid, mtu, family=AF_INET_WIN):
        """设置网卡 MTU 和跃点数"""
        if not self._ensure_loaded():
            return False
        row = MIB_IPINTERFACE_ROW()
        self._dll.InitializeIpInterfaceEntry(ctypes.byref(row))
        row.Family = family
        row.InterfaceLuid = luid
        if self._dll.GetIpInterfaceEntry(ctypes.byref(row)) == 0:  # NO_ERROR
            row.NlMtu = mtu
            row.UseAutomaticMetric = False
            row.Metric = 1  # 最高优先级
            self._dll.SetIpInterfaceEntry(ctypes.byref(row))
            return True
        return False

    def set_ip_address(self, luid, ip_str, mask_str=None):
        """设置网卡单播 IP 地址 (自动识别 v4/v6)"""
        if not self._ensure_loaded():
            return False
        row = MIB_UNICASTIPADDRESS_ROW()
        self._dll.InitializeUnicastIpAddressEntry(ctypes.byref(row))
        row.InterfaceLuid = luid
        if ":" in ip_str:
            row.Address = sockaddr_inet_v6(ip_str)
            row.OnLinkPrefixLength = int(mask_str) if mask_str else 64
        else:
            row.Address = sockaddr_inet_v4(ip_str)
            row.OnLinkPrefixLength = self._mask_to_prefix(mask_str) if mask_str else 24
        row.DadState = 1  # IpDadStatePreferred
        res = self._dll.CreateUnicastIpAddressEntry(ctypes.byref(row))
        return res == 0 or res == 0x000000B7  # NO_ERROR or ERROR_OBJECT_ALREADY_EXISTS

    def add_route(self, luid, dest_str, prefix_len, gw_str, metric=1,
                  if_index=0):
        """添加静态路由 (自动识别 v4/v6；gw_str 为 None 时表示 on-link)"""
        if not self._ensure_loaded():
            return False, None
        row = MIB_IPFORWARD_ROW2()
        row.InterfaceLuid = luid
        if if_index:
            row.InterfaceIndex = if_index
        if ":" in dest_str:
            row.DestinationPrefix.Prefix = sockaddr_inet_v6(dest_str)
            if gw_str:
                row.NextHop = sockaddr_inet_v6(gw_str)
        else:
            row.DestinationPrefix.Prefix = sockaddr_inet_v4(dest_str)
            if gw_str:
                row.NextHop = sockaddr_inet_v4(gw_str)
        row.DestinationPrefix.PrefixLength = prefix_len
        row.Metric = metric
        row.Protocol = 3  # MIB_IPPROTO_NETMGMT
        row.ValidLifetime = 0xFFFFFFFF
        row.PreferredLifetime = 0xFFFFFFFF
        res = self._dll.CreateIpForwardEntry2(ctypes.byref(row))
        if res != 0 and res != 0x000000B7 and gw_str:
            if ':' in dest_str:
                row.NextHop = sockaddr_inet_v6('::')
            else:
                row.NextHop = sockaddr_inet_v4('0.0.0.0')
            res = self._dll.CreateIpForwardEntry2(ctypes.byref(row))
        return res == 0 or res == 0x000000B7, row

    def delete_route(self, row):
        """删除之前添加的路由"""
        if not self._ensure_loaded():
            return False
        self._dll.DeleteIpForwardEntry2(ctypes.byref(row))
        return True

    def get_best_route_v4(self, dest_ip: str):
        """GetBestRoute: 返回 (next_hop_str, if_index) 或 (None, 0)"""
        if not self._ensure_loaded():
            return None, 0
        row = MIB_IPFORWARDROW()
        rc = self._dll.GetBestRoute(
            wintypes.DWORD(self.inet_addr(dest_ip)),
            wintypes.DWORD(0),
            ctypes.byref(row))
        if rc != 0:
            return None, 0
        nexthop = socket.inet_ntoa(struct.pack("<I", row.dwForwardNextHop))
        return nexthop, row.dwForwardIfIndex

    def ifindex_to_luid(self, if_index: int):
        """ConvertInterfaceIndexToLuid"""
        if not self._ensure_loaded():
            return None
        luid = NET_LUID()
        rc = self._dll.ConvertInterfaceIndexToLuid(
            wintypes.ULONG(if_index), ctypes.byref(luid))
        return luid if rc == 0 else None

    def get_ipv4_addr_for_ifindex(self, if_index: int):
        """GetIpAddrTable: 查找指定接口的 IPv4 地址"""
        if not self._ensure_loaded():
            return None
        size = wintypes.ULONG(0)
        self._dll.GetIpAddrTable(None, ctypes.byref(size), False)
        if size.value <= 0:
            return None
        buf = ctypes.create_string_buffer(size.value)
        if self._dll.GetIpAddrTable(buf, ctypes.byref(size), False) != 0:
            return None
        num = struct.unpack_from("I", buf, 0)[0]
        for i in range(num):
            off = 4 + i * 24  # MIB_IPADDRROW = 24 字节
            dw_addr, _mask, dw_if = struct.unpack_from("III", buf, off)
            if dw_if == if_index:
                return socket.inet_ntoa(struct.pack("<I", dw_addr))
        return None

    @staticmethod
    def _mask_to_prefix(mask_str):
        """255.254.0.0 -> 15"""
        parts = mask_str.split(".")
        val = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
        return bin(val).count("1")


# 全局 iphlpapi 实例
_g_iphlp = _IPHLPAPI()


def detect_physical_network():
    """在安装接管路由【之前】探测物理网络信息。

    返回 dict(v4_ip, v6_ip, gw_v4, if_index_v4)；探测失败的字段为 None。
    优先通过 GetAdaptersInfo 枚举物理适配器（排除虚假/虚拟网卡及 Fake-IP），
    兜底通过 GetBestRoute + UDP getsockname 选路。
    """
    info = {"v4_ip": None, "v6_ip": None, "gw_v4": None, "if_index_v4": 0}

    # 1. 优先使用 GetAdaptersInfo 查找真实的物理网卡及网关
    try:
        if _g_iphlp._ensure_loaded():
            buflen = wintypes.ULONG(0)
            _g_iphlp._dll.GetAdaptersInfo(None, ctypes.byref(buflen))
            if buflen.value > 0:
                buf = ctypes.create_string_buffer(buflen.value)
                if _g_iphlp._dll.GetAdaptersInfo(
                        ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO)),
                        ctypes.byref(buflen)) == 0:
                    ptr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_INFO))
                    candidates = []
                    virtual_keywords = (
                        "wintun", "tunnel", "meta", "tap", "wireguard",
                        "tailscale", "loopback", "hyper-v", "virtual", "vpn"
                    )
                    while ptr:
                        cur = ptr.contents
                        desc = cur.Description.decode("latin-1", errors="ignore").lower()
                        ip = cur.IpAddressList.IpAddress.decode("ascii").strip("\x00")
                        gw = cur.GatewayList.IpAddress.decode("ascii").strip("\x00")
                        idx = cur.Index
                        itype = cur.Type
                        is_virtual = any(k in desc for k in virtual_keywords) or (itype == 53)
                        if (ip and ip != "0.0.0.0" and not is_fake_v4(ip) and
                                gw and gw != "0.0.0.0" and not is_fake_v4(gw)):
                            candidates.append({
                                "v4_ip": ip,
                                "gw_v4": gw,
                                "if_index_v4": idx,
                                "is_virtual": is_virtual,
                                "type": itype,
                            })
                        ptr = cur.Next
                    if candidates:
                        # 排序优先级: 真实物理网卡 > 虚拟网卡; Wi-Fi(71)/Ethernet(6) > 其他类型
                        candidates.sort(
                            key=lambda c: (c["is_virtual"], 0 if c["type"] in (6, 71) else 1)
                        )
                        best = candidates[0]
                        info["v4_ip"] = best["v4_ip"]
                        info["gw_v4"] = best["gw_v4"]
                        info["if_index_v4"] = best["if_index_v4"]
    except Exception:
        pass

    # 2. 兜底探测: 若 GetAdaptersInfo 未找到有效 IP，尝试 UDP connect
    if not info["v4_ip"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 53))
            v4 = s.getsockname()[0]
            s.close()
            if v4 and not is_fake_v4(v4):
                info["v4_ip"] = v4
        except Exception:
            pass

    # 3. 兜底网关: 若未拿到网关，通过 GetBestRoute 获取
    if not info["gw_v4"]:
        try:
            gw, ifidx = _g_iphlp.get_best_route_v4("8.8.8.8")
            if gw and not is_fake_v4(gw):
                info["gw_v4"] = gw
                info["if_index_v4"] = ifidx
                if not info["v4_ip"]:
                    info["v4_ip"] = _g_iphlp.get_ipv4_addr_for_ifindex(ifidx)
        except Exception:
            pass

    # 4. 探测物理 IPv6 (如有)
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("2001:4860:4860::8888", 53))
        v6 = s.getsockname()[0].split("%")[0]
        s.close()
        if v6 and not is_fake_v6(v6) and not v6.startswith("fe80"):
            info["v6_ip"] = v6
    except Exception:
        pass

    return info


# ---- WinTUN 设备封装 ----
class WintunDevice:
    """WinTUN 虚拟网卡设备"""

    def __init__(self, adapter_name="AetherCore", tunnel_type="AetherTunnel"):
        self.adapter_name = adapter_name
        self.tunnel_type = tunnel_type
        self._adapter = None
        self._session = None
        self._read_event = None
        self._luid = None
        self._route_rows = []       # 所有由本设备添加的路由 (退出时统一删除)
        self._closed = False
        self._send_lock = threading.Lock()

    def open(self, engine=None):
        eng = engine or _g_engine
        if not eng.load():
            raise RuntimeError('无法加载 wintun.dll，请确保 wintun.dll 位于当前目录或系统目录')

        adapter = eng.WintunOpenAdapter(self.adapter_name)
        if not adapter:
            adapter = eng.WintunCreateAdapter(self.adapter_name, self.tunnel_type, None)
        if not adapter:
            time.sleep(0.3)
            adapter = eng.WintunOpenAdapter(self.adapter_name)
        if not adapter:
            raise RuntimeError(f"创建或打开 Wintun 适配器 '{self.adapter_name}' 失败 (需管理员权限)")

        session = None
        try:
            session = eng.WintunStartSession(adapter, 0x400000)
        except Exception:
            session = None

        if not session:
            try:
                eng.WintunCloseAdapter(adapter)
            except Exception:
                pass
            time.sleep(0.5)
            adapter = eng.WintunCreateAdapter(self.adapter_name, self.tunnel_type, None)
            if not adapter:
                raise RuntimeError(f"重新创建 Wintun 适配器 '{self.adapter_name}' 失败")
            session = eng.WintunStartSession(adapter, 0x400000)
            if not session:
                raise RuntimeError('启动 Wintun 会话失败')

        self._adapter = adapter
        self._session = session
        self._read_event = eng.WintunGetReadWaitEvent(self._session)

        self._luid = NET_LUID()
        eng.WintunGetAdapterLUID(self._adapter, ctypes.byref(self._luid))

        self.interface_alias = self.adapter_name
        self.interface_index = 0
        try:
            alias_buf = ctypes.create_unicode_buffer(256)
            if _g_iphlp._ensure_loaded() and _g_iphlp._dll.ConvertInterfaceLuidToAlias(
                ctypes.byref(self._luid), alias_buf, 256
            ) == 0 and alias_buf.value:
                self.interface_alias = alias_buf.value
            idx = wintypes.DWORD()
            if _g_iphlp._ensure_loaded() and _g_iphlp._dll.ConvertInterfaceLuidToIndex(
                ctypes.byref(self._luid), ctypes.byref(idx)
            ) == 0:
                self.interface_index = idx.value
        except Exception:
            pass

        return self

    def configure_network(self, ip_str=TUN_V4_IP, mask_str=TUN_V4_MASK,
                          mtu=1500, ipv6_str=TUN_V6_IP, ipv6_prefix=TUN_V6_PREFIX):
        """配置网卡 IP (v4+v6)、MTU 以及 DNS 服务器"""
        iphlp = _g_iphlp
        iphlp.set_mtu_and_metric(self._luid, mtu, AF_INET_WIN)
        iphlp.set_ip_address(self._luid, ip_str, mask_str)
        if ipv6_str:
            iphlp.set_mtu_and_metric(self._luid, mtu, AF_INET6_WIN)
            iphlp.set_ip_address(self._luid, ipv6_str, str(ipv6_prefix))

        # 配置 TUN 网卡 DNS 服务器为 Fake-IP 网关地址，保证系统 DNS 查询进入 TUN 劫持
        targets = []
        if getattr(self, 'interface_index', 0):
            targets.append(str(self.interface_index))
        if getattr(self, 'interface_alias', None):
            targets.append(self.interface_alias)
        if self.adapter_name:
            targets.append(self.adapter_name)

        flags = 0x08000000 if sys.platform == 'win32' else 0
        for target_name in targets:
            try:
                res = subprocess.run(
                    ['netsh', 'interface', 'ipv4', 'set', 'dnsservers',
                     f'name={target_name}', 'source=static', f'address={ip_str}',
                     'register=none', 'validate=no'],
                    capture_output=True, timeout=3, creationflags=flags
                )
                if res.returncode == 0:
                    break
            except Exception:
                pass

        if ipv6_str:
            for target_name in targets:
                try:
                    res = subprocess.run(
                        ['netsh', 'interface', 'ipv6', 'set', 'dnsservers',
                         f'name={target_name}', 'source=static', f'address={ipv6_str}',
                         'register=none', 'validate=no'],
                        capture_output=True, timeout=3, creationflags=flags
                    )
                    if res.returncode == 0:
                        break
                except Exception:
                    pass

        if getattr(self, 'interface_index', 0):
            try:
                ps_cmd = (f'Set-DnsClientServerAddress -InterfaceIndex {self.interface_index} '
                          f"-ServerAddresses @('{ip_str}')")
                subprocess.run(['powershell', '-Command', ps_cmd],
                               capture_output=True, timeout=3, creationflags=flags)
            except Exception:
                pass

    def add_route(self, dest_str, prefix_len, gw_str, metric=1):
        """添加经本网卡的路由并登记 (stop 时自动清理)"""
        if_idx = getattr(self, 'interface_index', 0)
        ok, row = _g_iphlp.add_route(self._luid, dest_str, prefix_len, gw_str, metric, if_index=if_idx)
        if ok and row is not None:
            self._route_rows.append(row)
        return ok

    def install_capture_routes(self, with_v4=True, with_v6=True):
        """安装默认路由接管:
        v4: 0.0.0.0/1 + 128.0.0.0/1 (比 0.0.0.0/0 更精确，原默认路由保留作物理出口)
        v6: ::/1 + 8000::/1
        另含 Fake-IP 网段 on-link 路由。
        """
        results = []
        if with_v4:
            results.append(self.add_route("0.0.0.0", 1, None))
            results.append(self.add_route("128.0.0.0", 1, None))
            net, plen = FAKE_V4_NET.split("/")
            results.append(self.add_route(net, int(plen), None))
        if with_v6:
            results.append(self.add_route("::", 1, None))
            results.append(self.add_route("8000::", 1, None))
            net, plen = FAKE_V6_NET.split("/")
            results.append(self.add_route(net, int(plen), None))
        return all(results)

    def install_bypass_route_v4(self, dest_ip: str):
        """为指定 IPv4 添加经原物理网关的 /32 主机路由 (双保险防回环)"""
        phys = getattr(self, "physical", None)
        if not phys or not phys.get("gw_v4"):
            return False
        luid = _g_iphlp.ifindex_to_luid(phys["if_index_v4"]) if phys.get("if_index_v4") else None
        ok, row = _g_iphlp.add_route(
            luid if luid else 0, dest_ip, 32, phys["gw_v4"], metric=1,
            if_index=0 if luid else phys.get("if_index_v4", 0))
        if ok and row is not None:
            self._route_rows.append(row)
        return ok

    def read_packet(self, timeout_ms=500):
        """从环形缓冲区读取一个数据包
        返回 (packet_bytes, packet_size) 或 (None, 0) 超时
        """
        if self._closed or not self._session:
            return None, 0

        eng = _g_engine
        size = wintypes.DWORD(0)
        packet_ptr = eng.WintunReceivePacket(self._session, ctypes.byref(size))

        if packet_ptr:
            packet_size = size.value
            data = ctypes.string_at(packet_ptr, packet_size)
            eng.WintunReleaseReceivePacket(self._session, packet_ptr)
            return data, packet_size

        err = ctypes.GetLastError()
        if err == 0x103:  # ERROR_NO_MORE_ITEMS
            wait_ms = timeout_ms if timeout_ms >= 0 else 0xFFFFFFFF
            ret = ctypes.windll.kernel32.WaitForSingleObject(self._read_event, wait_ms)
            if ret == 0:  # WAIT_OBJECT_0
                return self.read_packet(0)

        return None, 0

    def write_packet(self, data):
        """向环形缓冲区写入一个数据包 (线程安全)"""
        if self._closed or not self._session:
            return False

        packet_size = len(data)
        if packet_size == 0 or packet_size > WINTUN_MAX_IP_PACKET_SIZE:
            return False

        eng = _g_engine
        with self._send_lock:
            buf_ptr = eng.WintunAllocateSendPacket(self._session, packet_size)
            if not buf_ptr:
                return False
            ctypes.memmove(buf_ptr, data, packet_size)
            eng.WintunSendPacket(self._session, buf_ptr)
        return True

    def close(self):
        """关闭网卡并清理所有路由"""
        with threading.Lock():
            if self._closed:
                return
            self._closed = True

        eng = _g_engine

        # 删除全部接管路由
        for row in self._route_rows:
            try:
                _g_iphlp.delete_route(row)
            except Exception:
                pass
        self._route_rows = []

        if self._session:
            try:
                eng.WintunEndSession(self._session)
            except Exception:
                pass
            self._session = None

        if self._adapter:
            try:
                eng.WintunCloseAdapter(self._adapter)
            except Exception:
                pass
            self._adapter = None

        self._read_event = None

    @property
    def is_open(self):
        return self._adapter is not None and not self._closed


# ---- IP 包解析工具 ----
def parse_ipv4_header(packet):
    """解析 IPv4 包头部，返回 dict 或 None"""
    if len(packet) < 20:
        return None
    ver_ihl = packet[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4:
        return None
    total_length = (packet[2] << 8) | packet[3]
    protocol = packet[9]
    src_ip = ".".join(str(packet[i]) for i in range(12, 16))
    dst_ip = ".".join(str(packet[i]) for i in range(16, 20))
    return {
        "version": version,
        "ihl": ihl,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "total_length": total_length,
    }


# ---- TUN 引擎入口 (由 tun_stack.TunEngine 驱动) ----
def main():
    """CLI 入口: 启动完整 TUN 数据面 (需要先启动 aether_core)"""
    import argparse
    parser = argparse.ArgumentParser(description="AetherCore WinTun TUN 引擎")
    parser.add_argument("--name", default="AetherCore", help="网卡名称")
    parser.add_argument("--listen", default="127.0.0.1:7899", help="内核 SOCKS5/HTTP 入站地址")
    args = parser.parse_args()

    from tun_stack import TunEngine
    host, _, port = args.listen.rpartition(":")
    engine = TunEngine(socks_addr=(host or "127.0.0.1", int(port)))
    try:
        engine.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()


if __name__ == "__main__":
    main()
