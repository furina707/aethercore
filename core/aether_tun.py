# SPDX-License-Identifier: MIT
# AetherCore - 纯 Python WinTun TUN 虚拟网卡引擎 (替代 aether_tun.exe / tun_wintun.c)
#
# 功能：
#   - 使用 ctypes 加载 wintun.dll，创建/打开 Wintun 虚拟网卡
#   - 通过 iphlpapi.dll 原生配置 IP 地址、MTU、路由 (零子进程)
#   - 零拷贝环形缓冲区读写 (Ring Buffer)
#   - 支持 Fake-IP 路由注入 (198.18.0.0/15)
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
from ctypes import wintypes

# ---- WinTUN DLL 函数类型定义 ----
# 参考 wintun.h 头文件

WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
WINTUN_SESSION_HANDLE = ctypes.c_void_p

# WINTUN_CREATE_ADAPTER_FUNC
WINTUN_CREATE_ADAPTER_FUNC = ctypes.WINFUNCTYPE(
    WINTUN_ADAPTER_HANDLE,
    wintypes.LPCWSTR,       # Name
    wintypes.LPCWSTR,       # TunnelType
    ctypes.POINTER(wintypes.GUID),  # RequestedGUID (optional)
)

# WINTUN_OPEN_ADAPTER_FUNC
WINTUN_OPEN_ADAPTER_FUNC = ctypes.WINFUNCTYPE(
    WINTUN_ADAPTER_HANDLE,
    wintypes.LPCWSTR,       # Name
)

# WINTUN_CLOSE_ADAPTER_FUNC
WINTUN_CLOSE_ADAPTER_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_ADAPTER_HANDLE,  # Adapter
)

# WINTUN_DELETE_DRIVER_FUNC
WINTUN_DELETE_DRIVER_FUNC = ctypes.WINFUNCTYPE(
    wintypes.BOOL,
)

# WINTUN_GET_ADAPTER_LUID_FUNC
WINTUN_GET_ADAPTER_LUID_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_ADAPTER_HANDLE,  # Adapter
    ctypes.c_void_p,        # Luid (NET_LUID*)
)

# WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC = ctypes.WINFUNCTYPE(
    wintypes.DWORD,
)

# WINTUN_SET_LOGGER_FUNC
WINTUN_LOGGER_CALLBACK = ctypes.WINFUNCTYPE(
    None,
    wintypes.DWORD,         # Level
    wintypes.DWORD64,       # Timestamp
    wintypes.LPCWSTR,       # Message
)
WINTUN_SET_LOGGER_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_LOGGER_CALLBACK, # NewLogger
)

# WINTUN_START_SESSION_FUNC
WINTUN_START_SESSION_FUNC = ctypes.WINFUNCTYPE(
    WINTUN_SESSION_HANDLE,
    WINTUN_ADAPTER_HANDLE,  # Adapter
    wintypes.DWORD,         # Capacity
)

# WINTUN_END_SESSION_FUNC
WINTUN_END_SESSION_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_SESSION_HANDLE,  # Session
)

# WINTUN_GET_READ_WAIT_EVENT_FUNC
WINTUN_GET_READ_WAIT_EVENT_FUNC = ctypes.WINFUNCTYPE(
    wintypes.HANDLE,
    WINTUN_SESSION_HANDLE,  # Session
)

# WINTUN_RECEIVE_PACKET_FUNC
WINTUN_RECEIVE_PACKET_FUNC = ctypes.WINFUNCTYPE(
    ctypes.POINTER(wintypes.BYTE),  # BYTE*
    WINTUN_SESSION_HANDLE,          # Session
    ctypes.POINTER(wintypes.DWORD), # PacketSize
)

# WINTUN_RELEASE_RECEIVE_PACKET_FUNC
WINTUN_RELEASE_RECEIVE_PACKET_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_SESSION_HANDLE,  # Session
    ctypes.POINTER(wintypes.BYTE),  # Packet
)

# WINTUN_ALLOCATE_SEND_PACKET_FUNC
WINTUN_ALLOCATE_SEND_PACKET_FUNC = ctypes.WINFUNCTYPE(
    ctypes.POINTER(wintypes.BYTE),
    WINTUN_SESSION_HANDLE,  # Session
    wintypes.DWORD,         # PacketSize
)

# WINTUN_SEND_PACKET_FUNC
WINTUN_SEND_PACKET_FUNC = ctypes.WINFUNCTYPE(
    None,
    WINTUN_SESSION_HANDLE,  # Session
    ctypes.POINTER(wintypes.BYTE),  # Packet
)

WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF

# ---- WinTUN 引擎封装 ----
class WintunEngine:
    """加载 wintun.dll 并解析所有函数指针"""

    def __init__(self):
        self._module = None
        self._fns = {}
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

        # 解析所有函数
        fn_names = [
            "WintunCreateAdapter",
            "WintunCloseAdapter",
            "WintunOpenAdapter",
            "WintunGetAdapterLUID",
            "WintunGetRunningDriverVersion",
            "WintunDeleteDriver",
            "WintunSetLogger",
            "WintunStartSession",
            "WintunEndSession",
            "WintunGetReadWaitEvent",
            "WintunReceivePacket",
            "WintunReleaseReceivePacket",
            "WintunAllocateSendPacket",
            "WintunSendPacket",
        ]

        fn_types = {
            "WintunCreateAdapter": WINTUN_CREATE_ADAPTER_FUNC,
            "WintunCloseAdapter": WINTUN_CLOSE_ADAPTER_FUNC,
            "WintunOpenAdapter": WINTUN_OPEN_ADAPTER_FUNC,
            "WintunGetAdapterLUID": WINTUN_GET_ADAPTER_LUID_FUNC,
            "WintunGetRunningDriverVersion": WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC,
            "WintunDeleteDriver": WINTUN_DELETE_DRIVER_FUNC,
            "WintunSetLogger": WINTUN_SET_LOGGER_FUNC,
            "WintunStartSession": WINTUN_START_SESSION_FUNC,
            "WintunEndSession": WINTUN_END_SESSION_FUNC,
            "WintunGetReadWaitEvent": WINTUN_GET_READ_WAIT_EVENT_FUNC,
            "WintunReceivePacket": WINTUN_RECEIVE_PACKET_FUNC,
            "WintunReleaseReceivePacket": WINTUN_RELEASE_RECEIVE_PACKET_FUNC,
            "WintunAllocateSendPacket": WINTUN_ALLOCATE_SEND_PACKET_FUNC,
            "WintunSendPacket": WINTUN_SEND_PACKET_FUNC,
        }

        for name in fn_names:
            try:
                fn_ptr = self._module[name]
                self._fns[name] = fn_types[name](fn_ptr)
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
        self._fns["WintunSetLogger"](_log_cb)

    def __getattr__(self, name):
        if name.startswith("_") or name not in self._fns:
            raise AttributeError(f"WintunEngine has no attribute {name}")
        return self._fns[name]

    def unload(self):
        if self._module:
            self._module = None
            self._fns = {}
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


class SOCKADDR_IN(ctypes.Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", INET_ADDR),
        ("sin_zero", wintypes.BYTE * 8),
    ]


class IP_ADDRESS_PREFIX(ctypes.Structure):
    _fields_ = [
        ("Prefix", SOCKADDR_IN),
        ("PrefixLength", wintypes.UINT8),
    ]


class MIB_IPFORWARD_ROW2(ctypes.Structure):
    _fields_ = [
        ("InterfaceLuid", NET_LUID),
        ("InterfaceIndex", wintypes.ULONG),
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_IN),
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
        ("Address", SOCKADDR_IN),
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


class _IPHLPAPI:
    """iphlpapi.dll 封装 (延迟加载)"""

    def __init__(self):
        self._dll = None
        self._InitializeIpInterfaceEntry = None
        self._GetIpInterfaceEntry = None
        self._SetIpInterfaceEntry = None
        self._InitializeUnicastIpAddressEntry = None
        self._CreateUnicastIpAddressEntry = None
        self._InitializeIpForwardEntry2 = None
        self._CreateIpForwardEntry2 = None
        self._DeleteIpForwardEntry2 = None
        self._RtlIpv4StringToAddressA = None

    def _ensure_loaded(self):
        if self._dll is not None:
            return True
        try:
            self._dll = ctypes.WinDLL("iphlpapi")
            self._ntdll = ctypes.WinDLL("ntdll")
        except OSError:
            return False

        self._InitializeIpInterfaceEntry = self._dll.InitializeIpInterfaceEntry
        self._InitializeIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
        self._InitializeIpInterfaceEntry.restype = None

        self._GetIpInterfaceEntry = self._dll.GetIpInterfaceEntry
        self._GetIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
        self._GetIpInterfaceEntry.restype = wintypes.DWORD

        self._SetIpInterfaceEntry = self._dll.SetIpInterfaceEntry
        self._SetIpInterfaceEntry.argtypes = [ctypes.POINTER(MIB_IPINTERFACE_ROW)]
        self._SetIpInterfaceEntry.restype = wintypes.DWORD

        self._InitializeUnicastIpAddressEntry = self._dll.InitializeUnicastIpAddressEntry
        self._InitializeUnicastIpAddressEntry.argtypes = [ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW)]
        self._InitializeUnicastIpAddressEntry.restype = None

        self._CreateUnicastIpAddressEntry = self._dll.CreateUnicastIpAddressEntry
        self._CreateUnicastIpAddressEntry.argtypes = [ctypes.POINTER(MIB_UNICASTIPADDRESS_ROW)]
        self._CreateUnicastIpAddressEntry.restype = wintypes.DWORD

        self._InitializeIpForwardEntry2 = self._dll.InitializeIpForwardEntry2
        self._InitializeIpForwardEntry2.argtypes = [ctypes.POINTER(MIB_IPFORWARD_ROW2)]
        self._InitializeIpForwardEntry2.restype = None

        self._CreateIpForwardEntry2 = self._dll.CreateIpForwardEntry2
        self._CreateIpForwardEntry2.argtypes = [ctypes.POINTER(MIB_IPFORWARD_ROW2)]
        self._CreateIpForwardEntry2.restype = wintypes.DWORD

        self._DeleteIpForwardEntry2 = self._dll.DeleteIpForwardEntry2
        self._DeleteIpForwardEntry2.argtypes = [ctypes.POINTER(MIB_IPFORWARD_ROW2)]
        self._DeleteIpForwardEntry2.restype = wintypes.DWORD

        self._RtlIpv4StringToAddressA = self._ntdll.RtlIpv4StringToAddressA
        self._RtlIpv4StringToAddressA.argtypes = [
            ctypes.c_char_p, wintypes.BOOLEAN, ctypes.POINTER(ctypes.c_char_p),
            ctypes.POINTER(INET_ADDR)]
        self._RtlIpv4StringToAddressA.restype = wintypes.LONG

        return True

    def ipv4_string_to_addr(self, ip_str):
        """'198.18.0.1' -> INET_ADDR"""
        addr = INET_ADDR()
        term = ctypes.c_char_p()
        ret = self._RtlIpv4StringToAddressA(ip_str.encode("ascii"), True, ctypes.byref(term), ctypes.byref(addr))
        if ret != 0:
            raise ValueError(f"Invalid IP address: {ip_str}")
        return addr

    def inet_addr(self, ip_str):
        """inet_addr 兼容: '198.18.0.0' -> ULONG (network byte order)"""
        addr = self.ipv4_string_to_addr(ip_str)
        return addr.S_un

    def set_mtu_and_metric(self, luid, mtu):
        """设置网卡 MTU 和跃点数"""
        if not self._ensure_loaded():
            return False
        row = MIB_IPINTERFACE_ROW()
        self._InitializeIpInterfaceEntry(ctypes.byref(row))
        row.Family = 2  # AF_INET
        row.InterfaceLuid = luid
        if self._GetIpInterfaceEntry(ctypes.byref(row)) == 0:  # NO_ERROR
            row.NlMtu = mtu
            row.UseAutomaticMetric = False
            row.Metric = 1  # 最高优先级
            self._SetIpInterfaceEntry(ctypes.byref(row))
            return True
        return False

    def set_ip_address(self, luid, ip_str, mask_str):
        """设置网卡静态 IP 地址"""
        if not self._ensure_loaded():
            return False
        prefix_len = self._mask_to_prefix(mask_str)
        row = MIB_UNICASTIPADDRESS_ROW()
        self._InitializeUnicastIpAddressEntry(ctypes.byref(row))
        row.InterfaceLuid = luid
        row.Address.sin_family = 2  # AF_INET
        row.Address.sin_addr = self.ipv4_string_to_addr(ip_str)
        row.OnLinkPrefixLength = prefix_len
        row.DadState = 1  # IpDadStatePreferred
        res = self._CreateUnicastIpAddressEntry(ctypes.byref(row))
        return res == 0 or res == 0x000000B7  # NO_ERROR or ERROR_OBJECT_ALREADY_EXISTS

    def add_route(self, luid, dest_str, prefix_len, gw_str, metric=1):
        """添加静态路由"""
        if not self._ensure_loaded():
            return False
        row = MIB_IPFORWARD_ROW2()
        self._InitializeIpForwardEntry2(ctypes.byref(row))
        row.InterfaceLuid = luid
        row.DestinationPrefix.Prefix.sin_family = 2
        row.DestinationPrefix.Prefix.sin_addr = INET_ADDR()
        row.DestinationPrefix.Prefix.sin_addr.S_un = self.inet_addr(dest_str)
        row.DestinationPrefix.PrefixLength = prefix_len
        row.NextHop.sin_family = 2
        row.NextHop.sin_addr = self.ipv4_string_to_addr(gw_str)
        row.Metric = metric
        row.Protocol = 3  # MIB_IPPROTO_NETMGMT
        res = self._CreateIpForwardEntry2(ctypes.byref(row))
        if res == 0:
            return True, row
        return False, row

    def delete_route(self, row):
        """删除之前添加的路由"""
        if not self._ensure_loaded():
            return False
        self._DeleteIpForwardEntry2(ctypes.byref(row))
        return True

    @staticmethod
    def _mask_to_prefix(mask_str):
        """255.254.0.0 -> 15"""
        parts = mask_str.split(".")
        val = sum(int(p) << (24 - 8 * i) for i, p in enumerate(parts))
        return bin(val).count("1")


# 全局 iphlpapi 实例
_g_iphlp = _IPHLPAPI()


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
        self._route_row = None
        self._closed = False
        self._lock = threading.Lock()

    def open(self, engine=None):
        """创建或打开 WinTUN 虚拟网卡"""
        eng = engine or _g_engine
        if not eng.load():
            raise RuntimeError("无法加载 wintun.dll，请确保 wintun.dll 位于当前目录或系统目录")

        # 尝试创建网卡
        self._adapter = eng.WintunCreateAdapter(
            self.adapter_name,
            self.tunnel_type,
            None
        )

        if not self._adapter:
            # 已存在则尝试打开
            self._adapter = eng.WintunOpenAdapter(self.adapter_name)

        if not self._adapter:
            raise RuntimeError(f"创建/打开 Wintun 网卡 '{self.adapter_name}' 失败")

        # 启动 4MB 环形缓冲区
        self._session = eng.WintunStartSession(self._adapter, 0x400000)
        if not self._session:
            eng.WintunCloseAdapter(self._adapter)
            self._adapter = None
            raise RuntimeError("启动 Wintun 会话失败")

        # 获取读取事件句柄
        self._read_event = eng.WintunGetReadWaitEvent(self._session)

        # 获取 LUID
        self._luid = NET_LUID()
        eng.WintunGetAdapterLUID(self._adapter, ctypes.byref(self._luid))

        return self

    def configure_network(self, ip_str="198.18.0.1", mask_str="255.254.0.0",
                          mtu=1500, fake_ip_route="198.18.0.0/15"):
        """配置网卡 IP、MTU、Fake-IP 路由"""
        iphlp = _g_iphlp

        # 设置 MTU 和跃点数
        iphlp.set_mtu_and_metric(self._luid, mtu)

        # 设置 IP 地址
        iphlp.set_ip_address(self._luid, ip_str, mask_str)

        # 添加 Fake-IP 路由
        dest_str, prefix_len_str = fake_ip_route.split("/")
        prefix_len = int(prefix_len_str)
        ok, row = iphlp.add_route(self._luid, dest_str, prefix_len, ip_str, metric=1)
        if ok:
            self._route_row = row

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

        # 等待数据
        err = ctypes.GetLastError()
        if err == 0x103:  # ERROR_NO_MORE_ITEMS
            wait_ms = timeout_ms if timeout_ms >= 0 else 0xFFFFFFFF
            ret = ctypes.windll.kernel32.WaitForSingleObject(self._read_event, wait_ms)
            if ret == 0:  # WAIT_OBJECT_0
                # 有新数据，递归读取
                return self.read_packet(0)

        return None, 0

    def write_packet(self, data):
        """向环形缓冲区写入一个数据包"""
        if self._closed or not self._session:
            return False

        packet_size = len(data)
        if packet_size == 0 or packet_size > WINTUN_MAX_IP_PACKET_SIZE:
            return False

        eng = _g_engine
        buf_ptr = eng.WintunAllocateSendPacket(self._session, packet_size)
        if not buf_ptr:
            return False

        # 复制数据到发送缓冲区
        ctypes.memmove(buf_ptr, data, packet_size)
        eng.WintunSendPacket(self._session, buf_ptr)
        return True

    def close(self):
        """关闭网卡并清理路由"""
        with self._lock:
            if self._closed:
                return
            self._closed = True

        eng = _g_engine

        # 删除路由
        if self._route_row is not None:
            try:
                _g_iphlp.delete_route(self._route_row)
            except Exception:
                pass
            self._route_row = None

        # 结束会话
        if self._session:
            try:
                eng.WintunEndSession(self._session)
            except Exception:
                pass
            self._session = None

        # 关闭适配器
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


# ---- IPv4 包解析工具 ----
def parse_ipv4_header(packet):
    """解析 IPv4 包头部，返回 (version, ihl, protocol, src_ip, dst_ip, total_length)"""
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


# ---- 简易 TUN 引擎示例 ----
def run_tun_engine(adapter_name="AetherCore", ip_str="198.18.0.1",
                   mask_str="255.254.0.0", fake_ip_route="198.18.0.0/15",
                   stop_event=None):
    """运行 TUN 引擎主循环

    参数:
        stop_event: threading.Event，设置后停止循环
    """
    if stop_event is None:
        stop_event = threading.Event()

    print("=" * 60)
    print("  AetherCore Python WinTun TUN Engine")
    print("=" * 60)

    # 加载引擎
    if not _g_engine.load():
        print("[x] 无法加载 wintun.dll！请确保 wintun.dll 位于目录中。", file=sys.stderr)
        return 1

    print("[*] wintun.dll 加载成功")

    # 创建并配置网卡
    dev = WintunDevice(adapter_name)
    try:
        dev.open()
        dev.configure_network(ip_str, mask_str, fake_ip_route=fake_ip_route)
    except RuntimeError as e:
        print(f"[x] {e}", file=sys.stderr)
        return 1

    print(f"[+] [TUN] 虚拟网卡已就绪！")
    print(f"    - 设备名称: {adapter_name}")
    print(f"    - 虚拟 IP : {ip_str}/{_g_iphlp._mask_to_prefix(mask_str)}")
    print(f"    - 环形缓冲: 4MB (Ring Buffer)")
    print(f"    - Fake-IP : {fake_ip_route} -> {ip_str}")
    print()
    print("[*] 开始监听虚拟网卡流量 (按 Ctrl+C 安全停止)...")
    print()

    total_packets = 0
    try:
        while not stop_event.is_set():
            data, size = dev.read_packet(timeout=500)
            if data:
                total_packets += 1
                info = parse_ipv4_header(data)
                if info:
                    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
                    proto_name = proto_map.get(info["protocol"], f"0x{info['protocol']:02X}")
                    print(f"[IPv4] {proto_name} {info['src_ip']} -> {info['dst_ip']} ({size} bytes)")
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[*] 正在清理资源并销毁虚拟网卡...")
        dev.close()
        print(f"[+] 清理完成。总处理数据包: {total_packets}")

    return 0


def main():
    """CLI 入口"""
    import argparse
    parser = argparse.ArgumentParser(description="AetherCore WinTun TUN 引擎")
    parser.add_argument("--name", default="AetherCore", help="网卡名称")
    parser.add_argument("--ip", default="198.18.0.1", help="虚拟 IP 地址")
    parser.add_argument("--mask", default="255.254.0.0", help="子网掩码")
    parser.add_argument("--route", default="198.18.0.0/15", help="Fake-IP 路由")
    args = parser.parse_args()

    sys.exit(run_tun_engine(
        adapter_name=args.name,
        ip_str=args.ip,
        mask_str=args.mask,
        fake_ip_route=args.route,
    ))


if __name__ == "__main__":
    main()