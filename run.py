#!/usr/bin/env python3
"""AetherCore: 构建与启动脚本。TUN 全量网络代理必须以 root 权限运行。"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "zig-out" / "bin" / ("aethercore.exe" if os.name == "nt" else "aethercore")

# 1. 编译单二进制
subprocess.run(["zig", "build"], cwd=ROOT, check=True)

# 2. Linux 下 TUN 虚拟网卡与系统路由表操作必须以 root 权限执行
if os.name != "nt" and os.geteuid() != 0:
    print("[AetherCore] TUN 全量流量劫持与内核路由表配置需要 root 权限，正在提升权限启动...")
    os.execvp("sudo", ["sudo", "-E", str(BIN)] + sys.argv[1:])
else:
    os.execv(str(BIN), [str(BIN)] + sys.argv[1:])
