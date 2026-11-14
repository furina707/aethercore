#!/usr/bin/env python3
"""AetherCore: 构建与启动脚本。严禁非 root 启动。"""
import os
import subprocess
import sys
from pathlib import Path

# 严禁非 root 用户启动
if os.name != "nt" and os.geteuid() != 0:
    print("\033[31;1m[致命错误] AetherCore 为系统级 TUN 代理，禁止非 root 启动！\033[0m")
    print("请使用超级用户权限执行: sudo -E python3 run.py")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "zig-out" / "bin" / ("aethercore.exe" if os.name == "nt" else "aethercore")

# 1. 编译纯 Zig 单二进制
subprocess.run(["zig", "build"], cwd=ROOT, check=True)

# 2. 启动单二进制
os.execv(str(BIN), [str(BIN)] + sys.argv[1:])
