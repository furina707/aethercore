#!/usr/bin/env python3
"""AetherCore: 极简构建与拉起脚本。一键构建并直接启动单二进制。"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "zig-out" / "bin" / ("aethercore.exe" if os.name == "nt" else "aethercore")

subprocess.run(["zig", "build"], cwd=ROOT, check=True)

if os.name != "nt":
    # 赋予 CAP_NET_ADMIN 权限以允许无 root 密码创建 TUN 虚拟网卡 aether0
    subprocess.run(
        ["sudo", "-S", "setcap", "cap_net_admin,cap_net_raw+eip", str(BIN)],
        input=b"1231\n",
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )

os.execv(str(BIN), [str(BIN)] + sys.argv[1:])
