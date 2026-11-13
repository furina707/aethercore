#!/usr/bin/env python3
"""AetherCore: 极简构建与拉起脚本。一键构建并直接启动单二进制。"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "zig-out" / "bin" / ("aethercore.exe" if os.name == "nt" else "aethercore")

subprocess.run(["zig", "build"], cwd=ROOT, check=True)
os.execv(str(BIN), [str(BIN)] + sys.argv[1:])
