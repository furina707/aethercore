#!/usr/bin/env python3
"""AetherCore: 极简构建与拉起脚本。
仅保留构建与拉起 Zig 单二进制的极简逻辑，不保留任何其他语言业务代码。
"""
import os
import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "zig-out" / "bin" / ("aethercore.exe" if os.name == "nt" else "aethercore")

def main():
    # 1. 执行 zig build 构建单一原生二进制
    build_cmd = ["zig", "build"]
    if "--release" in sys.argv:
        build_cmd.append("-Doptimize=ReleaseFast")
        sys.argv.remove("--release")

    res = subprocess.run(build_cmd, cwd=ROOT)
    if res.returncode != 0:
        sys.exit(res.returncode)

    if "--build-only" in sys.argv:
        return

    # 2. 拉起生成的单二进制
    args = sys.argv[1:]
    if args and args[0] == "--":
        args = args[1:]

    if not BIN.exists():
        sys.exit(f"[!] 找不到二进制文件: {BIN}")

    os.execv(str(BIN), [str(BIN)] + args)

if __name__ == "__main__":
    main()
