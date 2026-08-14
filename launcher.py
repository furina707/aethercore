#!/usr/bin/env python3
"""omni-proxy 启动器（零参数，开箱即用）。

直接启动仓库根目录的 omni-config.json，日志落到 net/log/。
"""
import os
import signal
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "proxy-config.json"
BIN_DIR = ROOT / "core" / "proxy-core"
TARGET_DIR = BIN_DIR / "target"


def find_binary() -> Path:
    for profile in ("release", "debug"):
        name = "omni-proxy.exe" if os.name == "nt" else "omni-proxy"
        cand = TARGET_DIR / profile / name
        if cand.is_file():
            return cand
    sys.exit(
        "找不到 omni-proxy 可执行文件。\n"
        f"先编译：cd {BIN_DIR} && cargo build --release\n"
        f"或把已编译的 omni-proxy 放到 {TARGET_DIR}/release/ 下"
    )


def main() -> int:
    binary = find_binary()
    if not CONFIG.is_file():
        sys.exit(f"找不到配置文件：{CONFIG}")

    print(f"[launcher] 启动 {binary}")
    print(f"[launcher] 配置 {CONFIG}")
    print(f"[launcher] 工作目录 {ROOT}")

    kwargs = {"cwd": str(ROOT)}
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen([str(binary), str(CONFIG)], **kwargs)

    def forward(signum, _frame):
        print(f"[launcher] 收到信号，转发给子进程")
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, 0)
            except Exception:
                proc.terminate()
        else:
            proc.send_signal(signum)

    signal.signal(signal.SIGINT, forward)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, forward)

    try:
        return proc.wait()
    except KeyboardInterrupt:
        forward(signal.SIGINT, None)
        return proc.wait()


if __name__ == "__main__":
    raise SystemExit(main())
