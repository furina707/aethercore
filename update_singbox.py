#!/usr/bin/env python3
"""update_singbox.py — 自动从 GitHub 下载适配当前平台的最新 sing-box 并更新本地 core/singbox-core。

特性：
  - 获取最新版本号：优先 GitHub Releases API；被限流（403）时回退到
    /releases/latest 的 302 重定向解析 tag，下载走 releases/download 直链
    （不经 API，不受匿名限额影响）
  - 自动检测当前平台/架构（Windows/Linux/macOS × amd64/arm64/386）
  - 按官方资产命名规则匹配（sing-box-{ver}-{platform}-{arch}.zip / .tar.gz）
  - SHA-256 校验（API 可用且提供 digest 时）；原子替换可执行文件
  - 更新前自动备份旧二进制；保留 libcronet.dll、配置与订阅等既有文件

用法：
  python update_singbox.py            # 检测并更新到最新版本
  python update_singbox.py --check    # 仅查询并对比本地/最新版本，不下载
  python update_singbox.py --force    # 即使版本相同也强制重新下载
  python update_singbox.py --dir DIR  # 指定安装目录（默认 core/singbox-core）
  python update_singbox.py --quiet    # 减少输出

可选环境变量：
  GITHUB_TOKEN — 提供 GitHub Token 可显著提高 API 限额（5000 次/小时），
                 并附带 digest 以便做 SHA-256 校验。

仅依赖 Python 标准库，无第三方包。
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

API_URL = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
RELEASE_LATEST = "https://github.com/SagerNet/sing-box/releases/latest"
DOWNLOAD_BASE = "https://github.com/SagerNet/sing-box/releases/download"
USER_AGENT = "omni-update-singbox/1.0 (auto-updater)"


def eprint(*a, **k):
    print(*a, file=sys.stderr, **k)


# ---------- 平台 / 架构检测 ----------

def detect_target() -> tuple[str, str]:
    """返回 (platform, arch)，与 sing-box 官方资产命名一致。"""
    sysname = os.name
    machine = platform.machine().lower()

    if sysname == "nt":
        plat = "windows"
    elif sysname == "posix":
        if sys.platform.startswith("linux"):
            plat = "linux"
        elif sys.platform == "darwin":
            plat = "darwin"
        else:
            plat = sys.platform
    else:
        plat = sysname

    if machine in ("amd64", "x86_64", "x64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "386"
    else:
        arch = machine

    return plat, arch


def exe_name() -> str:
    return "sing-box.exe" if os.name == "nt" else "sing-box"


# ---------- GitHub 获取（API 优先，重定向回退） ----------

def _api_headers() -> dict:
    h = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _fetch(url: str, headers: dict, timeout: int = 30):
    req = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(req, timeout=timeout)


def _version_from_tag(tag: str) -> str:
    return tag.lstrip("v")


def resolve_latest() -> dict:
    """返回 {tag, version, published_at, digest: {asset_name: sha256hex}}。

    优先用 Releases API（信息最全，含 digest）；API 限流/失败时回退到
    /releases/latest 的 302 跳转解析版本号，digest 为空（跳过校验）。
    """
    digest: dict[str, str] = {}
    # 1) 尝试 API
    try:
        with _fetch(API_URL, _api_headers()) as resp:
            rel = json.loads(resp.read().decode("utf-8"))
        tag = rel["tag_name"]
        published = rel.get("published_at", "未知")
        for a in rel.get("assets", []):
            d = a.get("digest")
            if isinstance(d, str) and d.lower().startswith("sha256:"):
                digest[a["name"]] = d.split(":", 1)[1].strip().lower()
        return {"tag": tag, "version": _version_from_tag(tag),
                "published_at": published, "digest": digest, "source": "api"}
    except Exception as e:
        if not isinstance(e, Exception):
            raise
        eprint(f"[update] 提示：GitHub API 不可用（{e}），改用重定向方式获取版本号")
    # 2) 回退：解析 /releases/latest 的 302 Location
    try:
        req = urllib.request.Request(RELEASE_LATEST, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            final = resp.geturl()  # urllib 已跟随重定向
        m = re.search(r"/releases/tag/(v?[0-9]+\.[0-9]+\.[0-9]+)", final)
        if not m:
            raise RuntimeError(f"无法从重定向 URL 解析版本号：{final}")
        tag = m.group(1)
        return {"tag": tag, "version": _version_from_tag(tag),
                "published_at": "未知（API 限流）", "digest": digest, "source": "redirect"}
    except Exception as e2:
        raise RuntimeError(f"获取最新版本失败：{e2}") from e2


def candidate_asset_names(version: str, plat: str, arch: str) -> list[str]:
    """按官方命名规则生成候选资产名：zip 优先，其次 tar.gz。"""
    base = f"sing-box-{version}-{plat}-{arch}"
    names = [f"{base}.zip", f"{base}.tar.gz"]
    # 兼容旧版本用 gz 的情况（tar.gz 已覆盖；若平台为 windows 通常只有 zip）
    return names


def download_asset_url(tag: str, name: str) -> str:
    return f"{DOWNLOAD_BASE}/{tag}/{name}"


# ---------- 本地版本 / 更新 ----------

def local_version(dir_path: Path) -> str | None:
    exe = dir_path / exe_name()
    if not exe.is_file():
        return None
    try:
        out = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=15)
        m = re.search(r"sing-box version\s+v?([0-9]+\.[0-9]+\.[0-9]+)", out.stdout or out.stderr)
        return m.group(1) if m else None
    except Exception:
        return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, name: str, expected_sha256: str | None, quiet: bool) -> None:
    if not quiet:
        print(f"[update] 下载 {name}")
        print(f"[update] 来源 {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)
    if expected_sha256:
        actual = sha256_file(dest)
        if actual != expected_sha256:
            dest.unlink(missing_ok=True)
            raise RuntimeError(f"SHA-256 校验失败：期望 {expected_sha256}，实际 {actual}")
        if not quiet:
            print(f"[update] SHA-256 校验通过 {actual[:16]}…")
    elif not quiet:
        print("[update] 无 digest 信息，跳过 SHA-256 校验")


def extract_binary(archive: Path, dest_dir: Path) -> Path:
    """解压并返回 sing-box 可执行文件在 dest_dir 中的路径。"""
    with tempfile.TemporaryDirectory(prefix="singbox-x-") as td:
        tmp = Path(td)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as z:
                z.extractall(tmp)
        else:
            with tarfile.open(archive, "r:*") as t:
                t.extractall(tmp)
        hits = list(tmp.rglob(exe_name()))
        if not hits:
            raise RuntimeError(f"压缩包内未找到 {exe_name()}")
        src = hits[0]
        final = dest_dir / exe_name()
        os.replace(src, final)  # 原子替换（同文件系统）
        if os.name != "nt":
            final.chmod(0o755)
        return final


def update(dir_path: Path, force: bool, quiet: bool) -> int:
    plat, arch = detect_target()
    info = resolve_latest()
    tag, version, published, digest = info["tag"], info["version"], info["published_at"], info["digest"]

    if not quiet:
        print(f"[update] 最新版本 v{version}（发布于 {published}，来源 {info['source']}）")
        print(f"[update] 当前平台 {plat}/{arch}")

    local = local_version(dir_path)
    if not quiet:
        if local:
            print(f"[update] 本地版本 v{local}（{dir_path / exe_name()}）")
        else:
            print(f"[update] 本地未安装 sing-box（{dir_path}）")

    if not force and local == version:
        if not quiet:
            print("[update] 已是最新版本，无需更新（使用 --force 可强制重装）")
        return 0

    name = next((n for n in candidate_asset_names(version, plat, arch) if n in digest), None)
    if name is None:
        # 无 digest 映射（回退模式）或名字不在 digest 里时，按候选顺序尝试下载
        name = candidate_asset_names(version, plat, arch)[0]
    url = download_asset_url(tag, name)

    if not quiet:
        print(f"[update] 匹配资产 {name}")

    dir_path.mkdir(parents=True, exist_ok=True)
    current = dir_path / exe_name()

    # 备份旧二进制
    if current.exists():
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        backup = dir_path / f"{exe_name()}.bak-{ts}"
        shutil.copy2(current, backup)
        if not quiet:
            print(f"[update] 已备份旧版本 -> {backup.name}")

    with tempfile.TemporaryDirectory(prefix="singbox-dl-") as td:
        tdir = Path(td)
        archive = tdir / name
        download(url, archive, name, digest.get(name), quiet)
        extract_binary(archive, dir_path)

    if not quiet:
        print(f"[update] 完成：{dir_path / exe_name()}")
    return 0


# ---------- 入口 ----------

def main() -> int:
    ap = argparse.ArgumentParser(description="自动下载适配当前平台的最新 sing-box 并更新本地 core/singbox-core")
    ap.add_argument("--check", action="store_true", help="仅查询并对比本地/最新版本，不下载")
    ap.add_argument("--force", action="store_true", help="版本相同时也强制重新下载")
    ap.add_argument("--dir", type=Path, default=None, help="安装目录（默认：仓库 core/singbox-core）")
    ap.add_argument("--quiet", action="store_true", help="减少输出")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent
    target_dir = args.dir or (root / "core" / "singbox-core")

    try:
        if args.check:
            plat, arch = detect_target()
            info = resolve_latest()
            local = local_version(target_dir)
            print(f"最新版本: v{info['version']}  (发布于 {info['published_at']})")
            print(f"当前平台: {plat}/{arch}")
            print(f"本地版本: v{local}  ({target_dir / exe_name()})")
            print(f"结论: {'需要更新' if local != info['version'] else '已是最新'}")
            return 0
        return update(target_dir, args.force, args.quiet)
    except RuntimeError as e:
        eprint(f"[update] 错误：{e}")
        return 1
    except KeyboardInterrupt:
        eprint("[update] 已取消")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
