# SPDX-License-Identifier: MIT
# AetherCore - 分应用代理规则存储 (纯 Python 实现)
#
# 读写 data/app_rules.json，提供 list/get/set/del 接口，供 launcher 调用。
# 用法:
#   aether_rules.py -d <数据目录> list
#   aether_rules.py -d <数据目录> get <进程名>
#   aether_rules.py -d <数据目录> set <进程名> <direct|proxy|auto|节点名>
#   aether_rules.py -d <数据目录> del <进程名>

import os
import json
import sys


def get_rules_path(data_dir: str = None) -> str:
    """获取 app_rules.json 的路径"""
    if data_dir:
        return os.path.join(data_dir, "app_rules.json")
    # 默认：脚本所在目录的上一级 / data
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(os.path.dirname(script_dir), "data", "app_rules.json")


def load_rules(rules_path: str = None) -> dict:
    """从 JSON 文件加载规则，返回 {进程名小写: 目标}"""
    if rules_path is None:
        rules_path = get_rules_path()
    if not os.path.exists(rules_path):
        return {}
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return {k.lower(): v for k, v in data.items()}
        return {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_rules(rules: dict, rules_path: str = None) -> bool:
    """保存规则到 JSON 文件"""
    if rules_path is None:
        rules_path = get_rules_path()
    try:
        os.makedirs(os.path.dirname(rules_path), exist_ok=True)
        with open(rules_path, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def _normalize_target(target: str) -> str:
    """标准化目标值"""
    low = target.lower().strip()
    if low in ("direct", "proxy", "auto"):
        return low
    return target


def rules_list(data_dir: str = None) -> dict:
    """列出所有规则 -> {进程名小写: 目标}"""
    return load_rules(get_rules_path(data_dir))


def rules_get(proc: str, data_dir: str = None) -> str:
    """获取指定进程的规则，未找到返回空字符串"""
    rules = load_rules(get_rules_path(data_dir))
    return rules.get(proc.lower(), "")


def rules_set(proc: str, target: str, data_dir: str = None) -> bool:
    """设置指定进程的规则"""
    proc = proc.lower().strip()
    if not proc:
        return False
    target = _normalize_target(target)
    rules_path = get_rules_path(data_dir)
    rules = load_rules(rules_path)
    rules[proc] = target
    return save_rules(rules, rules_path)


def rules_del(proc: str, data_dir: str = None) -> bool:
    """删除指定进程的规则"""
    proc = proc.lower().strip()
    if not proc:
        return False
    rules_path = get_rules_path(data_dir)
    rules = load_rules(rules_path)
    if proc not in rules:
        return False
    del rules[proc]
    return save_rules(rules, rules_path)


def main():
    """CLI 入口，兼容 C 版本 aether_rules.exe 的参数格式"""
    import argparse

    parser = argparse.ArgumentParser(description="AetherCore 分应用代理规则管理")
    parser.add_argument("-d", "--data-dir", default=None, help="数据目录路径")
    parser.add_argument("command", nargs="+", help="命令: list|get|set|del [...]")

    # 手动解析以兼容 C 风格参数
    data_dir = None
    args = sys.argv[1:]

    i = 0
    while i < len(args):
        if args[i] == "-d" and i + 1 < len(args):
            data_dir = args[i + 1]
            i += 2
        else:
            break

    cmd_args = args[i:]
    if not cmd_args:
        print("usage: aether_rules.py [-d datadir] list|get|set|del ...")
        return 2

    cmd = cmd_args[0]

    if cmd == "list":
        for proc, target in rules_list(data_dir).items():
            print(f"{proc}\t{target}")
        return 0

    if cmd == "get":
        if len(cmd_args) < 2:
            print("usage: aether_rules.py get <process_name>")
            return 2
        val = rules_get(cmd_args[1], data_dir)
        if val:
            print(val)
            return 0
        return 1

    if cmd == "set":
        if len(cmd_args) < 3:
            print("usage: aether_rules.py set <process_name> <target>")
            return 2
        return 0 if rules_set(cmd_args[1], cmd_args[2], data_dir) else 1

    if cmd == "del":
        if len(cmd_args) < 2:
            print("usage: aether_rules.py del <process_name>")
            return 2
        return 0 if rules_del(cmd_args[1], data_dir) else 1

    print(f"unknown command: {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main())