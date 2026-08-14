//! omni-elevater — 独立提权辅助程序（Windows）。
//!
//! 职责：以管理员身份（由主程序通过 UAC 的 `runas` 动词触发）重新拉起
//! `omni-proxy.exe`，并透传原始命令行参数。提权成功后立即退出。
//!
//! 用法（一般由主程序自动调用，无需手动执行）：
//! ```text
//! omni-elevater <目标exe路径> [参数...]
//! ```
//!
//! 原理：
//! - 主程序 `omni-proxy` 启动时检测到非管理员 → 用 ShellExecuteExW(runas)
//!   启动本程序（弹一次 UAC 确认框）。
//! - 本程序此时以提升后的令牌运行 → 用 std::process::Command 直接拉起目标
//!   exe（子进程继承提升令牌）→ 自身立即退出。
//! - 目标 exe 检测到已是管理员，继续正常运行。全程只弹一次 UAC。

use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // args[0] = 本程序路径, args[1] = 目标 exe, args[2..] = 透传参数
    if args.len() < 2 {
        eprintln!("用法: omni-elevater <目标exe路径> [参数...]");
        std::process::exit(2);
    }
    let target = &args[1];
    let target_args = &args[2..];

    // 让目标 exe 从主程序原工作目录启动，避免相对路径（如配置路径）失效。
    if let Ok(cwd) = std::env::current_dir() {
        let _ = Command::new(target)
            .args(target_args)
            .current_dir(&cwd)
            .spawn();
    } else {
        let _ = Command::new(target).args(target_args).spawn();
    }

    // 无论拉起成功与否，本程序都立即退出；失败时主程序已在日志中告警。
    std::process::exit(0);
}
