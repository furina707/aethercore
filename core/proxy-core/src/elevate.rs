//! 内置提权工具（Windows）：启动时检测管理员权限，非管理员时经独立提权
//! 辅助程序 `omni-elevater` 以管理员身份重启自身。
//!
//! 设计（按用户选定方案）：
//! - **独立提权辅助 exe**：主程序不直接 self-elevate，而是调用同目录下的
//!   `omni-elevater.exe`（一个无依赖的极小程序），由其以管理员令牌重启
//!   `omni-proxy.exe` 并透传参数。解耦、可单独分发/审查。
//! - **启动时总是检测**：无论配置如何，启动即检测管理员身份，非管理员时
//!   尝试提权（普通 HTTP/SOCKS 模式同样生效）。
//!
//! 流程：
//!   1. `is_elevated()` 用 `IsUserAnAdmin` 检测是否管理员。
//!   2. 已是管理员 → 直接继续。
//!   3. 非管理员且未跳过 → `ShellExecuteExW(verb="runas")` 启动
//!      `omni-elevater.exe`，参数为 `<omni-proxy.exe 路径> <原始参数...>`，
//!      随后退出当前进程。
//!   4. 提权后的 omni-elevater 用 std::process 拉起 omni-proxy（继承提升令牌），
//!      新实例检测到已是管理员，继续正常运行。
//!
//! 跳过开关（供开发/CI/普通模式使用）：
//!   - 环境变量 `OMNI_NO_ELEVATE=1`
//!   - 或命令行参数 `--no-elevate`
//!   设置后不再触发 UAC，直接以当前权限运行。
//!
//! 非 Windows 平台：本模块为 no-op（无需提权）。

use anyhow::Result;

/// 跳过提权的环境变量名。
pub const NO_ELEVATE_ENV: &str = "OMNI_NO_ELEVATE";

/// 是否以管理员身份运行。
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::UI::Shell::IsUserAnAdmin;
    // IsUserAnAdmin 返回 BOOL；非 0 即管理员
    unsafe { IsUserAnAdmin().as_bool() }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true // 非 Windows 无需提权，视为已提权
}

/// 用户是否显式要求跳过提权（环境变量或命令行 --no-elevate）。
pub fn should_skip_elevate(args: &crate::cli::CliArgs) -> bool {
    if std::env::var_os(NO_ELEVATE_ENV)
        .map(|v| !v.is_empty() && v != "0")
        .unwrap_or(false)
    {
        return true;
    }
    args.no_elevate
}

/// 启动时总是检测：非管理员且未跳过时，经 omni-elevater 提权重启后退出。
/// 返回 `true` 表示已触发提权（调用方应立即退出）；`false` 表示继续以当前权限运行。
#[cfg(windows)]
pub fn ensure_elevated_or_relaunch(args: &crate::cli::CliArgs) -> Result<bool> {
    if is_elevated() {
        return Ok(false);
    }
    if should_skip_elevate(args) {
        tracing::warn!(
            elevate_skip = true,
            "非管理员运行，且已通过 {} / --no-elevate 跳过提权；Wintun/WFP 等需要管理员的功能可能不可用",
            NO_ELEVATE_ENV
        );
        return Ok(false);
    }

    let exe = std::env::current_exe()?;
    let helper = exe.with_file_name("omni-elevater.exe");
    if !helper.exists() {
        tracing::warn!(
            helper = %helper.display(),
            "未找到提权辅助程序 omni-elevater.exe，将以当前权限继续运行"
        );
        return Ok(false);
    }

    // 构造参数：<omni-proxy.exe 路径> <原始参数...>
    let mut params = format!("{}", quote_win(&exe.to_string_lossy()));
    for a in std::env::args().skip(1) {
        params.push(' ');
        params.push_str(&quote_win(&a));
    }

    tracing::info!(
        helper = %helper.display(),
        "检测到非管理员运行，请求 UAC 提权（omni-elevater）"
    );

    match relaunch_via_runas(&helper, &params) {
        Ok(_) => {
            tracing::info!("已触发提权，本进程退出，由管理员实例接管");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "UAC 提权失败或用户取消，将以当前权限继续运行"
            );
            Ok(false)
        }
    }
}

#[cfg(not(windows))]
pub fn ensure_elevated_or_relaunch(_args: &crate::cli::CliArgs) -> Result<bool> {
    Ok(false)
}

/// 用 ShellExecuteExW(verb="runas") 以管理员身份启动 helper（触发一次 UAC）。
#[cfg(windows)]
fn relaunch_via_runas(helper: &std::path::Path, params: &str) -> Result<()> {
    use windows::Win32::Foundation::{HANDLE, HINSTANCE, HWND};
    use windows::Win32::System::Registry::HKEY;
    use windows::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW, SHELLEXECUTEINFOW_0};

    // 构造以 \0 结尾的宽字符字符串
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let verb = wide("runas");
    let file = wide(&helper.to_string_lossy());
    let parameters = wide(params);
    let dir = std::env::current_dir()
        .map(|d| wide(&d.to_string_lossy()))
        .unwrap_or_default();

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: 0, // 无需等待/句柄，取默认
        hwnd: HWND::default(),
        lpVerb: windows::core::PCWSTR(verb.as_ptr()),
        lpFile: windows::core::PCWSTR(file.as_ptr()),
        lpParameters: windows::core::PCWSTR(parameters.as_ptr()),
        lpDirectory: windows::core::PCWSTR(dir.as_ptr()),
        nShow: 1, // SW_SHOWNORMAL
        hInstApp: HINSTANCE::default(),
        lpIDList: std::ptr::null_mut(),
        lpClass: windows::core::PCWSTR::null(),
        hkeyClass: HKEY::default(),
        dwHotKey: 0,
        Anonymous: SHELLEXECUTEINFOW_0::default(),
        hProcess: HANDLE::default(),
    };

    unsafe { ShellExecuteExW(&mut sei) }?;
    Ok(())
}

/// 对命令行参数做 Windows 引号转义（含空格时加双引号，内嵌引号转义）。
fn quote_win(s: &str) -> String {
    let needs_quote = s.is_empty()
        || s.chars().any(|c| c == ' ' || c == '\t' || c == '"' || c == '\n' || c == '\r');
    if !needs_quote {
        return s.to_string();
    }
    format!("\"{}\"", s.replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_plain() {
        assert_eq!(quote_win("abc"), "abc");
    }

    #[test]
    fn quote_with_space() {
        assert_eq!(quote_win("C:\\Program Files\\x.exe"), "\"C:\\Program Files\\x.exe\"");
    }

    #[test]
    fn quote_embedded_quote() {
        assert_eq!(quote_win("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn quote_empty() {
        assert_eq!(quote_win(""), "\"\"");
    }
}
