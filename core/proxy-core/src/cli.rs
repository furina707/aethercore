//! 命令行参数解析：自实现轻量解析，不引入 clap 依赖。
//! 支持的参数：
//!   -c, --config <PATH>     配置文件路径（默认 proxy-config.json）
//!   -h, --help              打印帮助信息并退出
//!   -V, --version           打印版本号并退出
//!       --check <PATH>      仅校验配置文件合法性，不启动服务
//!   -v, --verbose           提升日志级别到 debug（覆盖配置中的 log_level）
//!   -q, --quiet             降低日志级别到 warn（覆盖配置中的 log_level）
//!
//! 用法示例：
//!   omni-proxy                          # 使用 ./proxy-config.json 启动
//!   omni-proxy --config /etc/p.json     # 指定配置
//!   omni-proxy --check /etc/p.json      # 仅校验配置
//!   omni-proxy -v                       # debug 日志

use std::process::exit;

/// 解析后的命令行参数。
#[derive(Debug, Clone)]
pub struct CliArgs {
    /// 配置文件路径
    pub config: String,
    /// 仅校验配置（不启动服务）
    pub check_only: bool,
    /// 日志级别覆盖：None=使用配置；Some("debug")/Some("warn") 等=覆盖
    pub log_level_override: Option<String>,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            config: "proxy-config.json".to_string(),
            check_only: false,
            log_level_override: None,
        }
    }
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
const NAME: &str = "omni-proxy";

const HELP_TEXT: &str = r#"omni-proxy — 全协议代理核心 (TCP/UDP/HTTP/SOCKS/DNS + TLS + 规则路由)

用法:
    omni-proxy [OPTIONS] [CONFIG_PATH]

参数:
    [CONFIG_PATH]            配置文件路径（位置参数，等价于 --config）

选项:
    -c, --config <PATH>      配置文件路径（默认: proxy-config.json）
        --check <PATH>       仅校验配置文件合法性，不启动服务
    -v, --verbose            提升日志级别到 debug（覆盖配置）
    -q, --quiet              降低日志级别到 warn（覆盖配置）
    -h, --help               显示此帮助信息
    -V, --version            显示版本号

示例:
    omni-proxy                            # 使用 ./proxy-config.json 启动
    omni-proxy /etc/omni/proxy.json       # 指定配置（位置参数）
    omni-proxy --config p.json -v         # 指定配置并启用 debug 日志
    omni-proxy --check p.json             # 仅校验配置语法/语义

配置热重载：进程运行中修改配置文件，按 hot_reload_secs 周期自动生效。
Web 仪表盘：默认 http://127.0.0.1:9090
"#;

/// 解析命令行参数。遇到 --help / --version 会直接 exit(0)。
/// 解析失败会打印到 stderr 并 exit(2)。
pub fn parse() -> CliArgs {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    parse_from(&raw)
}

/// 从给定参数列表解析（便于测试）。
pub fn parse_from(args: &[String]) -> CliArgs {
    let mut out = CliArgs::default();
    let mut i = 0;
    let mut positional_config: Option<String> = None;
    let mut verbose = false;
    let mut quiet = false;

    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", HELP_TEXT);
                exit(0);
            }
            "-V" | "--version" => {
                println!("{} {}", NAME, VERSION);
                exit(0);
            }
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-q" | "--quiet" => {
                quiet = true;
                i += 1;
            }
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: {} 需要一个参数", a);
                    exit(2);
                }
                out.config = args[i].clone();
                i += 1;
            }
            "--check" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --check 需要一个参数");
                    exit(2);
                }
                out.config = args[i].clone();
                out.check_only = true;
                i += 1;
            }
            // 长选项的 --key=value 形式
            s if s.starts_with("--config=") => {
                out.config = s.trim_start_matches("--config=").to_string();
                i += 1;
            }
            s if s.starts_with("--check=") => {
                out.config = s.trim_start_matches("--check=").to_string();
                out.check_only = true;
                i += 1;
            }
            // 未知的长/短选项
            s if s.starts_with("--") || (s.starts_with('-') && s.len() > 1 && !s.starts_with("--")) => {
                eprintln!("error: 未知参数 {}", s);
                eprintln!("使用 --help 查看完整用法");
                exit(2);
            }
            // 位置参数：第一个视为配置路径
            other => {
                if positional_config.is_none() {
                    positional_config = Some(other.to_string());
                } else {
                    eprintln!("error: 多余的位置参数 {}", other);
                    exit(2);
                }
                i += 1;
            }
        }
    }

    // 位置参数优先级低于 --config，但若未指定 --config 则使用位置参数
    if let Some(p) = positional_config {
        // 只有当用户没有显式 --config 时才覆盖
        // 判断方式：默认值意味着未显式指定
        // 注意：这里假设用户不会把配置文件命名为字面 "proxy-config.json" 来区分；
        //       即使如此，行为也合理：位置参数优先。
        if out.config == "proxy-config.json" {
            out.config = p;
        }
    }

    // 日志级别覆盖：verbose 优先于 quiet
    if verbose {
        out.log_level_override = Some("debug".to_string());
    } else if quiet {
        out.log_level_override = Some("warn".to_string());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default() {
        let a = parse_from(&[]);
        assert_eq!(a.config, "proxy-config.json");
        assert!(!a.check_only);
        assert!(a.log_level_override.is_none());
    }

    #[test]
    fn parses_positional_config() {
        let a = parse_from(&["my.json".to_string()]);
        assert_eq!(a.config, "my.json");
    }

    #[test]
    fn parses_long_config() {
        let a = parse_from(&["--config".to_string(), "x.json".to_string()]);
        assert_eq!(a.config, "x.json");
    }

    #[test]
    fn parses_short_config() {
        let a = parse_from(&["-c".to_string(), "y.json".to_string()]);
        assert_eq!(a.config, "y.json");
    }

    #[test]
    fn parses_config_equals_form() {
        let a = parse_from(&["--config=z.json".to_string()]);
        assert_eq!(a.config, "z.json");
    }

    #[test]
    fn parses_check_mode() {
        let a = parse_from(&["--check".to_string(), "c.json".to_string()]);
        assert_eq!(a.config, "c.json");
        assert!(a.check_only);
    }

    #[test]
    fn parses_verbose_quiet() {
        let a = parse_from(&["-v".to_string()]);
        assert_eq!(a.log_level_override.as_deref(), Some("debug"));
        let b = parse_from(&["-q".to_string()]);
        assert_eq!(b.log_level_override.as_deref(), Some("warn"));
    }

    #[test]
    fn verbose_overrides_quiet() {
        // 同时指定 -q -v 时 verbose 优先
        let a = parse_from(&["-q".to_string(), "-v".to_string()]);
        assert_eq!(a.log_level_override.as_deref(), Some("debug"));
    }
}
