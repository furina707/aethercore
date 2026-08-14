//! 生成自签名证书，供本地开发/测试使用。
//! 用法: cargo run --example gen_cert
use rcgen::{CertifiedKey, generate_simple_self_signed};
use std::fs;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let dir = Path::new("certs");
    fs::create_dir_all(dir)?;
    // 主题备用名：可用于 localhost / 本机 IP
    let subject_alt_names = vec![
        "omni-proxy".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(subject_alt_names)?;
    fs::write("certs/server.crt", cert.pem())?;
    fs::write("certs/server.key", key_pair.serialize_pem())?;
    println!("已生成 certs/server.crt 与 certs/server.key");
    Ok(())
}
