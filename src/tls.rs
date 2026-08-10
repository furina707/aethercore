//! TLS 加密传输层：构建服务端/客户端 rustls 配置，支持 mTLS。
use anyhow::Result;
use rustls::{ServerConfig, ClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// 构造服务端 TLS 配置（可用于 HTTPS 代理、TLS 包装的 SOCKS）。
/// 若提供 client_ca，则启用双向认证 (mTLS)。
pub fn build_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca: Option<&str>,
) -> Result<ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    if let Some(ca_path) = client_ca {
        let ca = load_certs(ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        for c in ca {
            roots.add(c)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?;
        Ok(config)
    } else {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Ok(config)
    }
}

/// 构造客户端 TLS 配置。
pub fn build_client_config(sni: &str) -> Result<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let _ = sni;
    Ok(config)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let key = rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| anyhow::anyhow!("无私钥"))?;
    Ok(key)
}
