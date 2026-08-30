use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
use crate::tls::verifier::CertValidationMode;
use anyhow::Context;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use rust_p2p_core::socket::LocalInterface;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct SharedRegistrationIp {
    inner: Arc<Mutex<Option<Ipv4Addr>>>,
}
impl SharedRegistrationIp {
    pub fn new(ip: Option<Ipv4Addr>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ip)),
        }
    }
    pub fn get(&self) -> Option<Ipv4Addr> {
        *self.inner.lock()
    }
    pub fn set(&self, ip: Ipv4Addr) {
        *self.inner.lock() = Some(ip);
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnectRegConfig {
    pub server_addr: ProtocolAddress,
    pub cert_mode: CertValidationMode,
    pub network_code: String,
    pub device_id: String,
    pub device_name: String,
    pub ip: SharedRegistrationIp,
    pub key_sign: Option<String>,
    pub ip_variable: bool,
    pub default_interface: Option<LocalInterface>,
}
#[derive(Debug, Clone)]
pub(crate) struct ConnectConfig {
    pub protocol_type: ProtocolType,
    pub server_addr: SocketAddr,
    pub server_domain: String,
    pub cert_mode: CertValidationMode,
    pub default_interface: Option<LocalInterface>,
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum ProtocolType {
    Quic,
    #[default]
    TlsTcp,
    Wss,
    Dynamic,
}
#[derive(Debug, Clone)]
pub struct ProtocolAddress {
    pub protocol_type: ProtocolType,
    pub address: String,
}
impl Default for ProtocolAddress {
    fn default() -> Self {
        Self {
            protocol_type: ProtocolType::default(),
            address: "127.0.0.1:29872".to_string(),
        }
    }
}
impl FromStr for ProtocolAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (protocol_type, server_addr) = parse_server(s)?;
        Ok(Self {
            protocol_type,
            address: server_addr,
        })
    }
}
impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self.protocol_type {
            ProtocolType::Quic => "quic://",
            ProtocolType::TlsTcp => "tcp://",
            ProtocolType::Wss => "wss://",
            ProtocolType::Dynamic => "dynamic://",
        };
        write!(f, "{}{}", prefix, self.address)
    }
}
pub fn parse_server(val: &str) -> Result<(ProtocolType, String), String> {
    let val = val.trim().to_lowercase();
    if let Some(s) = val.strip_prefix("quic://") {
        return Ok((ProtocolType::Quic, s.to_string()));
    }
    if let Some(s) = val.strip_prefix("tcp://") {
        return Ok((ProtocolType::TlsTcp, s.to_string()));
    }
    if let Some(s) = val.strip_prefix("wss://") {
        return Ok((ProtocolType::Wss, s.to_string()));
    }
    if let Some(s) = val.strip_prefix("dynamic://") {
        return Ok((ProtocolType::Dynamic, s.to_string()));
    }
    if val.contains("://") {
        return Err(format!("Unknown protocol in server address: {}", val));
    }
    Ok((ProtocolType::TlsTcp, val))
}
impl ConnectRegConfig {
    pub fn reg_msg_request(
        &self,
        server_id: u32,
        registration_mode: RegistrationMode,
    ) -> RegRequestMsg {
        RegRequestMsg {
            network_code: self.network_code.to_string(),
            device_id: self.device_id.to_string(),
            ip: self.ip.get(),
            name: self.device_name.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            key_sign: self.key_sign.clone(),
            ip_variable: self.ip_variable,
            server_id,
            registration_mode,
        }
    }
    pub async fn to_connect_config(&self) -> anyhow::Result<ConnectConfig> {
        let (protocol_type, server_domain) = match self.server_addr.protocol_type {
            ProtocolType::Dynamic => {
                let mut txt = crate::utils::dns_query::dns_query_txt(
                    &self.server_addr.address,
                    vec![],
                    &self.default_interface,
                )
                .await?;
                txt.shuffle(&mut rand::rng());
                let x = txt.first().context("DNS query failed")?;
                let x = x.to_lowercase();
                let (protocol_type, domain) = parse_dynamic_txt(&x);
                (protocol_type, domain.to_owned())
            }
            v => (v, self.server_addr.address.to_string()),
        };
        let server_addr = crate::utils::dns_query::dns_query_one(
            &server_domain,
            &vec![],
            &self.default_interface,
        )
        .await?;
        let server_domain = strip_port(&server_domain).to_owned();
        Ok(ConnectConfig {
            protocol_type,
            server_addr,
            server_domain,
            cert_mode: self.cert_mode.clone(),
            default_interface: self.default_interface.clone(),
        })
    }
}
/// 解析动态 DNS TXT 记录中的协议前缀。
/// 注意 wss:// 必须映射到 Wss（此前错映射为 TlsTcp，导致动态发现模式下
/// WSS 实际不可用）。
fn parse_dynamic_txt(txt: &str) -> (ProtocolType, &str) {
    if let Some(v) = txt.strip_prefix("udp://") {
        (ProtocolType::Quic, v)
    } else if let Some(v) = txt.strip_prefix("quic://") {
        (ProtocolType::Quic, v)
    } else if let Some(v) = txt.strip_prefix("tcp://") {
        (ProtocolType::TlsTcp, v)
    } else if let Some(v) = txt.strip_prefix("ws://") {
        (ProtocolType::TlsTcp, v)
    } else if let Some(v) = txt.strip_prefix("wss://") {
        (ProtocolType::Wss, v)
    } else {
        (ProtocolType::TlsTcp, txt)
    }
}

fn strip_port(addr: &str) -> &str {
    if let Some(stripped) = addr.strip_prefix('[')
        && let Some(pos) = stripped.find(']')
    {
        return &stripped[..pos];
    }

    if addr.contains(':') && !addr.contains('.') && addr.matches(':').count() > 1 {
        return addr;
    }

    if let Some((host, port)) = addr.rsplit_once(':')
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host;
    }

    addr
}
impl ConnectConfig {
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }
    pub fn server_name(&self) -> &String {
        &self.server_domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_request_reads_latest_shared_ip() {
        let initial_ip = Ipv4Addr::new(10, 26, 0, 2);
        let updated_ip = Ipv4Addr::new(10, 26, 0, 9);
        let shared_ip = SharedRegistrationIp::new(Some(initial_ip));
        let config = ConnectRegConfig {
            server_addr: ProtocolAddress::default(),
            cert_mode: CertValidationMode::default(),
            network_code: "test".to_string(),
            device_id: "device".to_string(),
            device_name: "device".to_string(),
            ip: shared_ip.clone(),
            key_sign: None,
            ip_variable: true,
            default_interface: None,
        };

        assert_eq!(
            config.reg_msg_request(0, RegistrationMode::Normal).ip,
            Some(initial_ip)
        );
        shared_ip.set(updated_ip);
        assert_eq!(
            config.reg_msg_request(0, RegistrationMode::Normal).ip,
            Some(updated_ip)
        );
    }

    /// 动态 DNS TXT 记录中的 wss:// 必须映射为 Wss，
    /// 其余前缀维持原有映射不变
    #[test]
    fn test_parse_dynamic_txt() {
        assert_eq!(
            parse_dynamic_txt("wss://example.com:443"),
            (ProtocolType::Wss, "example.com:443")
        );
        assert_eq!(
            parse_dynamic_txt("quic://example.com:29872"),
            (ProtocolType::Quic, "example.com:29872")
        );
        assert_eq!(
            parse_dynamic_txt("udp://example.com:29872"),
            (ProtocolType::Quic, "example.com:29872")
        );
        assert_eq!(
            parse_dynamic_txt("tcp://example.com:29872"),
            (ProtocolType::TlsTcp, "example.com:29872")
        );
        assert_eq!(
            parse_dynamic_txt("ws://example.com:80"),
            (ProtocolType::TlsTcp, "example.com:80")
        );
        assert_eq!(
            parse_dynamic_txt("example.com:29872"),
            (ProtocolType::TlsTcp, "example.com:29872")
        );
    }
}
