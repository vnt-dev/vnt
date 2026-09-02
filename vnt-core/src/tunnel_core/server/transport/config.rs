use crate::protocol::control_message::{RegRequestMsg, RegistrationMode};
use crate::tls::verifier::CertValidationMode;
use anyhow::bail;
use ipnet::Ipv4Net;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use rustp2p_core::socket::LocalInterface;
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
    pub advertised_subnets: Arc<Vec<Ipv4Net>>,
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
    let trimmed = val.trim();
    let lower = trimmed.to_lowercase();
    // 前缀匹配不区分大小写；返回的地址保留原始大小写，
    // 因为 dynamic://http(s):// 的 URL 路径/查询串是区分大小写的
    if lower.starts_with("quic://") {
        return Ok((ProtocolType::Quic, trimmed[7..].to_string()));
    }
    if lower.starts_with("tcp://") {
        return Ok((ProtocolType::TlsTcp, trimmed[6..].to_string()));
    }
    if lower.starts_with("wss://") {
        return Ok((ProtocolType::Wss, trimmed[6..].to_string()));
    }
    if lower.starts_with("dynamic://") {
        return Ok((ProtocolType::Dynamic, trimmed[10..].to_string()));
    }
    if trimmed.contains("://") {
        return Err(format!("Unknown protocol in server address: {}", val));
    }
    Ok((ProtocolType::TlsTcp, trimmed.to_string()))
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
            advertised_subnets: self.advertised_subnets.as_ref().clone(),
        }
    }
    /// 解析出全部候选服务器地址：动态地址（DNS TXT 记录或 http(s) 接口返回的
    /// 地址列表）与静态地址解析出的每个 IP 对应一个 ConnectConfig，
    /// 调用方逐个尝试连接直到成功。
    pub async fn to_connect_config(&self) -> anyhow::Result<Vec<ConnectConfig>> {
        let server_domains: Vec<(ProtocolType, String)> = match self.server_addr.protocol_type {
            ProtocolType::Dynamic => {
                // 动态发现：默认用 DNS TXT 记录；也支持填入 http(s) 接口，
                // 如 dynamic://https://example.com/servers，响应为换行分隔的
                // 服务器地址列表（每行同样支持 tcp:// quic:// wss:// 前缀）
                let address = &self.server_addr.address;
                let lower_address = address.to_lowercase();
                let entries: Vec<String> = if lower_address.starts_with("http://")
                    || lower_address.starts_with("https://")
                {
                    // HTTP(S) 接口：按返回顺序连接，服务端可自行控制优先级
                    let body = crate::utils::http_get::http_get_text(address).await?;
                    body.lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(str::to_string)
                        .collect()
                } else {
                    // DNS TXT 记录的顺序无意义，随机化以分散负载
                    let mut txt = crate::utils::dns_query::dns_query_txt(
                        address,
                        vec![],
                        &self.default_interface,
                    )
                    .await?;
                    txt.shuffle(&mut rand::rng());
                    txt
                };
                entries
                    .into_iter()
                    .map(|x| {
                        let x = x.to_lowercase();
                        let (protocol_type, domain) = parse_dynamic_txt(&x);
                        (protocol_type, domain.to_owned())
                    })
                    .collect()
            }
            v => vec![(v, self.server_addr.address.to_string())],
        };

        let mut connect_configs = Vec::new();
        for (protocol_type, server_domain) in server_domains {
            // DNS 只负责解析 IP，端口由调用方从地址中解析后自行拼装
            let (host, port) = match crate::utils::addr::split_host_port(&server_domain) {
                Ok(v) => v,
                Err(error) => {
                    log::warn!("invalid server address {server_domain:?}: {error:#}");
                    continue;
                }
            };
            let addrs = match crate::utils::dns_query::dns_query_all(
                host,
                &vec![],
                &self.default_interface,
            )
            .await
            {
                Ok(addrs) => addrs,
                Err(error) => {
                    log::warn!("DNS query failed for {host:?}: {error:#}");
                    continue;
                }
            };
            connect_configs.extend(addrs.into_iter().map(|ip| ConnectConfig {
                protocol_type,
                server_addr: SocketAddr::new(ip, port),
                server_domain: host.to_owned(),
                cert_mode: self.cert_mode.clone(),
                default_interface: self.default_interface.clone(),
            }));
        }
        if connect_configs.is_empty() {
            bail!(
                "no server address resolved for {}",
                self.server_addr.address
            );
        }
        Ok(connect_configs)
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
            advertised_subnets: Arc::new(Vec::new()),
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

    /// 协议前缀不区分大小写，但 dynamic://http(s):// 的 URL 地址必须保留
    /// 原始大小写（路径/查询串区分大小写）
    #[test]
    fn test_parse_server_preserves_url_case() {
        assert_eq!(
            parse_server("dynamic://HTTPS://Example.com/API/GetServers?token=AbC"),
            Ok((
                ProtocolType::Dynamic,
                "HTTPS://Example.com/API/GetServers?token=AbC".to_string()
            ))
        );
        assert_eq!(
            parse_server("DYNAMIC://http://127.0.0.1:8080/servers"),
            Ok((
                ProtocolType::Dynamic,
                "http://127.0.0.1:8080/servers".to_string()
            ))
        );
        assert_eq!(
            parse_server("TCP://Example.com:29872"),
            Ok((ProtocolType::TlsTcp, "Example.com:29872".to_string()))
        );
    }
}
