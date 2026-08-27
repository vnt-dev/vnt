use crate::crypto::PacketCrypto;
use crate::nat::NetInput;
use crate::port_mapping::PortMapping;
use crate::tls::verifier::CertValidationMode;
use crate::tunnel_core::server::transport::config::{ConnectRegConfig, ProtocolAddress};
use anyhow::bail;
use ipnet::Ipv4Net;
use rust_p2p_core::route::ConnectProtocol;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

pub const MAX_NETWORK_CODE_LEN: usize = 32;
pub const MAX_DEVICE_ID_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_VERSION_LEN: usize = 32;
pub const MAX_MTU: u16 = 1500;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum PeerProtocol {
    Both,
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PeerAddress {
    protocol: PeerProtocol,
    address: SocketAddr,
}

impl PeerAddress {
    pub fn protocol(&self) -> PeerProtocol {
        self.protocol
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn endpoints(&self) -> Vec<(ConnectProtocol, SocketAddr)> {
        match self.protocol {
            PeerProtocol::Both => vec![
                (ConnectProtocol::TCP, self.address),
                (ConnectProtocol::UDP, self.address),
            ],
            PeerProtocol::Tcp => vec![(ConnectProtocol::TCP, self.address)],
            PeerProtocol::Udp => vec![(ConnectProtocol::UDP, self.address)],
        }
    }
}

impl FromStr for PeerAddress {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let lower = value.to_ascii_lowercase();
        let (protocol, address) = if lower.starts_with("tcp://") {
            (PeerProtocol::Tcp, &value[6..])
        } else if lower.starts_with("udp://") {
            (PeerProtocol::Udp, &value[6..])
        } else if value.contains("://") {
            bail!("invalid peer protocol in '{value}', expected tcp:// or udp://")
        } else {
            (PeerProtocol::Both, value)
        };
        let address = address
            .parse::<SocketAddr>()
            .map_err(|error| anyhow::anyhow!("invalid peer address '{value}': {error}"))?;
        if address.port() == 0 {
            bail!("invalid peer address '{value}': port must not be 0")
        }
        Ok(Self { protocol, address })
    }
}

impl Display for PeerAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.protocol {
            PeerProtocol::Both => write!(f, "{}", self.address),
            PeerProtocol::Tcp => write!(f, "tcp://{}", self.address),
            PeerProtocol::Udp => write!(f, "udp://{}", self.address),
        }
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMode {
    No,
    #[default]
    Tun,
    Tap,
}

impl DeviceMode {
    pub fn has_device(self) -> bool {
        !matches!(self, Self::No)
    }
}

impl Display for DeviceMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::No => "no",
            Self::Tun => "tun",
            Self::Tap => "tap",
        })
    }
}

impl FromStr for DeviceMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "no" => Ok(Self::No),
            "tun" => Ok(Self::Tun),
            "tap" => Ok(Self::Tap),
            _ => bail!("invalid device_mode '{value}', expected one of: no, tun, tap"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub server_addr: Vec<ProtocolAddress>,
    pub peer_address: Vec<PeerAddress>,
    pub cert_mode: CertValidationMode,
    pub network_code: String,
    pub device_id: String,
    pub device_name: String,
    pub tun_name: Option<String>,
    /// 绑定 VNT 对外通信 Socket 的物理网卡名称。
    pub outbound_interface: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub password: Option<String>,
    pub no_punch: bool,
    pub compress: bool,
    pub rtx: bool,
    pub fec: bool,
    pub input: Vec<NetInput>,
    pub output: Vec<Ipv4Net>,
    pub no_nat: bool,
    pub device_mode: DeviceMode,
    pub mtu: Option<u16>,
    pub port_mapping: Vec<PortMapping>,
    pub allow_port_mapping: bool,
    pub udp_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
    pub tunnel_port: Option<u16>,
}
impl Config {
    pub fn check(&self) -> anyhow::Result<()> {
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        if self.device_mode == DeviceMode::Tap {
            bail!("TAP mode is not supported on mobile VPN interfaces");
        }
        if self.server_addr.is_empty() {
            bail!("服务器地址不能为空");
        }
        if self.server_addr.len() > 1 {
            let mut set = HashSet::new();

            for a in self.server_addr.iter() {
                if !set.insert(a.address.as_str()) {
                    bail!("服务器地址不能相同")
                }
            }
        }

        if self.network_code.len() > MAX_NETWORK_CODE_LEN {
            bail!(
                "network_code length exceeds {} characters (current: {})",
                MAX_NETWORK_CODE_LEN,
                self.network_code.len()
            )
        }

        if self.device_id.len() > MAX_DEVICE_ID_LEN {
            bail!(
                "device_id length exceeds {} characters (current: {})",
                MAX_DEVICE_ID_LEN,
                self.device_id.len()
            )
        }

        if self.device_name.len() > MAX_NAME_LEN {
            bail!(
                "name length exceeds {} characters (current: {})",
                MAX_NAME_LEN,
                self.device_name.len()
            )
        }
        if let Some(mtu) = self.mtu
            && mtu > MAX_MTU
        {
            bail!("MTU is too large (Maximum mtu: {MAX_MTU})",)
        }
        Ok(())
    }
    pub fn key_sign(&self) -> Option<String> {
        self.password.as_ref().map(|p| PacketCrypto::key_sign(p))
    }
    pub(crate) fn to_connect_config(
        &self,
        index: usize,
        default_interface: Option<rust_p2p_core::socket::LocalInterface>,
    ) -> ConnectRegConfig {
        ConnectRegConfig {
            server_addr: self.server_addr[index].clone(),
            cert_mode: self.cert_mode.clone(),
            network_code: self.network_code.clone(),
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            ip: self.ip,
            key_sign: self.key_sign(),
            ip_variable: self.ip.is_none(),
            default_interface,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_mode_parse_and_display() {
        for (text, mode) in [
            ("no", DeviceMode::No),
            ("tun", DeviceMode::Tun),
            ("tap", DeviceMode::Tap),
        ] {
            assert_eq!(text.parse::<DeviceMode>().unwrap(), mode);
            assert_eq!(mode.to_string(), text);
        }
        assert!("bridge".parse::<DeviceMode>().is_err());
        assert_eq!(DeviceMode::default(), DeviceMode::Tun);
    }

    #[test]
    fn peer_address_parse_and_display() {
        let both = " 127.0.0.1:29872 ".parse::<PeerAddress>().unwrap();
        assert_eq!(both.protocol(), PeerProtocol::Both);
        assert_eq!(both.address(), "127.0.0.1:29872".parse().unwrap());
        assert_eq!(both.to_string(), "127.0.0.1:29872");
        let endpoints = both.endpoints();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().any(|(protocol, _)| protocol.is_tcp()));
        assert!(endpoints.iter().any(|(protocol, _)| protocol.is_udp()));

        let tcp = "TCP://127.0.0.1:29872".parse::<PeerAddress>().unwrap();
        assert_eq!(tcp.protocol(), PeerProtocol::Tcp);
        assert_eq!(tcp.to_string(), "tcp://127.0.0.1:29872");

        let udp = "udp://[::1]:29872".parse::<PeerAddress>().unwrap();
        assert_eq!(udp.protocol(), PeerProtocol::Udp);
        assert_eq!(udp.to_string(), "udp://[::1]:29872");
    }

    #[test]
    fn peer_address_rejects_invalid_values() {
        for value in [
            "quic://127.0.0.1:29872",
            "example.com:29872",
            "127.0.0.1",
            "127.0.0.1:0",
        ] {
            assert!(
                value.parse::<PeerAddress>().is_err(),
                "{value} must be rejected"
            );
        }
    }
}
