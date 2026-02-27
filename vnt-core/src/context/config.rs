use crate::crypto::PacketCrypto;
use crate::nat::NetInput;
use crate::port_mapping::PortMapping;
use crate::tls::verifier::CertValidationMode;
use crate::tunnel_core::server::transport::config::{ConnectRegConfig, ProtocolAddress};
use anyhow::bail;
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::net::Ipv4Addr;

pub const MAX_NETWORK_CODE_LEN: usize = 32;
pub const MAX_DEVICE_ID_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 128;
pub const MAX_VERSION_LEN: usize = 32;
pub const MAX_MTU: u16 = 1500;

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub server_addr: Vec<ProtocolAddress>,
    pub cert_mode: CertValidationMode,
    pub network_code: String,
    pub device_id: String,
    pub device_name: String,
    pub tun_name: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub password: Option<String>,
    pub no_punch: bool,
    pub compress: bool,
    pub rtx: bool,
    pub fec: bool,
    pub input: Vec<NetInput>,
    pub output: Vec<Ipv4Net>,
    pub no_nat: bool,
    pub no_tun: bool,
    pub mtu: Option<u16>,
    pub port_mapping: Vec<PortMapping>,
    pub allow_port_mapping: bool,
    pub udp_stun: Vec<String>,
    pub tcp_stun: Vec<String>,
    pub tunnel_port: Option<u16>,
}
impl Config {
    pub fn check(&self) -> anyhow::Result<()> {
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
    pub(crate) fn to_connect_config(&self, index: usize) -> ConnectRegConfig {
        ConnectRegConfig {
            server_addr: self.server_addr[index].clone(),
            cert_mode: self.cert_mode.clone(),
            network_code: self.network_code.clone(),
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            ip: self.ip,
            key_sign: self.key_sign(),
            ip_variable: self.ip.is_none(),
        }
    }
}
