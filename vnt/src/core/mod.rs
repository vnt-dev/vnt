use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

pub use conn::Vnt;

use crate::channel::punch::PunchModel;
use crate::channel::UseChannelType;
use crate::cipher::CipherModel;
use crate::compression::Compressor;
use crate::util::{address_choose, dns_query_all};

mod conn;

#[derive(Clone, Debug)]
pub struct Config {
    #[cfg(target_os = "windows")]
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: SocketAddr,
    pub server_address_str: String,
    pub name_servers: Vec<String>,
    pub stun_server: Vec<String>,
    pub in_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub out_ips: Vec<(u32, u32)>,
    pub password: Option<String>,
    pub mtu: Option<u32>,
    pub tcp: bool,
    pub ip: Option<Ipv4Addr>,
    #[cfg(feature = "ip_proxy")]
    pub no_proxy: bool,
    pub server_encrypt: bool,
    pub cipher_model: CipherModel,
    pub finger: bool,
    pub punch_model: PunchModel,
    pub ports: Option<Vec<u16>>,
    pub first_latency: bool,
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    pub use_channel_type: UseChannelType,
    //控制丢包率
    pub packet_loss_rate: Option<f64>,
    pub packet_delay: u32,
    // 端口映射
    #[cfg(feature = "port_mapping")]
    pub port_mapping_list: Vec<(bool, SocketAddr, String)>,
    pub compressor: Compressor,
}

impl Config {
    pub fn new(
        #[cfg(target_os = "windows")] tap: bool,
        token: String,
        device_id: String,
        name: String,
        server_address_str: String,
        mut name_servers: Vec<String>,
        mut stun_server: Vec<String>,
        mut in_ips: Vec<(u32, u32, Ipv4Addr)>,
        out_ips: Vec<(u32, u32)>,
        password: Option<String>,
        mtu: Option<u32>,
        tcp: bool,
        ip: Option<Ipv4Addr>,
        #[cfg(feature = "ip_proxy")] no_proxy: bool,
        server_encrypt: bool,
        cipher_model: CipherModel,
        finger: bool,
        punch_model: PunchModel,
        ports: Option<Vec<u16>>,
        first_latency: bool,
        #[cfg(not(target_os = "android"))] device_name: Option<String>,
        use_channel_type: UseChannelType,
        packet_loss_rate: Option<f64>,
        packet_delay: u32,
        // 例如 [udp:127.0.0.1:80->10.26.0.10:8080,tcp:127.0.0.1:80->10.26.0.10:8080]
        #[cfg(feature = "port_mapping")] port_mapping_list: Vec<String>,
        compressor: Compressor,
    ) -> anyhow::Result<Self> {
        for x in stun_server.iter_mut() {
            if !x.contains(":") {
                x.push_str(":3478");
            }
        }
        for x in name_servers.iter_mut() {
            if Ipv6Addr::from_str(x).is_ok() {
                x.push_str(":53");
            } else if !x.contains(":") {
                x.push_str(":53");
            }
        }
        if token.is_empty() || token.len() > 128 {
            return Err(anyhow!("token too long"));
        }
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(anyhow!("device_id too long"));
        }
        if name.is_empty() || name.len() > 128 {
            return Err(anyhow!("name too long"));
        }
        let server_address =
            address_choose(dns_query_all(&server_address_str, name_servers.clone())?)?;
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = crate::port_mapping::convert(port_mapping_list)?;

        for (dest, mask, _) in &mut in_ips {
            *dest = *mask & *dest;
        }
        in_ips.sort_by(|(dest1, _, _), (dest2, _, _)| dest2.cmp(dest1));
        Ok(Self {
            #[cfg(target_os = "windows")]
            tap,
            token,
            device_id,
            name,
            server_address,
            server_address_str,
            name_servers,
            stun_server,
            in_ips,
            out_ips,
            password,
            mtu,
            tcp,
            ip,
            #[cfg(feature = "ip_proxy")]
            no_proxy,
            server_encrypt,
            cipher_model,
            finger,
            punch_model,
            ports,
            first_latency,
            #[cfg(not(target_os = "android"))]
            device_name,
            use_channel_type,
            packet_loss_rate,
            packet_delay,
            #[cfg(feature = "port_mapping")]
            port_mapping_list,
            compressor,
        })
    }
}

impl Config {
    pub fn password_hash(&self) -> Option<[u8; 16]> {
        if let Some(p) = self.password.as_ref() {
            match self.cipher_model {
                CipherModel::Xor => {
                    let key = crate::cipher::simple_hash(&format!("Xor{}{}", p, self.token));
                    Some(key[16..].try_into().unwrap())
                }
                CipherModel::None => None,
                #[cfg(cipher)]
                _ => {
                    use sha2::Digest;
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(self.cipher_model.to_string().as_bytes());
                    hasher.update(p.as_bytes());
                    hasher.update(self.token.as_bytes());
                    let key: [u8; 32] = hasher.finalize().into();
                    Some(key[16..].try_into().unwrap())
                }
            }
        } else {
            None
        }
    }
}
