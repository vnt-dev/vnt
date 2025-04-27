use anyhow::anyhow;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

pub use conn::Vnt;

use crate::channel::punch::PunchModel;
use crate::channel::socket::LocalInterface;
use crate::channel::{ConnectProtocol, UseChannelType};
use crate::cipher::CipherModel;
use crate::compression::Compressor;
use crate::util::{address_choose, dns_query_all};

mod conn;

#[derive(Clone, Debug)]
pub struct Config {
    #[cfg(feature = "integrated_tun")]
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
    pub protocol: ConnectProtocol,
    pub ip: Option<Ipv4Addr>,
    #[cfg(feature = "ip_proxy")]
    #[cfg(feature = "integrated_tun")]
    pub no_proxy: bool,
    pub server_encrypt: bool,
    pub cipher_model: CipherModel,
    pub finger: bool,
    pub punch_model: PunchModel,
    pub ports: Option<Vec<u16>>,
    pub first_latency: bool,
    #[cfg(feature = "integrated_tun")]
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
    pub enable_traffic: bool,
    pub allow_wire_guard: bool,
    pub local_ipv4: Option<Ipv4Addr>,
    pub local_interface: LocalInterface,
}

impl Config {
    pub fn new(
        #[cfg(feature = "integrated_tun")]
        #[cfg(target_os = "windows")]
        tap: bool,
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
        ip: Option<Ipv4Addr>,
        #[cfg(feature = "integrated_tun")]
        #[cfg(feature = "ip_proxy")]
        no_proxy: bool,
        server_encrypt: bool,
        cipher_model: CipherModel,
        finger: bool,
        punch_model: PunchModel,
        ports: Option<Vec<u16>>,
        first_latency: bool,
        #[cfg(feature = "integrated_tun")]
        #[cfg(not(target_os = "android"))]
        device_name: Option<String>,
        use_channel_type: UseChannelType,
        packet_loss_rate: Option<f64>,
        packet_delay: u32,
        // 例如 [udp:127.0.0.1:80->10.26.0.10:8080,tcp:127.0.0.1:80->10.26.0.10:8080]
        #[cfg(feature = "port_mapping")] port_mapping_list: Vec<String>,
        compressor: Compressor,
        enable_traffic: bool,
        // 允许传递wg流量
        allow_wire_guard: bool,
        local_dev: Option<String>,
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
        let mut server_address_str = server_address_str.to_lowercase();
        let mut _query_dns = true;
        let mut protocol = ConnectProtocol::UDP;
        if server_address_str.starts_with("ws://") {
            #[cfg(not(feature = "ws"))]
            Err(anyhow!("Ws not supported"))?;
            protocol = ConnectProtocol::WS;
            _query_dns = false;
        }
        if server_address_str.starts_with("wss://") {
            #[cfg(not(feature = "wss"))]
            Err(anyhow!("Wss not supported"))?;
            protocol = ConnectProtocol::WSS;
            _query_dns = false;
        }

        let mut server_address = "0.0.0.0:0".parse().unwrap();
        if _query_dns {
            if let Some(s) = server_address_str.strip_prefix("udp://") {
                server_address_str = s.to_string();
            } else if let Some(s) = server_address_str.strip_prefix("tcp://") {
                server_address_str = s.to_string();
                protocol = ConnectProtocol::TCP;
            }
            let address_result = dns_query_all(
                &server_address_str,
                name_servers.clone(),
                &LocalInterface::default(),
            );
            match address_result {
                Ok(address) => {
                    match address_choose(address) {
                        Ok(resolved_address) => {
                            server_address = resolved_address; 
                        }
                        Err(e) => {
                            log::error!("Failed to choose address: {}", e);
                            println!("Failed to choose address: {}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("DNS query failed: {}", e);
                    println!("DNS query failed: {}", e);
                }
            }
        }
        
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = crate::port_mapping::convert(port_mapping_list)?;

        for (dest, mask, _) in &mut in_ips {
            *dest = *mask & *dest;
        }
        in_ips.sort_by(|(dest1, _, _), (dest2, _, _)| dest2.cmp(dest1));
        let (local_interface, local_ipv4) = if let Some(local_dev) = local_dev {
            let (default_interface, ip) = crate::channel::socket::get_interface(local_dev)?;
            log::info!("default_interface = {:?} local_ip= {ip}", default_interface);
            (default_interface, Some(ip))
        } else {
            (LocalInterface::default(), None)
        };
        Ok(Self {
            #[cfg(feature = "integrated_tun")]
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
            protocol,
            ip,
            #[cfg(feature = "ip_proxy")]
            #[cfg(feature = "integrated_tun")]
            no_proxy,
            server_encrypt,
            cipher_model,
            finger,
            punch_model,
            ports,
            first_latency,
            #[cfg(feature = "integrated_tun")]
            #[cfg(not(target_os = "android"))]
            device_name,
            use_channel_type,
            packet_loss_rate,
            packet_delay,
            #[cfg(feature = "port_mapping")]
            port_mapping_list,
            compressor,
            enable_traffic,
            allow_wire_guard,
            local_ipv4,
            local_interface,
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
