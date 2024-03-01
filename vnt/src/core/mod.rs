use std::io;
use std::net::{Ipv4Addr, SocketAddr};

pub use conn::Vnt;

use crate::channel::punch::PunchModel;
use crate::channel::UseChannelType;
use crate::cipher::CipherModel;

mod conn;

#[derive(Clone, Debug)]
pub struct Config {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: SocketAddr,
    pub server_address_str: String,
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
    pub parallel: usize,
    pub cipher_model: CipherModel,
    pub finger: bool,
    pub punch_model: PunchModel,
    pub ports: Option<Vec<u16>>,
    pub first_latency: bool,
    #[cfg(not(target_os = "android"))]
    pub device_name: Option<String>,
    #[cfg(target_os = "android")]
    pub device_fd: i32,
    pub use_channel_type: UseChannelType,
}

impl Config {
    pub fn new(
        #[cfg(any(target_os = "windows", target_os = "linux"))] tap: bool,
        token: String,
        device_id: String,
        name: String,
        server_address: SocketAddr,
        server_address_str: String,
        mut stun_server: Vec<String>,
        in_ips: Vec<(u32, u32, Ipv4Addr)>,
        out_ips: Vec<(u32, u32)>,
        password: Option<String>,
        mtu: Option<u32>,
        tcp: bool,
        ip: Option<Ipv4Addr>,
        #[cfg(feature = "ip_proxy")] no_proxy: bool,
        server_encrypt: bool,
        parallel: usize,
        cipher_model: CipherModel,
        finger: bool,
        punch_model: PunchModel,
        ports: Option<Vec<u16>>,
        first_latency: bool,
        #[cfg(not(target_os = "android"))] device_name: Option<String>,
        #[cfg(target_os = "android")] device_fd: i32,
        use_channel_type: UseChannelType,
    ) -> io::Result<Self> {
        for x in stun_server.iter_mut() {
            if !x.contains(":") {
                x.push_str(":3478");
            }
        }
        if token.is_empty() || token.len() > 128 {
            return Err(io::Error::new(io::ErrorKind::Other, "token too long"));
        }
        if device_id.is_empty() || device_id.len() > 128 {
            return Err(io::Error::new(io::ErrorKind::Other, "device_id too long"));
        }
        if name.is_empty() || name.len() > 128 {
            return Err(io::Error::new(io::ErrorKind::Other, "name too long"));
        }
        Ok(Self {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            tap,
            token,
            device_id,
            name,
            server_address,
            server_address_str,
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
            parallel,
            cipher_model,
            finger,
            punch_model,
            ports,
            first_latency,
            #[cfg(not(target_os = "android"))]
            device_name,
            #[cfg(target_os = "android")]
            device_fd,
            use_channel_type,
        })
    }
}
