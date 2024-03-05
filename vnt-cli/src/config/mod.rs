use std::io;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use vnt::channel::punch::PunchModel;
use vnt::channel::UseChannelType;
use vnt::cipher::CipherModel;
use vnt::core::Config;

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct FileConfig {
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: String,
    pub stun_server: Vec<String>,
    pub in_ips: Vec<String>,
    pub out_ips: Vec<String>,
    pub password: Option<String>,
    pub mtu: Option<u32>,
    pub tcp: bool,
    pub ip: Option<String>,
    pub use_channel: String,
    #[cfg(feature = "ip_proxy")]
    pub no_proxy: bool,
    pub server_encrypt: bool,
    pub parallel: usize,
    pub cipher_model: String,
    pub finger: bool,
    pub punch_model: String,
    pub ports: Option<Vec<u16>>,
    pub cmd: bool,
    pub first_latency: bool,
    pub device_name: Option<String>,
    pub packet_loss: Option<f64>,
    pub packet_delay: u32,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            #[cfg(any(target_os = "windows", target_os = "linux"))]
            tap: false,
            token: "".to_string(),
            device_id: get_device_id(),
            name: os_info::get().to_string(),
            server_address: "nat1.wherewego.top:29872".to_string(),
            stun_server: vec![
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun.qq.com:3478".to_string(),
            ],
            in_ips: vec![],
            out_ips: vec![],
            password: None,
            mtu: None,
            tcp: false,
            ip: None,
            use_channel: "all".to_string(),
            #[cfg(feature = "ip_proxy")]
            no_proxy: false,
            server_encrypt: false,
            parallel: 1,
            cipher_model: "aes_gcm".to_string(),
            finger: false,
            punch_model: "all".to_string(),
            ports: None,
            cmd: false,
            first_latency: false,
            device_name: None,
            packet_loss: None,
            packet_delay: 0,
        }
    }
}

pub fn read_config(file_path: &str) -> io::Result<(Config, bool)> {
    let conf = std::fs::read_to_string(file_path)?;
    let file_conf = match serde_yaml::from_str::<FileConfig>(&conf) {
        Ok(val) => val,
        Err(e) => {
            log::error!("{:?}", e);
            return Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)));
        }
    };
    if file_conf.token.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "token is_empty"));
    }
    let server_address = match file_conf.server_address.to_socket_addrs() {
        Ok(mut addr) => {
            if let Some(addr) = addr.next() {
                addr
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("server_address {:?} error", &file_conf.server_address),
                ));
            }
        }
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("server_address {:?} error:{}", &file_conf.server_address, e),
            ));
        }
    };
    let in_ips = match common::args_parse::ips_parse(&file_conf.in_ips) {
        Ok(in_ips) => in_ips,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("in_ips {:?} error:{}", &file_conf.in_ips, e),
            ));
        }
    };
    let out_ips = match common::args_parse::out_ips_parse(&file_conf.out_ips) {
        Ok(out_ips) => out_ips,
        Err(e) => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("out_ips {:?} error:{}", &file_conf.out_ips, e),
            ));
        }
    };
    let virtual_ip = match file_conf.ip.clone().map(|v| Ipv4Addr::from_str(&v)) {
        None => None,
        Some(r) => Some(r.map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("ip {:?} error:{}", &file_conf.ip, e),
            )
        })?),
    };

    let cipher_model = CipherModel::from_str(&file_conf.cipher_model)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let punch_model = PunchModel::from_str(&file_conf.punch_model)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let use_channel_type = UseChannelType::from_str(&file_conf.use_channel)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let config = Config::new(
        #[cfg(any(target_os = "windows", target_os = "linux"))]
        file_conf.tap,
        file_conf.token,
        file_conf.device_id,
        file_conf.name,
        server_address,
        file_conf.server_address,
        file_conf.stun_server,
        in_ips,
        out_ips,
        file_conf.password,
        file_conf.mtu,
        file_conf.tcp,
        virtual_ip,
        #[cfg(feature = "ip_proxy")]
        file_conf.no_proxy,
        file_conf.server_encrypt,
        file_conf.parallel,
        cipher_model,
        file_conf.finger,
        punch_model,
        file_conf.ports,
        file_conf.first_latency,
        file_conf.device_name,
        use_channel_type,
        file_conf.packet_loss,
        file_conf.packet_delay
    )
    .unwrap();
    Ok((config, file_conf.cmd))
}

pub fn get_device_id() -> String {
    if let Some(id) = common::identifier::get_unique_identifier() {
        id
    } else {
        let path_buf = match crate::app_home() {
            Ok(path_buf) => path_buf.join("device-id"),
            Err(e) => {
                log::warn!("{:?}", e);
                return String::new();
            }
        };
        if let Ok(id) = std::fs::read_to_string(path_buf.as_path()) {
            id
        } else {
            let id = uuid::Uuid::new_v4().to_string();
            let _ = std::fs::write(path_buf, &id);
            id
        }
    }
}
