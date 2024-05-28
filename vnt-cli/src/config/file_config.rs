use anyhow::anyhow;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::config::get_device_id;
use vnt::channel::punch::PunchModel;
use vnt::channel::UseChannelType;
use vnt::cipher::CipherModel;
use vnt::compression::Compressor;
use vnt::core::Config;

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct FileConfig {
    #[cfg(target_os = "windows")]
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: String,
    pub stun_server: Vec<String>,
    pub dns: Vec<String>,
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
    pub cipher_model: Option<String>,
    pub finger: bool,
    pub punch_model: String,
    pub ports: Option<Vec<u16>>,
    pub cmd: bool,
    pub first_latency: bool,
    pub device_name: Option<String>,
    pub packet_loss: Option<f64>,
    pub packet_delay: u32,
    #[cfg(feature = "port_mapping")]
    pub mapping: Vec<String>,
    pub compressor: Option<String>,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            tap: false,
            token: "".to_string(),
            device_id: get_device_id(),
            name: os_info::get().to_string(),
            server_address: "nat1.wherewego.top:29872".to_string(),
            stun_server: vec![
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun.miwifi.com:3478".to_string(),
            ],
            dns: vec![],
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
            cipher_model: None,
            finger: false,
            punch_model: "all".to_string(),
            ports: None,
            cmd: false,
            first_latency: false,
            device_name: None,
            packet_loss: None,
            packet_delay: 0,
            #[cfg(feature = "port_mapping")]
            mapping: vec![],
            compressor: None,
        }
    }
}

pub fn read_config(file_path: &str) -> anyhow::Result<(Config, bool)> {
    let conf = std::fs::read_to_string(file_path)?;
    let file_conf = match serde_yaml::from_str::<FileConfig>(&conf) {
        Ok(val) => val,
        Err(e) => {
            log::error!("{:?}", e);
            return Err(anyhow!("{}", e));
        }
    };
    if file_conf.token.is_empty() {
        return Err(anyhow!("token is_empty"));
    }

    let in_ips = match common::args_parse::ips_parse(&file_conf.in_ips) {
        Ok(in_ips) => in_ips,
        Err(e) => {
            return Err(anyhow!("in_ips {:?} error:{}", &file_conf.in_ips, e));
        }
    };
    let out_ips = match common::args_parse::out_ips_parse(&file_conf.out_ips) {
        Ok(out_ips) => out_ips,
        Err(e) => {
            return Err(anyhow!("out_ips {:?} error:{}", &file_conf.out_ips, e));
        }
    };
    let virtual_ip = match file_conf.ip.clone().map(|v| Ipv4Addr::from_str(&v)) {
        None => None,
        Some(r) => Some(r.map_err(|e| anyhow!("ip {:?} error:{}", &file_conf.ip, e))?),
    };
    let cipher_model = {
        #[cfg(not(any(feature = "aes_gcm", feature = "server_encrypt")))]
        if file_conf.password.is_some() && file_conf.cipher_model.is_none() {
            Err(anyhow!("cipher_model undefined"))?
        }
        #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
        CipherModel::AesGcm
    };

    let punch_model = PunchModel::from_str(&file_conf.punch_model).map_err(|e| anyhow!("{}", e))?;
    let use_channel_type =
        UseChannelType::from_str(&file_conf.use_channel).map_err(|e| anyhow!("{}", e))?;
    let compressor = if let Some(compressor) = file_conf.compressor.as_ref() {
        Compressor::from_str(compressor).map_err(|e| anyhow!("{}", e))?
    } else {
        Compressor::None
    };
    let config = Config::new(
        #[cfg(target_os = "windows")]
        file_conf.tap,
        file_conf.token,
        file_conf.device_id,
        file_conf.name,
        file_conf.server_address,
        file_conf.dns,
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
        file_conf.packet_delay,
        #[cfg(feature = "port_mapping")]
        file_conf.mapping,
        compressor,
    )?;
    Ok((config, file_conf.cmd))
}
