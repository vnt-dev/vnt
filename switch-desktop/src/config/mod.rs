use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use lazy_static::lazy_static;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::StartArgs;

pub mod log_config;

pub struct StartConfig {
    pub name: String,
    pub token: String,
    pub server: SocketAddr,
    pub nat_test_server: Vec<SocketAddr>,
    pub device_id: String,
}

pub fn default_config(start_args: StartArgs) -> Result<StartConfig, String> {
    let args_config = read_config();
    if args_config.is_none() && start_args.token.is_none() {
        return Err("找不到token(Token not found)".to_string());
    }
    let token = start_args.token.unwrap_or_else(|| args_config.as_ref().unwrap().token.clone()).trim().to_string();
    if token.is_empty() {
        return Err("token不能为空(Token cannot be empty)".to_string());
    }
    if token.len() > 64 {
        return Err("token不能超过64字符(Token cannot exceed 64 characters)".to_string());
    }
    let name = start_args.name.unwrap_or_else(|| {
        if let Some(c) = &args_config {
            if !c.name.is_empty() {
                return c.name.clone();
            }
        }
        os_info::get().to_string()
    });
    let name = name.trim();
    let name = if name.len() > 64 {
        name[..64].to_string()
    } else {
        name.to_string()
    };
    let device_id = start_args.device_id.unwrap_or_else(|| {
        if let Some(c) = &args_config {
            if !c.device_id.is_empty() {
                return c.device_id.clone();
            }
        }
        if let Ok(Some(mac_address)) = mac_address::get_mac_address() {
            mac_address.to_string()
        } else {
            "".to_string()
        }
    });
    if device_id.is_empty() || device_id.len() > 64 {
        return Err("设备id不能为空并且长度不能大于64字符(The device id cannot be empty and the length cannot be greater than 64 characters)".to_string());
    }
    let server = match start_args.server.unwrap_or_else(|| {
        if let Some(c) = &args_config {
            if !c.server.is_empty() {
                return c.server.clone();
            }
        }
        "nat1.wherewego.top:29871".to_string()
    }).to_socket_addrs() {
        Ok(mut server) => {
            if let Some(addr) = server.next() {
                addr
            } else {
                return Err("中继服务器地址错误( Relay server address error)".to_string());
            }
        }
        Err(e) => {
            return Err(format!("中继服务器地址错误( Relay server address error) :{:?}", e));
        }
    };
    let nat_test_server = start_args.nat_test_server.unwrap_or_else(|| {
        if let Some(c) = &args_config {
            if !c.nat_test_server.is_empty() {
                return c.nat_test_server.join(",");
            }
        }
        "nat1.wherewego.top:35061,nat1.wherewego.top:35062,nat2.wherewego.top:35061,nat2.wherewego.top:35062".to_string()
    }).split(",").flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();
    if nat_test_server.is_empty() {
        return Err("NAT检测服务地址错误(NAT detection service address error)".to_string());
    }
    let base_config = StartConfig {
        name,
        token,
        server,
        nat_test_server,
        device_id,
    };
    Ok(base_config)
}

lazy_static! {
    static ref CONFIG: Mutex<Option<ArgsConfig>> = Mutex::new(None);
    pub static ref SWITCH_HOME_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgsConfig {
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_str")]
    pub token: String,
    #[serde(default = "default_str")]
    pub name: String,
    pub command_port: Option<u16>,
    #[serde(default = "default_str")]
    pub server: String,
    #[serde(default = "default_resource_vec")]
    pub nat_test_server: Vec<String>,
    #[serde(default = "default_str")]
    pub device_id: String,
    #[serde(default = "default_pid")]
    pub pid: u32,
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_str() -> String {
    "".to_string()
}

fn default_resource_vec() -> Vec<String> {
    vec![]
}

fn default_pid() -> u32 {
    0
}

impl ArgsConfig {
    pub fn new(token: String, name: String, server: String, nat_test_server: Vec<String>, device_id: String) -> Self {
        Self {
            version: "1.0".to_string(),
            token,
            name,
            command_port: None,
            server,
            nat_test_server,
            device_id,
            pid: 0,
        }
    }
}
use fd_lock::RwLock;
pub fn lock_config() -> io::Result<RwLock<File>> {
    let config_path = SWITCH_HOME_PATH.lock().clone().unwrap().join("config");
    Ok(RwLock::new(File::open(config_path)?))
}

pub fn save_config(config: ArgsConfig) -> io::Result<()> {
    let config_path = SWITCH_HOME_PATH.lock().clone().unwrap().join("config");
    save_config_(config, config_path)
}

fn save_config_(config: ArgsConfig, config_path: PathBuf) -> io::Result<()> {
    let mut config_lock = CONFIG.lock();
    config_lock.take();
    let str = serde_yaml::to_string(&config).unwrap();
    let mut file = File::create(config_path)?;
    file.write_all(str.as_bytes())
}

pub fn update_pid(pid: u32) -> io::Result<()> {
    let home_lock = SWITCH_HOME_PATH.lock();
    if let Some(home) = home_lock.clone() {
        drop(home_lock);
        let config_path = home.join("config");
        if let Some(mut config) = read_config() {
            config.pid = pid;
            return save_config_(config, config_path);
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "not found"))
}

#[cfg(any(unix))]
pub fn read_pid() -> io::Result<u32> {
    let home = SWITCH_HOME_PATH.lock().clone().unwrap();
    let config = read_config_(home)?;
    Ok(config.pid)
}

pub fn update_command_port(port: u16) -> io::Result<()> {
    let home_lock = SWITCH_HOME_PATH.lock();
    if let Some(home) = home_lock.clone() {
        drop(home_lock);
        let config_path = home.join("config");
        if let Some(mut config) = read_config() {
            config.command_port = Some(port);
            return save_config_(config, config_path);
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "not found"))
}

pub fn read_command_port() -> io::Result<u16> {
    let home = SWITCH_HOME_PATH.lock().clone().unwrap();
    let config = read_config_(home)?;
    if let Some(p) = config.command_port {
        Ok(p)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "not fount config"))
    }
}

pub fn read_config() -> Option<ArgsConfig> {
    let mut lock = CONFIG.lock();
    let c = lock.clone();
    if c.is_some() {
        return c;
    }
    if let Some(home) = SWITCH_HOME_PATH.lock().clone() {
        match read_config_(home.to_path_buf()) {
            Ok(config) => {
                lock.replace(config.clone());
                Some(config)
            }
            Err(e) => {
                log::error!("{:?},path:{:?}", e,home);
                None
            }
        }
    } else {
        None
    }
}

pub fn set_home(home: PathBuf) {
    SWITCH_HOME_PATH.lock().replace(home);
}

fn read_config_(home: PathBuf) -> io::Result<ArgsConfig> {
    let config_path = home.join("config");
    let mut file = if config_path.exists() {
        File::open(config_path)?
    } else {
        OpenOptions::new().read(true).write(true).truncate(false).create(true).open(config_path)?
    };
    let mut str = String::new();
    file.read_to_string(&mut str)?;
    match serde_yaml::from_str::<ArgsConfig>(&str) {
        Ok(config) => Ok(config),
        Err(e) => {
            log::warn!("{:?}", e);
            Err(io::Error::new(io::ErrorKind::Other, "config error"))
        }
    }
}
