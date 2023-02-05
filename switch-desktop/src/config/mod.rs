use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;

use lazy_static::lazy_static;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref CONFIG: Mutex<Option<ArgsConfig>> = Mutex::new(None);
    static ref SWITCH_HOME_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgsConfig {
    pub token: String,
    pub name: Option<String>,
    pub command_port: Option<u16>,
}

impl ArgsConfig {
    pub fn new(token: String, name: Option<String>) -> Self {
        Self {
            token,
            name,
            command_port: None,
        }
    }
}

pub fn save_config(config: ArgsConfig) -> io::Result<()> {
    let config_path = dirs::home_dir().unwrap().join(".switch").join("config");
    save_config_(config, config_path)
}

fn save_config_(config: ArgsConfig, config_path: PathBuf) -> io::Result<()> {
    let str = serde_yaml::to_string(&config).unwrap();
    let mut file = File::create(config_path)?;
    file.write_all(str.as_bytes())
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
    let home = dirs::home_dir().unwrap().join(".switch");
    let config = read_config_(home)?;
    Ok(config.command_port.unwrap())
}

pub fn read_config() -> Option<ArgsConfig> {
    let mut lock = CONFIG.lock();
    let c = lock.clone();
    if c.is_some() {
        return c;
    }
    if let Some(home) = SWITCH_HOME_PATH.lock().clone() {
        match read_config_(home) {
            Ok(config) => {
                lock.replace(config.clone());
                Some(config)
            }
            Err(e) => {
                log::error!("{:?}", e);
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
    let mut file = File::open(config_path)?;
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
