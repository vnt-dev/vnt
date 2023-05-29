use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use lazy_static::lazy_static;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::StartArgs;

pub mod log_config;
lazy_static! {
    pub static ref SWITCH_HOME_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
}

#[cfg(windows)]
pub fn get_win_server_home() -> PathBuf {
    SWITCH_HOME_PATH.lock().as_ref().unwrap().clone()
}

#[cfg(windows)]
pub fn set_win_server_home(home: PathBuf) {
    let _ = SWITCH_HOME_PATH.lock().insert(home);
}

pub struct StartConfig {
    pub tap: bool,
    pub name: String,
    pub token: String,
    pub server: SocketAddr,
    pub nat_test_server: Vec<SocketAddr>,
    pub device_id: String,
    pub in_ips: Vec<(u32, u32, Ipv4Addr)>,
    pub out_ips: Vec<(u32, u32, Ipv4Addr)>,
    #[cfg(any(unix))]
    pub off_command_server: bool,
}

fn ips_parse(ips: &Vec<String>) -> Result<Vec<(u32, u32, Ipv4Addr)>, String> {
    let mut in_ips_c = vec![];
    for x in ips {
        let mut split = x.split(",");
        let net = if let Some(net) = split.next() {
            net
        } else {
            return Err("参数错误".to_string());
        };
        let ip = if let Some(ip) = split.next() {
            ip
        } else {
            return Err("参数错误".to_string());
        };
        let ip = if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            ip
        } else {
            return Err("参数错误".to_string());
        };
        let mut split = net.split("/");
        let dest = if let Some(dest) = split.next() {
            dest
        } else {
            return Err("参数错误".to_string());
        };
        let mask = if let Some(mask) = split.next() {
            mask
        } else {
            return Err("参数错误".to_string());
        };
        let dest = if let Ok(dest) = dest.parse::<Ipv4Addr>() {
            dest
        } else {
            return Err("参数错误".to_string());
        };
        let mask = if let Ok(m) = mask.parse::<u32>() {
            let mut mask = 0 as u32;
            for i in 0..m {
                mask = mask | (1 << (31 - i));
            }
            mask
        } else {
            return Err("参数错误".to_string());
        };
        in_ips_c.push((u32::from_be_bytes(dest.octets()), mask, ip));
    }
    Ok(in_ips_c)
}

pub fn default_config(start_args: StartArgs) -> Result<StartConfig, String> {
    println!("========参数配置========");
    let tap = start_args.tap;
    if tap {
        println!("use tap");
    } else {
        println!("use tun");
    }
    if start_args.token.is_none() {
        return Err("找不到token(Token not found)".to_string());
    }
    let token = start_args.token.unwrap();
    if token.is_empty() {
        return Err("token不能为空(Token cannot be empty)".to_string());
    }
    if token.len() > 64 {
        return Err("token不能超过64字符(Token cannot exceed 64 characters)".to_string());
    }
    println!("token:{:?}", token);
    let name = start_args.name.unwrap_or_else(|| {
        os_info::get().to_string()
    });
    let name = name.trim();
    let name = if name.len() > 64 {
        name[..64].to_string()
    } else {
        name.to_string()
    };
    println!("name:{:?}", name);
    let device_id = start_args.device_id.unwrap_or_else(|| {
        if let Ok(Some(mac_address)) = mac_address::get_mac_address() {
            mac_address.to_string()
        } else {
            "".to_string()
        }
    });
    if device_id.is_empty() || device_id.len() > 64 {
        return Err("设备id不能为空并且长度不能大于64字符(The device id cannot be empty and the length cannot be greater than 64 characters)".to_string());
    }
    println!("device_id:{:?}", device_id);
    let in_ips = start_args.in_ip.unwrap_or_else(|| {
        vec![]
    });
    let out_ips = start_args.out_ip.unwrap_or_else(|| {
        vec![]
    });
    println!("in_ips:{:?}", in_ips);
    let in_ips_c = if let Ok(in_ips_c) = ips_parse(&in_ips) {
        in_ips_c
    } else {
        return Err("in_ips 参数错误 示例：--in_ip 192.168.10.0/24,10.26.0.3".to_string());
    };
    println!("out_ips:{:?}", out_ips);
    let out_ips_c = if let Ok(out_ips_c) = ips_parse(&out_ips) {
        out_ips_c
    } else {
        return Err("out_ips 参数错误 示例：--out_ip 192.168.10.0/24,192.168.0.5".to_string());
    };


    let server = match start_args.server.unwrap_or_else(|| {
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
    println!("中继服务器:{:?}", server);
    let nat_test_server = start_args.nat_test_server.unwrap_or_else(|| {
        "nat1.wherewego.top:35061,nat1.wherewego.top:35062,nat2.wherewego.top:35061,nat2.wherewego.top:35062".to_string()
    }).split(",").flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();
    if nat_test_server.is_empty() {
        return Err("NAT检测服务地址错误(NAT detection service address error)".to_string());
    }
    println!("NAT探测服务器:{:?}", nat_test_server);
    let base_config = StartConfig {
        tap,
        name,
        token,
        server,
        nat_test_server,
        device_id,
        in_ips: in_ips_c,
        out_ips: out_ips_c,
        #[cfg(any(unix))]
        off_command_server: start_args.off_command_server,
    };
    println!("========参数配置========");
    Ok(base_config)
}

pub fn read_config_file(config_path: PathBuf) -> Result<StartConfig, String> {
    println!("========读取配置文件========");
    let args_config = if let Ok(config) = read_config(config_path) {
        config
    } else {
        return Err("读取配置文件失败".to_string());
    };

    let tap = args_config.tap;
    if tap {
        println!("use tap");
    } else {
        println!("use tun");
    }
    let token = args_config.token;
    if token.is_empty() {
        return Err("token不能为空(Token cannot be empty)".to_string());
    }
    if token.len() > 64 {
        return Err("token不能超过64字符(Token cannot exceed 64 characters)".to_string());
    }
    println!("token:{:?}", token);
    let name = args_config.name;
    let name = name.trim();
    let name = if name.len() > 64 {
        name[..64].to_string()
    } else {
        name.to_string()
    };
    println!("name:{:?}", name);
    let device_id = if !args_config.device_id.is_empty() {
        args_config.device_id
    } else {
        if let Ok(Some(mac_address)) = mac_address::get_mac_address() {
            mac_address.to_string()
        } else {
            "".to_string()
        }
    };
    if device_id.is_empty() || device_id.len() > 64 {
        return Err("设备id不能为空并且长度不能大于64字符(The device id cannot be empty and the length cannot be greater than 64 characters)".to_string());
    }
    println!("device_id:{:?}", device_id);
    let in_ips = args_config.in_ips;
    let out_ips = args_config.out_ips;
    println!("in_ips:{:?}", in_ips);
    let in_ips_c = if let Ok(in_ips_c) = ips_parse(&in_ips) {
        in_ips_c
    } else {
        return Err("in_ips 参数错误 示例：--in_ip 192.168.10.0/24,10.26.0.3".to_string());
    };
    println!("out_ips:{:?}", out_ips);
    let out_ips_c = if let Ok(out_ips_c) = ips_parse(&out_ips) {
        out_ips_c
    } else {
        return Err("out_ips 参数错误 示例：--out_ip 192.168.10.0/24,192.168.0.5".to_string());
    };
    let server = match {
        if !args_config.server.is_empty() {
            args_config.server
        } else {
            "nat1.wherewego.top:29871".to_string()
        }
    }.to_socket_addrs()
    {
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
    println!("中继服务器:{:?}", server);
    let nat_test_server = if args_config.nat_test_server.is_empty() {
        vec!["nat1.wherewego.top:35061".to_string(), "nat1.wherewego.top:35062".to_string(), "nat2.wherewego.top:35061".to_string(), "nat2.wherewego.top:35062".to_string()]
    } else {
        args_config.nat_test_server
    }.iter().flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();
    if nat_test_server.is_empty() {
        return Err("NAT检测服务地址错误(NAT detection service address error)".to_string());
    }
    println!("NAT探测服务器:{:?}", nat_test_server);
    let base_config = StartConfig {
        tap,
        name,
        token,
        server,
        nat_test_server,
        device_id,
        in_ips: in_ips_c,
        out_ips: out_ips_c,
        #[cfg(any(unix))]
        off_command_server: args_config.off_command_server,
    };
    println!("========参数配置========");
    Ok(base_config)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeData {
    #[serde(default = "default_pid")]
    pub pid: u32,
    pub command_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArgsConfig {
    #[serde(default = "default_false")]
    pub tap: bool,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_str")]
    pub token: String,
    #[serde(default = "default_str")]
    pub name: String,
    #[serde(default = "default_str")]
    pub server: String,
    #[serde(default = "default_vec")]
    pub nat_test_server: Vec<String>,
    #[serde(default = "default_str")]
    pub device_id: String,
    #[serde(default = "default_vec")]
    pub in_ips: Vec<String>,
    #[serde(default = "default_vec")]
    pub out_ips: Vec<String>,
    #[cfg(any(unix))]
    #[serde(default = "default_false")]
    pub off_command_server: bool,
}

fn default_false() -> bool {
    false
}

fn default_version() -> String {
    "1.0".to_string()
}

fn default_str() -> String {
    "".to_string()
}

fn default_vec() -> Vec<String> {
    vec![]
}

fn default_pid() -> u32 {
    0
}

// impl ArgsConfig {
//     pub fn new(tap: bool, token: String, name: String, server: SocketAddr,
//                nat_test_server: &Vec<SocketAddr>, device_id: String,
//                in_ips: Vec<(u32, u32, Ipv4Addr)>, out_ips: Vec<(u32, u32, Ipv4Addr)>, ) -> Self {
//
//         Self {
//             tap,
//             version: "1.0".to_string(),
//             token,
//             name,
//             command_port: None,
//             server: server.to_string(),
//             nat_test_server: nat_test_server.iter().map(|v| v.to_string()).collect::<Vec<String>>(),
//             device_id,
//             pid: 0,
//         }
//     }
// }

pub fn lock_file() -> io::Result<File> {
    let path = get_home().join(".lock");
    let file = File::create(path)?;
    file.sync_all()?;
    Ok(file)
}


fn save_runtime_data(config: RuntimeData) -> io::Result<()> {
    let config_path = get_runtime_data_path();
    let str = serde_yaml::to_string(&config).unwrap();
    let mut file = File::create(config_path)?;
    file.write_all(str.as_bytes())?;
    file.sync_all()
}

pub fn update_pid(pid: u32) -> io::Result<()> {
    let mut config = read_runtime_data()?;
    config.pid = pid;
    return save_runtime_data(config);
}

#[cfg(any(unix))]
pub fn read_pid() -> io::Result<u32> {
    let config = read_runtime_data()?;
    Ok(config.pid)
}

pub fn update_command_port(port: u16) -> io::Result<()> {
    let mut config = read_runtime_data()?;
    config.command_port = Some(port);
    return save_runtime_data(config);
}

pub fn read_command_port() -> io::Result<u16> {
    let config = read_runtime_data()?;
    if let Some(p) = config.command_port {
        Ok(p)
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "not fount config"))
    }
}


pub fn get_home() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(path) = SWITCH_HOME_PATH.lock().as_ref() {
            return path.clone();
        }
    }
    let home = dirs::home_dir().unwrap().join(".switch_desktop");
    if !home.exists() {
        std::fs::create_dir(&home).unwrap();
    }
    home
}

pub fn get_runtime_data_path() -> PathBuf {
    let home = get_home();
    home.join(".data")
}

fn read_runtime_data() -> io::Result<RuntimeData> {
    let config_path = get_runtime_data_path();
    let mut file = if config_path.exists() {
        File::open(config_path)?
    } else {
        OpenOptions::new().read(true).write(true).truncate(false).create(true).open(config_path)?
    };
    let mut str = String::new();
    file.read_to_string(&mut str)?;
    match serde_yaml::from_str::<RuntimeData>(&str) {
        Ok(config) => Ok(config),
        Err(e) => {
            log::warn!("{:?}", e);
            Err(io::Error::new(io::ErrorKind::Other, "config error"))
        }
    }
}

fn read_config(config_path: PathBuf) -> io::Result<ArgsConfig> {
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