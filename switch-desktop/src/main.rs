// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::{Ipv4Addr, ToSocketAddrs};
use lazy_static::lazy_static;
use parking_lot::Mutex;
use common::args_parse::ips_parse;
use switch::core::Config;
use switch::core::{Switch, SwitchUtil};
use switch::handle::registration_handler::ReqEnum;

#[cfg(windows)]
mod load_dll;
#[cfg(windows)]
mod config;

lazy_static! {
    static ref SWITCH:Mutex<Option<Switch>> = Mutex::new(None);
}

fn main() {
    #[cfg(windows)]
    {
        load_dll::load_tun_dll().unwrap();
    }
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![default_value_name,default_value_device_id,connect,close,list])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn default_value_name() -> String {
    os_info::get().to_string()
}

#[tauri::command]
fn default_value_device_id() -> String {
    common::identifier::get_unique_identifier().unwrap_or(String::new())
}

#[tauri::command]
async fn connect(config: ConnectConfig) -> Result<ConnectRegResponse, String> {
    let tap = config.tap;
    let token = config.token;
    let device_id = config.device_id;
    let name = config.name;
    let server_address_str = config.server_address;
    let server_address = match server_address_str.to_socket_addrs() {
        Ok(mut addr) => {
            if let Some(addr) = addr.next() {
                addr
            } else {
                return Err(String::from("server"));
            }
        }
        Err(e) => {
            return Err(format!("server err:{}", e));
        }
    };
    let nat_test_server = config.nat_test_server.split(" ").flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();
    let in_ips = config.in_ips.split(" ").into_iter().filter(|e| !e.is_empty()).map(|e| e.to_string()).collect();
    let in_ips = match ips_parse(&in_ips) {
        Ok(in_ips) => { in_ips }
        Err(e) => {
            return Err(format!("inIps err:{}", e));
        }
    };
    let out_ips = config.out_ips.split(" ").into_iter().filter(|e| !e.is_empty()).map(|e| e.to_string()).collect();
    let out_ips = match ips_parse(&out_ips) {
        Ok(out_ips) => { out_ips }
        Err(e) => {
            return Err(format!("inIps err:{}", e));
        }
    };
    let password = if config.key.is_empty() {
        None
    } else {
        Some(config.key)
    };
    let simulate_multicast = config.simulate_multicast;
    let config = Config::new(tap, token, device_id, name, server_address, server_address_str,
                             nat_test_server, in_ips, out_ips,
                             password, simulate_multicast, None);

    let mut switch_util = SwitchUtil::new(config).await.unwrap();
    let mut count = 0;
    let response = loop {
        match switch_util.connect().await {
            Ok(response) => {
                break response;
            }
            Err(e) => {
                match e {
                    ReqEnum::TokenError => {
                        return Err("token error".to_string());
                    }
                    ReqEnum::AddressExhausted => {
                        return Err("address exhausted".to_string());
                    }
                    ReqEnum::Timeout => {
                        count += 1;
                        if count > 3 {
                            return Err("connect timeout".to_string());
                        }
                        continue;
                    }
                    ReqEnum::ServerError(str) => {
                        return Err(format!("error:{}", str));
                    }
                    ReqEnum::Other(str) => {
                        return Err(format!("error:{}", str));
                    }
                }
            }
        }
    };
    match switch_util.create_iface() {
        Ok(_) => {}
        Err(e) => {
            return Err(format!("create net interface error:{}", e));
        }
    }
    match switch_util.build().await {
        Ok(switch) => {
            let _ = SWITCH.lock().insert(switch);
        }
        Err(e) => {
            return Err(format!("build switch error:{}", e));
        }
    }
    Ok(ConnectRegResponse {
        virtual_ip: response.virtual_ip,
        virtual_gateway: response.virtual_gateway,
        virtual_netmask: response.virtual_netmask,
    })
}

#[tauri::command]
fn list() -> Vec<SwitchPeerItem> {
    let mut peer_list = Vec::new();
    let mut guard = SWITCH.lock();
    match &mut *guard {
        None => {}
        Some(switch) => {
            let mut list = switch.device_list();
            let current_device = switch.current_device();
            list.sort_unstable_by_key(|v| { (v.status, v.virtual_ip) });
            for x in list {
                let item = if let Some(route) = switch.route(&x.virtual_ip) {
                    let connect = if route.is_p2p() {
                        "p2p".to_string()
                    } else if route.addr == current_device.connect_server {
                        "server relay".to_string()
                    } else {
                        "client relay".to_string()
                    };
                    SwitchPeerItem {
                        name: x.name,
                        virtual_ip: x.virtual_ip,
                        status: format!("{:?}", x.status),
                        connect,
                        rt: route.rt.to_string(),
                        addr: route.addr.to_string(),
                    }
                } else {
                    SwitchPeerItem {
                        name: x.name,
                        virtual_ip: x.virtual_ip,
                        status: format!("{:?}", x.status),
                        connect: "".to_string(),
                        rt: "".to_string(),
                        addr: "".to_string(),
                    }
                };
                peer_list.push(item);
            }
        }
    }
    peer_list
}

#[tauri::command]
async fn close() {
    let switch = SWITCH.lock().take();
    match switch {
        None => {}
        Some(mut switch) => {
            switch.stop().unwrap();
            switch.wait_stop().await;
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ConnectConfig {
    pub tap: bool,
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub server_address: String,
    pub nat_test_server: String,
    pub in_ips: String,
    pub out_ips: String,
    pub key: String,
    pub simulate_multicast: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ConnectRegResponse {
    pub virtual_ip: Ipv4Addr,
    pub virtual_gateway: Ipv4Addr,
    pub virtual_netmask: Ipv4Addr,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct SwitchPeerItem {
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    pub status: String,
    pub connect: String,
    pub rt: String,
    pub addr: String,
}
