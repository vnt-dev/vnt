use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;

use switch::core::Switch;
use crate::command::entity::{DeviceItem, RouteItem, Status};


pub struct CommandServer {}

impl CommandServer {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandServer {
    pub fn start(&self, switch: Arc<Switch>) -> io::Result<()> {
        let mut port = 21637 as u16;
        let udp = loop {
            match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                port,
            ))) {
                Ok(udp) => {
                    break udp;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::AddrInUse {
                        port += 1;
                    } else {
                        log::error!("创建udp失败 {:?}", e);
                        return Err(e);
                    }
                }
            }
        };
        crate::config::update_command_port(port)?;
        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = udp.recv_from(&mut buf)?;
            match std::str::from_utf8(&buf[..len]) {
                Ok(cmd) => {
                    if let Ok(out) = command(cmd, &switch) {
                        udp.send_to(out.as_bytes(), addr)?;
                    }
                }
                Err(e) => {
                    log::warn!("{:?}", e);
                }
            }
        }
    }
}

pub fn command_route(switch: &Switch) -> Vec<RouteItem> {
    let route_table = switch.route_table();
    let mut route_list = Vec::with_capacity(route_table.len());
    for (destination, route) in route_table {
        let next_hop = switch.route_key(&route.route_key()).map_or(String::new(), |v| v.to_string());
        let metric = route.metric.to_string();
        let rt = if route.rt < 0 {
            "".to_string()
        } else {
            route.rt.to_string()
        };
        let interface = route.addr.to_string();
        let item = RouteItem {
            destination: destination.to_string(),
            next_hop,
            metric,
            rt,
            interface,
        };
        route_list.push(item);
    }
    route_list
}

pub fn command_list(switch: &Switch) -> Vec<DeviceItem> {
    let device_list = switch.device_list();
    let mut list = Vec::new();
    for peer in device_list {
        let name = peer.name;
        let virtual_ip = peer.virtual_ip.to_string();
        let (nat_type, public_ips, local_ip) = if let Some(nat_info) = switch.peer_nat_info(&peer.virtual_ip) {
            let nat_type = format!("{:?}", nat_info.nat_type);
            let public_ips: Vec<String> = nat_info.public_ips.iter().map(|v| v.to_string()).collect();
            let public_ips = public_ips.join(",");
            let local_ip = nat_info.local_ip.to_string();
            (nat_type, public_ips, local_ip)
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        };
        let (nat_traversal_type, rt) = if let Some(route) = switch.route(&peer.virtual_ip) {
            let nat_traversal_type = if route.metric == 1 { "p2p" } else { "relay" }.to_string();
            let rt = if route.rt < 0 {
                "".to_string()
            } else {
                route.rt.to_string()
            };
            (nat_traversal_type, rt)
        } else {
            ("relay".to_string(), "".to_string())
        };
        let status = format!("{:?}", peer.status);
        let item = DeviceItem {
            name,
            virtual_ip,
            nat_type,
            public_ips,
            local_ip,
            nat_traversal_type,
            rt,
            status,
        };
        list.push(item);
    }
    list
}

pub fn command_status(switch: &Switch) -> Status {
    let current_device = switch.current_device();
    let nat_info = switch.nat_info();
    let name = switch.name().to_string();
    let virtual_ip = current_device.virtual_ip().to_string();
    let virtual_gateway = current_device.virtual_gateway().to_string();
    let virtual_netmask = current_device.virtual_netmask.to_string();
    let connect_status = format!("{:?}", switch.connection_status());
    let relay_server = current_device.connect_server.to_string();
    let nat_type = format!("{:?}", nat_info.nat_type);
    let public_ips: Vec<String> = nat_info.public_ips.iter().map(|v| v.to_string()).collect();
    let public_ips = public_ips.join(",");
    let local_ip = nat_info.local_ip.to_string();
    Status {
        name,
        virtual_ip,
        virtual_gateway,
        virtual_netmask,
        connect_status,
        relay_server,
        nat_type,
        public_ips,
        local_ip,
    }
}

fn command(cmd: &str, switch: &Switch) -> io::Result<String> {
    let out_str = match cmd {
        "route" => {
            match serde_json::to_string(&command_route(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "list" => {
            match serde_json::to_string(&command_list(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "status" => {
            match serde_json::to_string(&command_status(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "stop" => {
            switch.stop()?;
            "stopping".to_string()
        }
        _ => {
            format!("command '{}' not found. \n Try to enter: 'help'\n", cmd)
        }
    };
    Ok(out_str)
}
