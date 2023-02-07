use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::Arc;

use console::style;

use switch::handle::{PeerDeviceStatus, RouteType};
use switch::Switch;

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

fn command(cmd: &str, switch: &Switch) -> io::Result<String> {
    let mut out_str = String::new();
    match cmd {
        "list" => {
            let server_rt = switch.server_rt();
            let device_list = switch.device_list();
            if device_list.is_empty() {
                return Ok("No other devices found\n".to_string());
            }
            for peer_device_info in device_list {
                let route = switch.route(&peer_device_info.virtual_ip);
                let str = if peer_device_info.status == PeerDeviceStatus::Online {
                    if route.route_type == RouteType::P2P {
                        let str = if route.rt >= 0 {
                            format!(
                                "[{}] {}(p2p delay:{}ms)\n",
                                peer_device_info.name, peer_device_info.virtual_ip, route.rt
                            )
                        } else {
                            format!(
                                "[{}] {}(p2p)",
                                peer_device_info.name, peer_device_info.virtual_ip
                            )
                        };
                        style(str).green().to_string()
                    } else {
                        let str = if server_rt >= 0 {
                            format!(
                                "[{}] {}(relay delay:{}ms)\n",
                                peer_device_info.name,
                                peer_device_info.virtual_ip,
                                server_rt * 2
                            )
                        } else {
                            format!(
                                "[{}] {}(relay)\n",
                                peer_device_info.name, peer_device_info.virtual_ip
                            )
                        };
                        style(str).blue().to_string()
                    }
                } else {
                    let str = format!(
                        "[{}] {}(Offline)\n",
                        peer_device_info.name, peer_device_info.virtual_ip
                    );
                    style(str).red().to_string()
                };
                out_str.push_str(&str);
            }
        }
        "status" => {
            let server_rt = switch.server_rt();
            let current_device = switch.current_device();
            let str = format!("Virtual ip:{}\n", style(current_device.virtual_ip).green());
            out_str.push_str(&str);
            let str = format!(
                "Virtual gateway:{}\n",
                style(current_device.virtual_gateway).green()
            );
            out_str.push_str(&str);
            let str = format!(
                "Connection status :{}\n",
                style(format!("{:?}", switch.connection_status())).green()
            );
            out_str.push_str(&str);
            let str = format!(
                "Relay server :{}\n",
                style(current_device.connect_server).green()
            );
            out_str.push_str(&str);
            if server_rt >= 0 {
                let str = format!("Delay of relay server :{}ms\n", style(server_rt).green());
                out_str.push_str(&str);
            }
            if let Some(nat_info) = switch.nat_info() {
                let str = format!(
                    "NAT type :{}",
                    style(format!("{:?}", nat_info.nat_type)).green()
                );
                out_str.push_str(&str);
            }
        }
        "help" | "h" => {
            let str = format!("Options: \n");
            out_str.push_str(&str);
            let str = format!(
                "{} , Query the virtual IP of other devices\n",
                style("list").green()
            );
            out_str.push_str(&str);
            let str = format!("{} , View current device status\n", style("status").green());
            out_str.push_str(&str);
            let str = format!("{} , Exit the program\n", style("exit").green());
            out_str.push_str(&str);
        }
        "exit" => {
            switch.stop_async();
        }
        _ => {
            let str = format!("command '{}' not fount. \n", style(cmd).red());
            out_str.push_str(&str);
            let str = format!("Try to enter: '{}'\n", style("help").green());
            out_str.push_str(&str);
        }
    }
    Ok(out_str)
}
