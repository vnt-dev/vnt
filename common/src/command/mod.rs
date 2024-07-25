use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use vnt::channel::ConnectProtocol;
use vnt::core::Vnt;

use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};
use crate::console_out;

pub mod client;
pub mod entity;
pub mod server;

pub enum CommandEnum {
    Route,
    List,
    All,
    Info,
    ChartA,
    ChartB(String),
    Stop,
}

pub fn command_str(cmd: &str, vnt: &Vnt) -> bool {
    if cmd.is_empty() {
        return false;
    }
    let cmd = cmd.to_lowercase();
    let cmd = cmd.trim();
    match cmd {
        "list" => {
            let list = command_list(&vnt);
            console_out::console_device_list(list);
        }
        "info" => {
            let info = command_info(&vnt);
            console_out::console_info(info);
        }
        "route" => {
            let route = command_route(&vnt);
            console_out::console_route_table(route);
        }
        "all" => {
            let list = command_list(&vnt);
            console_out::console_device_list_all(list);
        }
        "chart_a" => {
            let chart = command_chart_a(&vnt);
            console_out::console_chart_a(chart);
        }
        "stop" => {
            let _ = vnt.stop();
            return false;
        }
        _ => {}
    }
    if let Some(ip) = cmd.strip_prefix("chart_b") {
        let chart = if ip.is_empty() {
            command_chart_b(&vnt, &vnt.current_device().virtual_gateway.to_string())
        } else {
            command_chart_b(&vnt, &ip[1..])
        };
        console_out::console_chart_b(chart);
    }
    println!();
    return true;
}

pub fn command(cmd: CommandEnum) {
    if let Err(e) = command_(cmd) {
        println!("cmd: {:?}", e);
    }
}

fn command_(cmd: CommandEnum) -> io::Result<()> {
    let mut command_client = client::CommandClient::new()?;
    match cmd {
        CommandEnum::Route => {
            let list = command_client.route()?;
            console_out::console_route_table(list);
        }
        CommandEnum::List => {
            let list = command_client.list()?;
            console_out::console_device_list(list);
        }
        CommandEnum::All => {
            let list = command_client.list()?;
            console_out::console_device_list_all(list);
        }
        CommandEnum::Info => {
            let info = command_client.info()?;
            console_out::console_info(info);
        }
        CommandEnum::ChartA => {
            let chart = command_client.chart_a()?;
            console_out::console_chart_a(chart);
        }
        CommandEnum::ChartB(input) => {
            let chart = command_client.chart_b(&input)?;
            console_out::console_chart_b(chart);
        }
        CommandEnum::Stop => {
            command_client.stop()?;
        }
    }
    Ok(())
}

pub fn command_route(vnt: &Vnt) -> Vec<RouteItem> {
    let route_table = vnt.route_table();
    let server_addr = vnt.config().server_address_str.clone();
    let mut route_list = Vec::with_capacity(route_table.len());
    for (destination, routes) in route_table {
        for route in routes {
            let next_hop = vnt
                .route_key(&route.route_key())
                .map_or(String::new(), |v| v.to_string());
            let metric = route.metric.to_string();
            let rt = if route.rt < 0 {
                "".to_string()
            } else {
                route.rt.to_string()
            };
            let interface = match route.protocol {
                ConnectProtocol::UDP => route.addr.to_string(),
                ConnectProtocol::TCP => {
                    format!("tcp@{}", route.addr)
                }
                ConnectProtocol::WS | ConnectProtocol::WSS => server_addr.clone(),
            };

            let item = RouteItem {
                destination: destination.to_string(),
                next_hop,
                metric,
                rt,
                interface,
            };
            route_list.push(item);
        }
    }
    route_list
}

pub fn command_list(vnt: &Vnt) -> Vec<DeviceItem> {
    let info = vnt.current_device();
    let device_list = vnt.device_list();
    let mut list = Vec::new();
    let current_client_secret = vnt.client_encrypt();
    let client_encrypt_hash = vnt.client_encrypt_hash().unwrap_or(&[]);
    for peer in device_list {
        let name = peer.name;
        let virtual_ip = peer.virtual_ip.to_string();
        let (nat_type, public_ips, local_ip, ipv6) =
            if let Some(nat_info) = vnt.peer_nat_info(&peer.virtual_ip) {
                let nat_type = format!("{:?}", nat_info.nat_type);
                let public_ips: Vec<String> =
                    nat_info.public_ips.iter().map(|v| v.to_string()).collect();
                let public_ips = public_ips.join(",");
                let local_ip = nat_info
                    .local_ipv4()
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string());
                let ipv6 = nat_info
                    .ipv6()
                    .map(|v| v.to_string())
                    .unwrap_or("None".to_string());
                (nat_type, public_ips, local_ip, ipv6)
            } else {
                (
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                    "".to_string(),
                )
            };
        let (nat_traversal_type, rt) = if let Some(route) = vnt.route(&peer.virtual_ip) {
            let nat_traversal_type = if route.metric == 1 {
                if route.protocol.is_base_tcp() {
                    "tcp-p2p"
                } else {
                    "p2p"
                }
            } else {
                let next_hop = vnt.route_key(&route.route_key());
                if let Some(next_hop) = next_hop {
                    if info.is_gateway(&next_hop) {
                        "server-relay"
                    } else {
                        "client-relay"
                    }
                } else {
                    "server-relay"
                }
            }
            .to_string();
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
        let client_secret = peer.client_secret;
        let item = DeviceItem {
            name,
            virtual_ip,
            nat_type,
            public_ips,
            local_ip,
            ipv6,
            nat_traversal_type,
            rt,
            status,
            client_secret,
            client_secret_hash: peer.client_secret_hash,
            current_client_secret,
            current_client_secret_hash: client_encrypt_hash.to_vec(),
            wire_guard: peer.wireguard,
        };
        list.push(item);
    }
    list
}

pub fn command_info(vnt: &Vnt) -> Info {
    let config = vnt.config();
    let current_device = vnt.current_device();
    let nat_info = vnt.nat_info();
    let name = vnt.name().to_string();
    let virtual_ip = current_device.virtual_ip().to_string();
    let virtual_gateway = current_device.virtual_gateway().to_string();
    let virtual_netmask = current_device.virtual_netmask.to_string();
    let connect_status = format!("{:?}", vnt.connection_status());
    let relay_server = if current_device.connect_server.port() == 0 {
        config.server_address_str.clone()
    } else {
        current_device.connect_server.to_string()
    };
    let nat_type = format!("{:?}", nat_info.nat_type);
    let public_ips: Vec<String> = nat_info.public_ips.iter().map(|v| v.to_string()).collect();
    let public_ips = public_ips.join(",");
    let local_addr = nat_info
        .local_ipv4()
        .map(|v| v.to_string())
        .unwrap_or("None".to_string());
    let ipv6_addr = nat_info
        .ipv6()
        .map(|v| v.to_string())
        .unwrap_or("None".to_string());
    #[cfg(feature = "port_mapping")]
    let port_mapping_list = vnt.config().port_mapping_list.clone();
    #[cfg(not(feature = "port_mapping"))]
    let port_mapping_list = vec![];
    let in_ips = vnt.config().in_ips.clone();
    let out_ips = vnt.config().out_ips.clone();
    let udp_listen_addr = nat_info
        .udp_ports
        .iter()
        .map(|port| format!("0.0.0.0:{}", port))
        .collect();
    let tcp_listen_addr = format!("0.0.0.0:{}", nat_info.tcp_port);
    Info {
        name,
        virtual_ip,
        virtual_gateway,
        virtual_netmask,
        connect_status,
        relay_server,
        nat_type,
        public_ips,
        local_addr,
        ipv6_addr,
        port_mapping_list,
        in_ips,
        out_ips,
        udp_listen_addr,
        tcp_listen_addr,
    }
}

pub fn command_chart_a(vnt: &Vnt) -> ChartA {
    let disable_stats = !vnt.config().enable_traffic;
    if disable_stats {
        let mut chart = ChartA::default();
        chart.disable_stats = true;
        return chart;
    }
    let (up_total, up_map) = vnt.up_stream_all().unwrap_or_default();
    let (down_total, down_map) = vnt.down_stream_all().unwrap_or_default();
    ChartA {
        disable_stats,
        up_total,
        down_total,
        up_map,
        down_map,
    }
}

pub fn command_chart_b(vnt: &Vnt, input_str: &str) -> ChartB {
    let disable_stats = !vnt.config().enable_traffic;
    if disable_stats {
        let mut chart = ChartB::default();
        chart.disable_stats = true;
        return chart;
    }
    let (_, up_map) = vnt.up_stream_history().unwrap_or_default();
    let (_, down_map) = vnt.down_stream_history().unwrap_or_default();
    let up_keys: HashSet<_> = up_map.keys().cloned().collect();
    let down_keys: HashSet<_> = down_map.keys().cloned().collect();
    let mut keys: Vec<Ipv4Addr> = up_keys.union(&down_keys).cloned().collect();
    keys.sort();
    if let Some(ip) = find_matching_ipv4_address(input_str, &keys) {
        let (up_total, up_list) = up_map.get(&ip).cloned().unwrap_or_default();
        let (down_total, down_list) = down_map.get(&ip).cloned().unwrap_or_default();
        ChartB {
            disable_stats,
            ip: Some(ip),
            up_total,
            up_list,
            down_total,
            down_list,
        }
    } else {
        ChartB::default()
    }
}

fn match_from_end(input_str: &str, ip: &str) -> bool {
    let mut input_chars = input_str.chars().rev();
    let mut ip_chars = ip.chars().rev();

    while let (Some(ic), Some(pc)) = (input_chars.next(), ip_chars.next()) {
        if ic != pc {
            return false;
        }
    }

    input_chars.next().is_none() // Ensure all input characters matched
}

fn find_matching_ipv4_address(input_str: &str, ip_addresses: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    for &ip in ip_addresses {
        let ip_str = ip.to_string();
        if match_from_end(input_str, &ip_str) {
            return Some(ip);
        }
    }
    None
}
