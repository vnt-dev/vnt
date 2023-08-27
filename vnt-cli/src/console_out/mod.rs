use console::{style, Style};

use crate::command::entity::{DeviceItem, RouteItem, Info};

pub mod table;

pub fn console_info(status: Info) {
    println!("Name: {}", style(status.name).green());
    println!("Virtual ip: {}", style(status.virtual_ip).green());
    println!("Virtual gateway: {}", style(status.virtual_gateway).green());
    println!("Virtual netmask: {}", style(status.virtual_netmask).green());
    println!("Connection status: {}", style(status.connect_status).green());
    println!("NAT type: {}", style(status.nat_type).green());
    println!("Relay server: {}", style(status.relay_server).green());
    println!("Public ips: {}", style(status.public_ips).green());
    println!("Local ip: {}", style(status.local_ip).green());
}

pub fn console_route_table(mut list: Vec<RouteItem>) {
    if list.is_empty() {
        println!("No route found");
        return;
    }
    list.sort_by(|t1, t2| t1.destination.cmp(&t2.destination));
    let mut out_list = Vec::with_capacity(list.len());

    out_list.push(vec![("Destination".to_string(), Style::new()),
                       ("Next Hop".to_string(), Style::new()),
                       ("Metric".to_string(), Style::new()),
                       ("Rt".to_string(), Style::new()),
                       ("Interface".to_string(), Style::new()), ]);
    for item in list {
        out_list.push(vec![(item.destination, Style::new().green()),
                           (item.next_hop, Style::new().green()),
                           (item.metric, Style::new().green()),
                           (item.rt, Style::new().green()),
                           (item.interface, Style::new().green())]);
    }

    table::println_table(out_list)
}

pub fn console_device_list(mut list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    list.sort_by(|t1, t2| t1.virtual_ip.cmp(&t2.virtual_ip));
    list.sort_by(|t1, t2| t1.status.cmp(&t2.status));
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec![("Name".to_string(), Style::new()),
                       ("Virtual Ip".to_string(), Style::new()),
                       ("Status".to_string(), Style::new()),
                       ("P2P/Relay".to_string(), Style::new()),
                       ("Rt".to_string(), Style::new())]);
    for item in list {
        if &item.status == "Online" {
            if item.client_secret != item.current_client_secret {
                //加密状态不一致，无法通信的
                out_list.push(vec![(item.name, Style::new().red()),
                                   (item.virtual_ip, Style::new().red()),
                                   (item.status, Style::new().red()),
                                   ("".to_string(), Style::new().red()),
                                   ("".to_string(), Style::new().red())]);
            } else {
                if &item.nat_traversal_type == "p2p" {
                    out_list.push(vec![(item.name, Style::new().green()),
                                       (item.virtual_ip, Style::new().green()),
                                       (item.status, Style::new().green()),
                                       (item.nat_traversal_type, Style::new().green()),
                                       (item.rt, Style::new().green())]);
                } else {
                    out_list.push(vec![(item.name, Style::new().yellow()),
                                       (item.virtual_ip, Style::new().yellow()),
                                       (item.status, Style::new().yellow()),
                                       (item.nat_traversal_type, Style::new().yellow()),
                                       (item.rt, Style::new().yellow())]);
                }
            }
        } else {
            out_list.push(vec![(item.name, Style::new().color256(102)),
                               (item.virtual_ip, Style::new().color256(102)),
                               (item.status, Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102))]);
        }
    }
    table::println_table(out_list)
}

pub fn console_device_list_all(mut list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    list.sort_by(|t1, t2| t1.virtual_ip.cmp(&t2.virtual_ip));
    list.sort_by(|t1, t2| t1.status.cmp(&t2.status));
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec![("Name".to_string(), Style::new()),
                       ("Virtual Ip".to_string(), Style::new()),
                       ("Status".to_string(), Style::new()),
                       ("P2P/Relay".to_string(), Style::new()),
                       ("Rt".to_string(), Style::new()),
                       ("NAT Type".to_string(), Style::new()),
                       ("Public Ips".to_string(), Style::new()),
                       ("Local Ip".to_string(), Style::new())]);
    for item in list {
        if &item.status == "Online" {
            if &item.nat_traversal_type == "p2p" {
                out_list.push(vec![(item.name, Style::new().green()),
                                   (item.virtual_ip, Style::new().green()),
                                   (item.status, Style::new().green()),
                                   (item.nat_traversal_type, Style::new().green()),
                                   (item.rt, Style::new().green()),
                                   (item.nat_type, Style::new().green()),
                                   (item.public_ips, Style::new().green()),
                                   (item.local_ip, Style::new().green())]);
            } else {
                out_list.push(vec![(item.name, Style::new().yellow()),
                                   (item.virtual_ip, Style::new().yellow()),
                                   (item.status, Style::new().yellow()),
                                   (item.nat_traversal_type, Style::new().yellow()),
                                   (item.rt, Style::new().yellow()),
                                   (item.nat_type, Style::new().yellow()),
                                   (item.public_ips, Style::new().yellow()),
                                   (item.local_ip, Style::new().yellow()), ]);
            }
        } else {
            out_list.push(vec![(item.name, Style::new().color256(102)),
                               (item.virtual_ip, Style::new().color256(102)),
                               (item.status, Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)),
                               ("".to_string(), Style::new().color256(102)), ]);
        }
    }
    table::println_table(out_list)
}