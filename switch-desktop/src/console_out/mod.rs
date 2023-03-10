use std::net::Ipv4Addr;
use console::style;

use switch::Route;

use crate::command::entity::{DeviceItem, RouteItem, Status};

pub mod table;

pub fn console_status(status: Status) {
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

pub fn console_route_table(list: Vec<RouteItem>) {
    if list.is_empty() {
        println!("No route found");
        return;
    }
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec!["Destination".to_string(), "Next Hop".to_string(), "Metric".to_string(),
                       "Rt".to_string(), "Interface".to_string()]);
    for item in list {
        out_list.push(vec![item.destination, item.next_hop, item.metric,
                           item.rt, item.interface]);
    }
    table::println_table(out_list)
}

pub fn console_device_list(list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec!["Name".to_string(), "Virtual Ip".to_string(), "P2P/Relay".to_string(), "Rt".to_string(), "Status".to_string()]);
    for item in list {
        out_list.push(vec![item.name, item.virtual_ip, item.nat_traversal_type,
                           item.rt, item.status]);
    }
    table::println_table(out_list)
}

pub fn console_device_list_all(list: Vec<DeviceItem>) {
    if list.is_empty() {
        println!("No other devices found");
        return;
    }
    let mut out_list = Vec::with_capacity(list.len());
    //表头
    out_list.push(vec!["Name".to_string(), "Virtual Ip".to_string(), "NAT Type".to_string(),
                       "Public Ips".to_string(), "Local Ip".to_string(), "P2P/Relay".to_string(),
                       "Rt".to_string(), "Status".to_string()]);
    for item in list {
        out_list.push(vec![item.name, item.virtual_ip, item.nat_type,
                           item.public_ips, item.local_ip, item.nat_traversal_type,
                           item.rt, item.status]);
    }
    table::println_table(out_list)
}