use console::{style, Style};
use std::collections::HashSet;
use std::net::Ipv4Addr;

use crate::command::entity::{ChartA, ChartB, DeviceItem, Info, RouteItem};

pub mod table;

pub fn console_info(status: Info) {
    println!("Name: {}", style(status.name).green());
    println!("Virtual ip: {}", style(status.virtual_ip).green());
    println!("Virtual gateway: {}", style(status.virtual_gateway).green());
    println!("Virtual netmask: {}", style(status.virtual_netmask).green());
    if status.connect_status.eq_ignore_ascii_case("Connected") {
        println!(
            "Connection status: {}",
            style(status.connect_status).green()
        );
    } else {
        println!("Connection status: {}", style(status.connect_status).red());
    }

    println!("NAT type: {}", style(status.nat_type).green());
    println!("Relay server: {}", style(status.relay_server).green());
    println!(
        "Udp listen: {}",
        style(status.udp_listen_addr.join(", ")).green()
    );
    println!("Tcp listen: {}", style(status.tcp_listen_addr).green());
    println!("Public ips: {}", style(status.public_ips).green());
    println!("Local addr: {}", style(status.local_addr).green());
    println!("IPv6: {}", style(status.ipv6_addr).green());

    if !status.port_mapping_list.is_empty() {
        println!("------------------------------------------");
        println!("Port mapping {}", status.port_mapping_list.len());
        for (is_tcp, addr, dest) in status.port_mapping_list {
            if is_tcp {
                println!("  TCP: {} -> {}", addr, dest)
            } else {
                println!("  UDP: {} -> {}", addr, dest)
            }
        }
    }
    if !status.in_ips.is_empty() || !status.out_ips.is_empty() {
        println!("------------------------------------------");
    }
    if !status.in_ips.is_empty() {
        println!("IP forwarding {}", status.in_ips.len());
        for (dest, mask, ip) in status.in_ips {
            println!(
                "  -- {} --> {}/{}",
                ip,
                Ipv4Addr::from(dest),
                mask.count_ones()
            )
        }
    }
    if !status.out_ips.is_empty() {
        println!("Allows network {}", status.out_ips.len());
        for (dest, mask) in status.out_ips {
            println!("  {}/{}", Ipv4Addr::from(dest), mask.count_ones())
        }
    }
}

fn convert(num: u64) -> String {
    let gigabytes = num / (1024 * 1024 * 1024);
    let remaining_bytes = num % (1024 * 1024 * 1024);
    let megabytes = remaining_bytes / (1024 * 1024);
    let remaining_bytes = remaining_bytes % (1024 * 1024);
    let kilobytes = remaining_bytes / 1024;
    let remaining_bytes = remaining_bytes % 1024;
    let mut s = String::new();
    if gigabytes > 0 {
        s.push_str(&format!("{} GB ", gigabytes));
    }
    if megabytes > 0 {
        s.push_str(&format!("{} MB ", megabytes));
    }
    if kilobytes > 0 {
        s.push_str(&format!("{} KB ", kilobytes));
    }
    if remaining_bytes > 0 {
        s.push_str(&format!("{} bytes", remaining_bytes));
    }
    s
}

pub fn console_route_table(mut list: Vec<RouteItem>) {
    if list.is_empty() {
        println!("No route found");
        return;
    }
    list.sort_by(|t1, t2| t1.destination.cmp(&t2.destination));
    let mut out_list = Vec::with_capacity(list.len());

    out_list.push(vec![
        ("Destination".to_string(), Style::new()),
        ("Next Hop".to_string(), Style::new()),
        ("Metric".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
        ("Interface".to_string(), Style::new()),
    ]);
    for item in list {
        out_list.push(vec![
            (item.destination, Style::new().green()),
            (item.next_hop, Style::new().green()),
            (item.metric, Style::new().green()),
            (item.rt, Style::new().green()),
            (item.interface, Style::new().green()),
        ]);
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
    out_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Virtual Ip".to_string(), Style::new()),
        ("Status".to_string(), Style::new()),
        ("P2P/Relay".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
    ]);
    for item in list {
        let name = if item.wire_guard {
            format!("{}(wg)", item.name)
        } else {
            item.name
        };
        if &item.status == "Online" {
            if !item.wire_guard
                && (item.client_secret != item.current_client_secret
                    || (!item.current_client_secret_hash.is_empty()
                        && !item.client_secret_hash.is_empty()
                        && item.current_client_secret_hash != item.client_secret_hash))
            {
                //加密状态不一致，无法通信的
                out_list.push(vec![
                    (name, Style::new().red()),
                    (item.virtual_ip, Style::new().red()),
                    (item.status, Style::new().red()),
                    ("Mismatch".to_string(), Style::new().red()),
                    ("".to_string(), Style::new().red()),
                ]);
            } else {
                if item.nat_traversal_type.contains("p2p") {
                    out_list.push(vec![
                        (name, Style::new().green()),
                        (item.virtual_ip, Style::new().green()),
                        (item.status, Style::new().green()),
                        (item.nat_traversal_type, Style::new().green()),
                        (item.rt, Style::new().green()),
                    ]);
                } else {
                    out_list.push(vec![
                        (name, Style::new().yellow()),
                        (item.virtual_ip, Style::new().yellow()),
                        (item.status, Style::new().yellow()),
                        (item.nat_traversal_type, Style::new().yellow()),
                        (item.rt, Style::new().yellow()),
                    ]);
                }
            }
        } else {
            out_list.push(vec![
                (name, Style::new().color256(102)),
                (item.virtual_ip, Style::new().color256(102)),
                (item.status, Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
            ]);
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
    out_list.push(vec![
        ("Name".to_string(), Style::new()),
        ("Virtual Ip".to_string(), Style::new()),
        ("Status".to_string(), Style::new()),
        ("P2P/Relay".to_string(), Style::new()),
        ("Rt".to_string(), Style::new()),
        ("NAT Type".to_string(), Style::new()),
        ("Public Ips".to_string(), Style::new()),
        ("Local Ip".to_string(), Style::new()),
        ("IPv6".to_string(), Style::new()),
    ]);
    for item in list {
        if &item.status == "Online" {
            if &item.nat_traversal_type == "p2p" {
                out_list.push(vec![
                    (item.name, Style::new().green()),
                    (item.virtual_ip, Style::new().green()),
                    (item.status, Style::new().green()),
                    (item.nat_traversal_type, Style::new().green()),
                    (item.rt, Style::new().green()),
                    (item.nat_type, Style::new().green()),
                    (item.public_ips, Style::new().green()),
                    (item.local_ip, Style::new().green()),
                    (item.ipv6, Style::new().green()),
                ]);
            } else {
                out_list.push(vec![
                    (item.name, Style::new().yellow()),
                    (item.virtual_ip, Style::new().yellow()),
                    (item.status, Style::new().yellow()),
                    (item.nat_traversal_type, Style::new().yellow()),
                    (item.rt, Style::new().yellow()),
                    (item.nat_type, Style::new().yellow()),
                    (item.public_ips, Style::new().yellow()),
                    (item.local_ip, Style::new().yellow()),
                    (item.ipv6, Style::new().yellow()),
                ]);
            }
        } else {
            out_list.push(vec![
                (item.name, Style::new().color256(102)),
                (item.virtual_ip, Style::new().color256(102)),
                (item.status, Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
                ("".to_string(), Style::new().color256(102)),
            ]);
        }
    }
    table::println_table(out_list)
}

pub fn console_chart_a(chart_a: ChartA) {
    if chart_a.disable_stats {
        println!("Traffic statistics not enabled");
        return;
    }
    println!();
    println!("-----------------------------------------------------------------");
    println!(
        "Upload total = {}",
        style(convert(chart_a.up_total)).green()
    );
    println!(
        "Download total = {}",
        style(convert(chart_a.down_total)).green()
    );
    println!("-----------------------------------------------------------------");
    let up_keys: HashSet<_> = chart_a.up_map.keys().cloned().collect();
    let down_keys: HashSet<_> = chart_a.down_map.keys().cloned().collect();
    let mut keys: Vec<Ipv4Addr> = up_keys.union(&down_keys).cloned().collect();
    // 排序
    keys.sort();

    // 找到最大的值，用于缩放条形图长度
    let up_max_value = *chart_a.up_map.values().max().unwrap_or(&0);
    let down_max_value = *chart_a.down_map.values().max().unwrap_or(&0);
    let max_value = up_max_value.max(down_max_value);
    let max_value = max_value.max(1);
    let max_height = 50;
    // 打印条形图
    for key in &keys {
        if let Some(&value) = chart_a.up_map.get(key) {
            let bar = "█".repeat(((value as f64 / max_value as f64) * max_height as f64) as usize);
            println!(
                "{:<10} | {} upload {}",
                key,
                bar,
                style(convert(value)).green()
            );
        }
        if let Some(&value) = chart_a.down_map.get(key) {
            let bar = "█".repeat(((value as f64 / max_value as f64) * max_height as f64) as usize);
            println!(
                "{:<10} | {} download {}",
                key,
                bar,
                style(convert(value)).green()
            );
        }
        println!("-");
    }
}

pub fn console_chart_b(chart_b: ChartB) {
    if chart_b.disable_stats {
        println!("Traffic statistics not enabled");
        return;
    }
    let ip = if let Some(ip) = chart_b.ip {
        ip
    } else {
        println!("Ip: None");
        return;
    };
    println!("----------------------------  upload  ----------------------------");
    println!("IP: {}", ip);
    println!("Upload total: {}", style(convert(chart_b.up_total)).green());
    println!(
        "Max: {}",
        style(convert(
            chart_b
                .up_list
                .iter()
                .max()
                .cloned()
                .map_or(0, |v| v as u64)
        ))
        .green()
    );
    console_chart_b_list(chart_b.up_list);
    println!("---------------------------- download ----------------------------");
    println!("IP: {}", ip);
    println!(
        "Download total: {}",
        style(convert(chart_b.down_total)).green()
    );
    println!(
        "Max: {}",
        style(convert(
            chart_b
                .down_list
                .iter()
                .max()
                .cloned()
                .map_or(0, |v| v as u64)
        ))
        .green()
    );
    console_chart_b_list(chart_b.down_list);
}
fn console_chart_b_list(list: Vec<usize>) {
    let max_value = *list.iter().max().unwrap_or(&0);
    let max_value = max_value.max(1);
    let max_height = max_value.min(20);
    // 遍历从最大高度到0
    for i in (0..=max_height).rev() {
        for &value in &list {
            let scaled_value = (value as f64 / max_value as f64 * max_height as f64) as usize;
            if scaled_value >= i {
                print!("█");
            } else {
                print!(" ");
            }
        }
        println!();
    }
}
