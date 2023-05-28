use std::io;
use crate::tun_device::{TunReader, TunWriter};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tun::Device;
use parking_lot::Mutex;
use std::process::Command;

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
) -> crate::error::Result<(TunWriter, TunReader)> {
    println!("========TUN网卡配置========");
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        // .queues(2) 用多个队列有兼容性问题
        .up();

    let dev = tun::create(&config).unwrap();
    let packet_information = dev.has_packet_information();
    let queue = dev.queue(0).unwrap();
    let reader = queue.reader();
    let writer = queue.writer();
    let name = dev.name();
    println!("name:{:?}", name);
    for (address, netmask) in in_ips {
        add_route(name, address, netmask)?;
    }
    println!("========TUN网卡配置========");
    Ok((
        TunWriter(writer, packet_information, Arc::new(Mutex::new(dev))),
        TunReader(reader, packet_information),
    ))
}

fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let route_add_str: String = format!(
        "ip route add {:?}/{:?} dev {}",
        address, netmask, name
    );
    let route_add_out = Command::new("sh")
        .arg("-c")
        .arg(route_add_str)
        .output()
        .expect("sh exec error!");
    if !route_add_out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("添加路由失败: {:?}", route_add_out)));
    }
    Ok(())
}
