use crate::tun_device::{TunReader, TunWriter};

pub type TapReader = TunReader;
pub type TapWriter = TunWriter;

use std::net::Ipv4Addr;
use std::sync::Arc;
use tun::Device;
use parking_lot::Mutex;
use std::io;

pub fn create_tap(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> io::Result<(TunWriter, TunReader, [u8; 6])> {
    println!("========TAP网卡配置========");
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        .layer(tun::Layer::L2)
        // .queues(2) 用多个队列有兼容性问题
        .up();

    let dev = tun::create(&config).unwrap();
    let name = dev.name();
    println!("name:{:?}", name);
    let packet_information = dev.has_packet_information();
    let queue = dev.queue(0).unwrap();
    let reader = queue.reader();
    let writer = queue.writer();
    let get_mac_cmd = format!("cat /sys/class/net/{}/address", name);
    let mac_out = std::process::Command::new("sh")
        .arg("-c")
        .arg(get_mac_cmd)
        .output()
        .expect("sh exec error!");
    if !mac_out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("获取mac地址错误: {:?}", mac_out)));
    }
    let mac_str = String::from_utf8(mac_out.stdout).unwrap();
    let mut mac = [0; 6];
    let mut split = mac_str.split(":");
    for i in 0..6 {
        mac[i] = u8::from_str_radix(&split.next().unwrap()[..2], 16).unwrap();
    }
    println!("mac:{:?}", mac);
    println!("========TAP网卡配置========");
    Ok((
        TunWriter(writer, packet_information, Arc::new(Mutex::new(dev))),
        TunReader(reader, packet_information),
        mac
    ))
}
