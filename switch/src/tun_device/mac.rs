use std::io;
use std::io::{Error, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::process::Command;

use bytes::BufMut;
use tun::platform::posix::{Reader, Writer};
use tun::Device;

use crate::tun_device::{TunReader, TunWriter};

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> crate::error::Result<(TunWriter, TunReader)> {
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        .up();

    let dev = tun::create(&config).unwrap();
    let up_eth_str: String = format!("ifconfig {} {:?} {:?} up ", dev.name(), address, gateway);
    let route_add_str: String = format!(
        "sudo route -n add -net {:?} -netmask {:?} {:?}",
        address, netmask, gateway
    );
    let up_eth_out = Command::new("sh")
        .arg("-c")
        .arg(up_eth_str)
        .output()
        .expect("sh exec error!");
    if !up_eth_out.status.success() {
        return Err(crate::error::Error::Stop(format!(
            "设置地址失败:{:?}",
            up_eth_out
        )));
    }
    let if_config_out = Command::new("sh")
        .arg("-c")
        .arg(route_add_str)
        .output()
        .expect("sh exec error!");
    if !if_config_out.status.success() {
        return Err(crate::error::Error::Stop(format!(
            "设置路由失败:{:?}",
            if_config_out
        )));
    }
    // println!("{:?}", if_config_out);
    // let cmd_str: String = " ifconfig|grep  flags=8051|awk -F ':' '{print $1}'|tail -1".to_string();
    //
    // let cmd_str_out = Command::new("sh")
    //     .arg("-c")
    //     .arg(cmd_str)
    //     .output()
    //     .expect("sh exec error!");
    // if !cmd_str_out.status.success(){
    //     return Err(Error::Stop(format!("设置路由失败:{:?}", cmd_str_out)));
    // }
    // println!("{:?}", cmd_str_out);
    let packet_information = dev.has_packet_information();
    let (reader, writer) = dev.split();
    Ok((
        TunWriter(writer, packet_information),
        TunReader(reader, packet_information),
    ))
}
