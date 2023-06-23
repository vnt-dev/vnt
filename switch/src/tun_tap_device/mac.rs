use std::io;
use std::net::Ipv4Addr;
use crate::tun_tap_device::{DeviceReader, DeviceType, DeviceWriter};
use tun::Device;
use parking_lot::Mutex;
use std::process::Command;
use std::sync::Arc;
use crate::tun_tap_device::unix::DeviceW;

impl DeviceWriter {
    pub fn change_ip(&self, address: Ipv4Addr, netmask: Ipv4Addr,
                     gateway: Ipv4Addr, _old_netmask: Ipv4Addr, _old_gateway: Ipv4Addr) -> io::Result<()> {
        let mut config = tun::Configuration::default();
        config
            .destination(gateway)
            .address(address)
            .netmask(netmask)
            .mtu(1420)
            .up();
        let mut dev = self.lock.lock();
        if let Err(e) = dev.configure(&config) {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
        }
        if let Err(e) = config_ip(dev.name(), address, netmask, gateway) {
            log::error!("{}",e);
        }
        let name = dev.name();
        for (address, netmask) in &self.in_ips {
            add_route(name, *address, *netmask)?;
        }
        // 当前网段路由
        add_route(name, address, netmask)?;
        // 广播和组播路由
        add_route(name, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST)?;
        add_route(name, Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]))?;
        return Ok(());
    }
}

pub fn create_device(device_type: DeviceType,
                     address: Ipv4Addr,
                     netmask: Ipv4Addr,
                     gateway: Ipv4Addr,
                     in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
) -> io::Result<(DeviceWriter, DeviceReader)> {
    match device_type {
        DeviceType::Tun => {}
        DeviceType::Tap => {
            unimplemented!()
        }
    }
    println!("========TUN网卡配置========");
    let mut config = tun::Configuration::default();

    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(1420)
        .up();

    let dev = tun::create(&config).unwrap();
    let name = dev.name();
    config_ip(name, address, netmask, gateway)?;
    for (address, netmask) in &in_ips {
        add_route(name, *address, *netmask)?;
    }
    // 当前网段路由
    add_route(name, address, netmask)?;
    // 广播和组播路由
    add_route(name, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST)?;
    add_route(name, Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]))?;
    let packet_information = dev.has_packet_information();
    let queue = dev.queue(0).unwrap();
    let reader = queue.reader();
    let writer = queue.writer();
    println!("name:{:?}", name);
    println!("========TUN网卡配置========");
    Ok((
        DeviceWriter::new(DeviceW::Tun(writer), Arc::new(Mutex::new(dev)), in_ips, address, packet_information),
        DeviceReader::new(reader),
    ))
}

fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let route_add_str: String = format!(
        "sudo route -n add -net {:?}/{:?} -interface {}",
        address, netmask, name
    );
    let route_add_out = Command::new("sh")
        .arg("-c")
        .arg(&route_add_str)
        .output()
        .expect("sh exec error!");
    if !route_add_out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("添加路由失败: cmd:{},out:{:?}", route_add_str, route_add_out)));
    }
    Ok(())
}

fn config_ip(name: &str, address: Ipv4Addr, _netmask: Ipv4Addr, gateway: Ipv4Addr) -> io::Result<()> {
    let up_eth_str: String = format!("ifconfig {} {:?} {:?} up ", name, address, gateway);
    let up_eth_out = Command::new("sh")
        .arg("-c")
        .arg(&up_eth_str)
        .output()
        .expect("sh exec error!");
    if !up_eth_out.status.success() {
        return Err(io::Error::new(io::ErrorKind::Other, format!("设置网络地址失败: cmd:{},out:{:?}", up_eth_str, up_eth_out)));
    }
    Ok(())
}

pub fn delete_device(_device_type: DeviceType) {}