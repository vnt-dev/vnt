use std::io;
use std::net::Ipv4Addr;
use crate::tun_tap_device::{DeviceReader, DeviceType, DeviceWriter, DriverInfo};
use tun::Device;
use parking_lot::Mutex;
use std::process::Command;
use std::sync::Arc;
use crate::tun_tap_device::linux_mac::DeviceW;

impl DeviceWriter {
    pub fn change_ip(&self, address: Ipv4Addr, netmask: Ipv4Addr,
                     gateway: Ipv4Addr, _old_netmask: Ipv4Addr, _old_gateway: Ipv4Addr) -> io::Result<()> {
        let mut config = tun::Configuration::default();
        let broadcast_address = (!u32::from_be_bytes(netmask.octets()))
            | u32::from_be_bytes(gateway.octets());
        let broadcast_address = Ipv4Addr::from(broadcast_address);
        config
            .destination(gateway)
            .address(address)
            .netmask(netmask)
            .broadcast(broadcast_address)
            // .queues(2)
            .up();
        let mut dev = self.lock.lock();
        if let Err(e) = dev.configure(&config) {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
        }
        let name = dev.name();
        for (address, netmask) in &self.in_ips {
            add_route(name, *address, *netmask)?;
        }
        // 当前网段路由
        // add_route(name, address, netmask)?;
        // 广播和组播路由
        add_route(name, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST)?;
        add_route(name, Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]))?;
        return Ok(());
    }
}

pub fn add_route(name: &str, address: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
    let route_add_str: String = format!(
        "ip route add {:?}/{:?} dev {}",
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

pub fn create_device(device_type: DeviceType,
                     address: Ipv4Addr,
                     netmask: Ipv4Addr,
                     gateway: Ipv4Addr,
                     in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
                     mtu: u16,
) -> io::Result<(DeviceWriter, DeviceReader,DriverInfo)> {
    let mut config = tun::Configuration::default();
    let broadcast_address = (!u32::from_be_bytes(netmask.octets()))
        | u32::from_be_bytes(gateway.octets());
    let broadcast_address = Ipv4Addr::from(broadcast_address);
    config
        .destination(gateway)
        .address(address)
        .netmask(netmask)
        .mtu(mtu.into())
        .broadcast(broadcast_address)
        // .queues(2) 用多个队列有兼容性问题
        .up();
    match device_type {
        DeviceType::Tun => {}
        DeviceType::Tap => {
            config.layer(tun::Layer::L2);
        }
    }
    let dev = tun::create(&config).expect("tun/tap failed to create");
    let packet_information = dev.has_packet_information();
    let queue = dev.queue(0).unwrap();
    let reader = queue.reader();
    let writer = queue.writer();
    let name = dev.name();
    for (address, netmask) in &in_ips {
        add_route(name, *address, *netmask)?;
    }
    // 当前网段路由
    // add_route(name, address, netmask)?;
    // 广播和组播路由
    add_route(name, Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST)?;
    add_route(name, Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]))?;
    let device_w = match device_type {
        DeviceType::Tun => {
            DeviceW::Tun(writer)
        }
        DeviceType::Tap => {
            let get_mac_cmd = format!("cat /sys/class/net/{}/address", name);
            let mac_out = Command::new("sh")
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
            DeviceW::Tap((writer, mac))
        }
    };
    let driver_info = DriverInfo {
        device_type,
        name:name.to_string(),
        version:String::new(),
        mac: None,
    };
    Ok((
        DeviceWriter::new(device_w, Arc::new(Mutex::new(dev)), in_ips, address, packet_information),
        DeviceReader::new(reader),
        driver_info,
    ))
}

pub fn delete_device(_device_type: DeviceType) {}