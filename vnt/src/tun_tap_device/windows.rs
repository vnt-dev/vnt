use std::{io, thread};
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::sync::Arc;
use std::time::Duration;
use libloading::Library;
use parking_lot::Mutex;
use packet::ethernet;
use packet::ethernet::packet::EthernetPacket;
use win_tun_tap::{IFace, TapDevice, TunDevice};
use crate::tun_tap_device::{DriverInfo, DeviceType};

pub const TUN_INTERFACE_NAME: &str = "Vnt-Tun-V1";
pub const TUN_POOL_NAME: &str = "Vnt-Tun-V1";
pub const TAP_INTERFACE_NAME: &str = "Vnt-Tap-V1";

pub enum Device {
    Tun(TunDevice),
    Tap((TapDevice, [u8; 6])),
}

impl Device {
    pub fn is_tun(&self) -> bool {
        match self {
            Device::Tun(_) => {
                true
            }
            Device::Tap(_) => {
                false
            }
        }
    }
}

#[derive(Clone)]
pub struct DeviceWriter {
    device: Arc<Device>,
    lock: Arc<Mutex<()>>,
    in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl DeviceWriter {
    pub fn new(device: Arc<Device>, in_ips: Vec<(Ipv4Addr, Ipv4Addr)>, _ip: Ipv4Addr) -> Self {
        Self {
            device,
            lock: Arc::new(Default::default()),
            in_ips,
        }
    }
}

impl DeviceWriter {
    ///tun网卡写入ipv4数据
    pub fn write_ipv4_tun(&self, buf: &[u8]) -> io::Result<()> {
        match self.device.as_ref() {
            Device::Tun(dev) => {
                let mut packet = dev.allocate_send_packet(buf.len() as u16)?;
                packet.bytes_mut().copy_from_slice(buf);
                dev.send_packet(packet);
                Ok(())
            }
            Device::Tap(_) => {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
        }
    }
    /// tap网卡写入以太网帧
    pub fn write_ethernet_tap(&self, buf: &[u8]) -> io::Result<()> {
        match self.device.as_ref() {
            Device::Tun(_) => {
                Err(io::Error::from(io::ErrorKind::Unsupported))
            }
            Device::Tap((dev, _)) => {
                dev.write(buf)?;
                Ok(())
            }
        }
    }
    ///写入ipv4数据，头部必须留14字节，给tap写入以太网帧头
    pub fn write_ipv4(&self, buf: &mut [u8]) -> io::Result<()> {
        match self.device.as_ref() {
            Device::Tun(dev) => {
                let mut packet = dev.allocate_send_packet((buf.len() - 14) as u16)?;
                packet.bytes_mut().copy_from_slice(&buf[14..]);
                dev.send_packet(packet);
            }
            Device::Tap((dev, mac)) => {
                let source_mac = [buf[14 + 12], buf[14 + 13], buf[14 + 14], buf[14 + 15], !mac[5], 234];
                let mut ethernet_packet = EthernetPacket::unchecked(buf);
                ethernet_packet.set_source(&source_mac);
                ethernet_packet.set_destination(mac);
                ethernet_packet.set_protocol(ethernet::protocol::Protocol::Ipv4);
                dev.write(&ethernet_packet.buffer)?;
            }
        }
        Ok(())
    }
    pub fn change_ip(
        &self,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        old_netmask: Ipv4Addr,
        old_gateway: Ipv4Addr,
    ) -> io::Result<()> {
        let _guard = self.lock.lock();
        let dev: &dyn IFace = match self.device.as_ref() {
            Device::Tun(dev) => {
                dev as &dyn IFace
            }
            Device::Tap((dev, _)) => {
                dev as &dyn IFace
            }
        };
        if let Err(e) =
            dev.delete_route(dest(old_gateway, old_gateway), old_netmask, old_gateway)
        {
            log::warn!("{:?}", e);
        }
        dev.set_ip(address, netmask)?;
        for (address, netmask) in &self.in_ips {
            dev.add_route(*address, *netmask, gateway, 1)?;
        }
        // 当前网段路由
        dev.add_route(address, netmask, gateway, 1)?;
        // 广播和组播路由
        dev.add_route(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, gateway, 1)?;
        dev.add_route(Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]), gateway, 1)?;
        delete_cache();
        Ok(())
    }
    pub fn close(&self) -> io::Result<()> {
        match self.device.as_ref() {
            Device::Tun(dev) => {
                dev.shutdown()
            }
            Device::Tap((dev, _)) => {
                dev.shutdown()
            }
        }
    }
    pub fn is_tun(&self) -> bool {
        self.device.is_tun()
    }
}

fn dest(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    let ip = ip.octets();
    let mask = mask.octets();
    Ipv4Addr::from([
        ip[0] & mask[0],
        ip[1] & mask[1],
        ip[2] & mask[2],
        ip[3] & mask[3],
    ])
}

pub struct DeviceReader {
    device: Arc<Device>,
}

impl DeviceReader {
    pub fn new(device: Arc<Device>) -> Self {
        Self {
            device,
        }
    }
}

impl DeviceReader {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.device.as_ref() {
            Device::Tun(dev) => {
                let packet = dev.receive_blocking()?;
                let packet = packet.bytes();
                let len = packet.len();
                if len > buf.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "data too long"));
                }
                buf[..len].copy_from_slice(packet);
                Ok(len)
            }
            Device::Tap((dev, _)) => {
                dev.read(buf)
            }
        }
    }
}

fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
    mtu: u16,
) -> io::Result<(DeviceWriter, DeviceReader, DriverInfo)> {
    unsafe {
        match Library::new("wintun.dll") {
            Ok(lib) => match TunDevice::delete_for_name(lib, TUN_INTERFACE_NAME) {
                Ok(_) => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {}
            },
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("wintun.dll not found {:?}", e),
                ));
            }
        }
        let tun_device = match TunDevice::create(
            Library::new("wintun.dll").unwrap(),
            TUN_POOL_NAME,
            TUN_INTERFACE_NAME,
        ) {
            Ok(tun_device) => tun_device,
            Err(_) => {
                thread::sleep(Duration::from_millis(200));
                match TunDevice::create(
                    Library::new("wintun.dll").unwrap(),
                    TUN_POOL_NAME,
                    TUN_INTERFACE_NAME,
                ) {
                    Ok(tun_device) => tun_device,
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("{:?}", e),
                        ));
                    }
                }
            }
        };
        let name = tun_device.get_name()?;
        let version = format!("{:?}", tun_device.version()?);
        tun_device.set_ip(address, netmask)?;
        tun_device.set_metric(1)?;
        tun_device.set_mtu(mtu)?;
        // ip代理路由
        for (address, netmask) in &in_ips {
            tun_device.add_route(*address, *netmask, gateway, 1)?;
        }
        // 当前网段路由
        tun_device.add_route(address, netmask, gateway, 1)?;
        // 广播和组播路由
        tun_device.add_route(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, gateway, 1)?;
        tun_device.add_route(Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]), gateway, 1)?;
        delete_cache();
        let device = Arc::new(Device::Tun(tun_device));
        let driver_info = DriverInfo {
            device_type: DeviceType::Tun,
            name,
            version,
            mac: None,
        };
        Ok((
            DeviceWriter::new(device.clone(), in_ips, address),
            DeviceReader::new(device),
            driver_info
        ))
    }
}

fn delete_cache() {
    //清除路由缓存
    let delete_cache = "netsh interface ip delete destinationcache";
    let out = std::process::Command::new("cmd")
        .creation_flags(0x08000000)
        .arg("/C")
        .arg(delete_cache)
        .output()
        .unwrap();
    if !out.status.success() {
        log::warn!("删除缓存失败:{:?}",out);
    }
}

fn delete_tun() {
    unsafe {
        match Library::new("wintun.dll") {
            Ok(lib) => match TunDevice::delete_for_name(lib, TUN_INTERFACE_NAME) {
                Ok(_) => {}
                Err(_) => {}
            },
            Err(_) => {}
        }
    }
}

fn create_tap(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
    mtu: u16,
) -> io::Result<(DeviceWriter, DeviceReader, DriverInfo)> {
    let tap_device = match TapDevice::open(TAP_INTERFACE_NAME) {
        Ok(tap_device) => tap_device,
        Err(e) => {
            log::warn!("{:?}", e);
            let tap_device = TapDevice::create()?;
            tap_device.set_name(TAP_INTERFACE_NAME)?;
            tap_device
        }
    };
    let mac = tap_device.get_mac()?;
    let name = tap_device.get_name()?;
    let version = format!("{:?}", tap_device.get_version()?);
    let mac_str = format!("mac:{:x?}", mac);
    tap_device.set_ip(address, netmask)?;
    tap_device.set_metric(1)?;
    tap_device.set_mtu(mtu)?;
    tap_device.set_status(true)?;
    tap_device.add_route(address, netmask, gateway, 1)?;
    for (address, netmask) in &in_ips {
        tap_device.add_route(*address, *netmask, gateway, 1)?;
    }
    // 广播和组播路由
    tap_device.add_route(Ipv4Addr::BROADCAST, Ipv4Addr::BROADCAST, gateway, 1)?;
    tap_device.add_route(Ipv4Addr::from([224, 0, 0, 0]), Ipv4Addr::from([240, 0, 0, 0]), gateway, 1)?;
    delete_cache();
    let tap = Arc::new(Device::Tap((tap_device, mac)));
    let driver_info = DriverInfo {
        device_type: DeviceType::Tap,
        name,
        version,
        mac: Some(mac_str),
    };
    Ok((
        DeviceWriter::new(tap.clone(), in_ips, address),
        DeviceReader::new(tap),
        driver_info
    ))
}

fn delete_tap() {
    let tap_device = match TapDevice::open(TAP_INTERFACE_NAME) {
        Ok(tap_device) => tap_device,
        Err(_) => {
            return;
        }
    };
    let _ = tap_device.delete();
}

pub fn create_device(device_type: DeviceType, address: Ipv4Addr,
                     netmask: Ipv4Addr,
                     gateway: Ipv4Addr,
                     in_ips: Vec<(Ipv4Addr, Ipv4Addr)>,
                     mtu: u16) -> io::Result<(DeviceWriter, DeviceReader, DriverInfo)> {
    match device_type {
        DeviceType::Tun => {
            create_tun(address, netmask, gateway, in_ips, mtu)
        }
        DeviceType::Tap => {
            create_tap(address, netmask, gateway, in_ips, mtu)
        }
    }
}

pub fn delete_device(device_type: DeviceType) {
    match device_type {
        DeviceType::Tun => {
            delete_tun()
        }
        DeviceType::Tap => {
            delete_tap()
        }
    }
}

