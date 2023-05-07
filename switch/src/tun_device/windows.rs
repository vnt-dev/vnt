use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use libloading::Library;
use parking_lot::Mutex;

use win_tun_tap::{IFace, TunDevice};
use win_tun_tap::packet::TunPacket;

pub const TUN_INTERFACE_NAME: &str = "Switch-V1";
pub const TUN_POOL_NAME: &str = "Switch-V1";

#[derive(Clone)]
pub struct TunWriter(Arc<TunDevice>, Arc<Mutex<()>>);

impl TunWriter {
    pub fn write(&self, buf: &[u8]) -> io::Result<()> {
        let mut packet = self.0.allocate_send_packet(buf.len() as u16)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.0.send_packet(packet);
        return Ok(());
    }
    pub fn change_ip(
        &self,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        old_netmask: Ipv4Addr,
        old_gateway: Ipv4Addr,
    ) -> io::Result<()> {
        if let Err(e) =
            self.0.delete_route(dest(old_gateway, old_gateway), old_netmask, old_gateway)
        {
            log::warn!("{:?}", e);
        }
        self.0.set_ip(address, netmask)?;
        self.0.add_route(dest(gateway, netmask), netmask, gateway)
    }
    pub fn close(&self) -> io::Result<()> {
        self.0.shutdown()
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

#[derive(Clone)]
pub struct TunReader(Arc<TunDevice>);


impl TunReader {
    pub fn next(&self) -> io::Result<TunPacket> {
        self.0.receive_blocking()
    }
}

pub fn create_tun(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> io::Result<(TunWriter, TunReader)> {
    unsafe {
        println!("========TUN网卡配置========");
        match Library::new("wintun.dll") {
            Ok(lib) => match TunDevice::open(lib, TUN_INTERFACE_NAME) {
                Ok(tun_device) => {
                    let _ = tun_device.delete();
                }
                Err(_) => {}
            },
            Err(e) => {
                log::error!("wintun.dll not found");
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
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{:?}", e),
                ));
            }
        };
        println!("name:{:?}", tun_device.get_name()?);
        println!("version:{:?}", tun_device.version()?);
        log::error!("创建tun成功 {:?}",tun_device.get_name()?);
        tun_device.set_ip(address, netmask)?;
        tun_device.set_mtu(1420)?;
        tun_device.add_route(address, netmask, gateway)?;
        let device = Arc::new(tun_device);
        println!("========TUN网卡配置========");
        Ok((
            TunWriter(device.clone(), Arc::default()),
            TunReader(device),
        ))
    }
}

pub fn delete_tun() {
    unsafe {
        match Library::new("wintun.dll") {
            Ok(lib) => match TunDevice::open(lib, TUN_INTERFACE_NAME) {
                Ok(tun_device) => {
                    let _ = tun_device.delete();
                }
                Err(_) => {}
            },
            Err(_) => {}
        }
    }
}





