use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;

use parking_lot::Mutex;

use win_tun_tap::{IFace, TapDevice};

#[derive(Clone)]
pub struct TapWriter(Arc<TapDevice>, Arc<Mutex<()>>);

impl TapWriter {
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
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
pub struct TapReader(Arc<TapDevice>);

impl TapReader {
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

pub const TAP_INTERFACE_NAME: &str = "Switch-Tap-V1";

pub fn create_tap(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> io::Result<(TapWriter, TapReader, [u8; 6])> {
    println!("========TAP网卡配置========");
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
    println!("name:{:?}", tap_device.get_name()?);
    println!("version:{:x?}", tap_device.get_version()?);
    println!("mac:{:x?}", mac);
    tap_device.set_ip(address, netmask)?;
    tap_device.set_metric(1)?;
    tap_device.set_mtu(1420)?;
    tap_device.set_status(true)?;
    tap_device.add_route(address, netmask, gateway)?;
    let tap = Arc::new(tap_device);
    println!("========TAP网卡配置========");
    Ok((
        TapWriter(tap.clone(), Arc::default()),
        TapReader(tap),
        mac
    ))
}

pub fn delete_tap() {
    let tap_device = match TapDevice::open(TAP_INTERFACE_NAME) {
        Ok(tap_device) => tap_device,
        Err(_) => {
            return;
        }
    };
    let _ = tap_device.delete();
}