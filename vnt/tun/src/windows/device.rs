use crate::device::IFace;
use crate::windows::{tap, tun};
use std::io;
use std::net::Ipv4Addr;

pub enum Device {
    Tap(tap::Device),
    Tun(tun::Device),
}

impl Device {
    pub fn new(name: String, tap: bool) -> io::Result<Self> {
        if tap {
            Ok(Device::Tap(tap::Device::new(name)?))
        } else {
            Ok(Device::Tun(tun::Device::new(name)?))
        }
    }
    pub fn check_tun_dll() -> io::Result<()> {
        crate::windows::check::check_win_tun_dll()
    }
}

impl IFace for Device {
    fn version(&self) -> io::Result<String> {
        match self {
            Device::Tap(dev) => dev.version(),
            Device::Tun(dev) => dev.version(),
        }
    }

    fn name(&self) -> io::Result<String> {
        match self {
            Device::Tap(dev) => dev.name(),
            Device::Tun(dev) => dev.name(),
        }
    }

    fn shutdown(&self) -> io::Result<()> {
        match self {
            Device::Tap(dev) => dev.shutdown(),
            Device::Tun(dev) => dev.shutdown(),
        }
    }

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        match self {
            Device::Tap(dev) => dev.set_ip(address, mask),
            Device::Tun(dev) => dev.set_ip(address, mask),
        }
    }

    fn mtu(&self) -> io::Result<u32> {
        match self {
            Device::Tap(dev) => dev.mtu(),
            Device::Tun(dev) => dev.mtu(),
        }
    }

    fn set_mtu(&self, value: u32) -> io::Result<()> {
        match self {
            Device::Tap(dev) => dev.set_mtu(value),
            Device::Tun(dev) => dev.set_mtu(value),
        }
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> io::Result<()> {
        match self {
            Device::Tap(dev) => dev.add_route(dest, netmask, metric),
            Device::Tun(dev) => dev.add_route(dest, netmask, metric),
        }
    }

    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        match self {
            Device::Tap(dev) => dev.delete_route(dest, netmask),
            Device::Tun(dev) => dev.delete_route(dest, netmask),
        }
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Device::Tap(dev) => dev.read(buf),
            Device::Tun(dev) => dev.read(buf),
        }
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Device::Tap(dev) => dev.write(buf),
            Device::Tun(dev) => dev.write(buf),
        }
    }
}
