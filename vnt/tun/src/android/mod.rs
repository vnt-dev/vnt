use crate::device::IFace;
use crate::Fd;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::RawFd;

pub struct Device {
    fd: Fd,
}

impl Device {
    pub fn new(fd: RawFd) -> io::Result<Self> {
        Ok(Self { fd: Fd::new(fd)? })
    }
}
impl IFace for Device {
    fn version(&self) -> io::Result<String> {
        Ok(String::new())
    }

    fn name(&self) -> io::Result<String> {
        Ok(String::new())
    }

    fn shutdown(&self) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn mtu(&self) -> io::Result<u32> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn set_mtu(&self, value: u32) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }
}
