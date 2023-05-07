use std::io;
use std::sync::Arc;

use bytes::BufMut;
use tun::platform::posix::{Reader, Writer};
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use tun::platform::linux::Device;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use tun::platform::macos::Device;
use parking_lot::Mutex;

#[derive(Clone)]
pub struct TunReader(pub(crate) Reader, pub(crate) bool);

impl TunReader {
    pub fn read(&self, buf: & mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}


#[derive(Clone)]
pub struct TunWriter(pub(crate) Writer, pub(crate) bool, pub(crate) Arc<Mutex<Device>>);

impl TunWriter {
    pub fn write(&self, packet: &[u8]) -> io::Result<()> {
        if self.1 {
            let mut buf = Vec::<u8>::with_capacity(4 + packet.len());
            buf.put_u16(0);
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            buf.put_u16(libc::PF_INET as u16);
            #[cfg(any(target_os = "linux", target_os = "android"))]
            buf.put_u16(libc::ETH_P_IP as u16);
            buf.extend_from_slice(packet);
            self.0.write_all(&buf)
        } else {
            self.0.write_all(packet)
        }
    }
    pub fn close(&self) -> io::Result<()>{
        unsafe {
            let raw = self.0.as_raw_fd();
            if raw >= 0 {
                libc::close(raw);
            }
        }
        Ok(())
    }
    pub fn change_ip(&self, address: Ipv4Addr, netmask: Ipv4Addr,
                     gateway: Ipv4Addr, _old_netmask: Ipv4Addr, _old_gateway: Ipv4Addr) -> io::Result<()> {
        let mut config = tun::Configuration::default();
        use tun::Device;
        config
            .destination(gateway)
            .address(address)
            .netmask(netmask)
            .mtu(1420)
            // .queues(2)
            .up();
        let mut dev = self.2.lock();
        if let Err(e) = dev.configure(&config) {
            return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)));
        }
        #[cfg(target_os = "macos")]
        if let Err(e) = crate::tun_device::mac::config_ip(dev.name(), address, netmask, gateway){
            log::error!("{}",e);
        }
        return Ok(());
    }
}
