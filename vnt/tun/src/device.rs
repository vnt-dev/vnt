use io::Result;
use std::io;
use std::net::Ipv4Addr;

pub trait IFace {
    fn version(&self) -> Result<String>;
    /// Get the device name.
    fn name(&self) -> Result<String>;

    fn shutdown(&self) -> Result<()>;

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> Result<()>;

    /// Get the MTU.
    fn mtu(&self) -> Result<u32>;

    /// Set the MTU.
    fn set_mtu(&self, value: u32) -> Result<()>;
    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> Result<()>;
    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> Result<()>;

    fn read(&self, buf: &mut [u8]) -> Result<usize>;
    fn write(&self, buf: &[u8]) -> Result<usize>;
}
