#![cfg(windows)]

mod tap;
mod tun;
mod ffi;
mod netsh;
mod route;
use std::{io, net};
use std::net::Ipv4Addr;
pub use tap::TapDevice;
pub use tun::*;

/// Encode a string as a utf16 buffer
fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

/// Decode a string from a utf16 buffer
fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

pub trait IFace {
    fn shutdown(&self) -> io::Result<()>;
    /// 获取接口索引
    fn get_index(&self) -> io::Result<u32>;
    /// 获取名称
    fn get_name(&self) -> io::Result<String>;
    /// 设置名称
    fn set_name(&self, new_name: &str) -> io::Result<()>;
    /// 设置ip
    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> io::Result<()>;
    /// 设置路由
    fn add_route(&self, dest: Ipv4Addr,
                     netmask: Ipv4Addr,
                     gateway: Ipv4Addr, metric: u16) -> io::Result<()>;
    /// 删除路由
    fn delete_route(&self, dest: Ipv4Addr,
                        netmask: Ipv4Addr,
                        gateway: Ipv4Addr, ) -> io::Result<()>;
    /// 设置最大传输单元
    fn set_mtu(&self, mtu: u16) -> io::Result<()>;
    /// 设置跃点
    fn set_metric(&self, metric: u16) -> io::Result<()>;
}
