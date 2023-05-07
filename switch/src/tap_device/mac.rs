use crate::tun_device::{TunReader, TunWriter};

pub type TapReader = TunReader;
pub type TapWriter = TunWriter;
use std::net::Ipv4Addr;

pub fn create_tap(
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> crate::error::Result<(TapWriter, TapReader, [u8; 6])> {
    unimplemented!()
}