use std::io;
use ipv4::packet::IpV4Packet;

pub mod ipv4;

pub enum IpPacket<B> {
    V4(IpV4Packet<B>),
}

impl<B: AsRef<[u8]>> IpPacket<B> {
    pub fn new(buffer: B) -> io::Result<Self> {
        match buffer.as_ref()[0] >> 4 {
            4 => Ok(IpPacket::V4(IpV4Packet::new(buffer)?)),
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}
