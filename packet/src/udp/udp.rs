use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;

use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ReadBytesExt};

use crate::error::*;

/// udp协议
///
/*
RFC 768   https://www.ietf.org/rfc/rfc768.txt

    0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |     源端口(16)   |   目的端口(16)    |
    +--------+--------+--------+--------+
    |     长度(16)     |    校验和(16)    |
    +--------+--------+--------+--------+
    |
    |               载荷 ...
    +---------------- ...

    注：1.长度包含标头和数据体，以字节为单位
       2.伪首部和载荷参与校验和的计算，位数不够则补0
*/

/// ipv6 udp伪首部
/*  https://datatracker.ietf.org/doc/html/rfc2460

  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  +                                                               +
  |                                                               |
  +                         Source Address                        +
  |                                                               |
  +                                                               +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  +                                                               +
  |                                                               |
  +                      Destination Address                      +
  |                                                               |
  +                                                               +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   Upper-Layer Packet Length                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      zero                     |  Next Header  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

pub struct UdpPacket<B> {
    source_ip: IpAddr,
    destination_ip: IpAddr,
    buffer: B,
}

impl<B: AsRef<[u8]>> UdpPacket<B> {
    pub fn unchecked(source_ip: IpAddr, destination_ip: IpAddr, buffer: B) -> UdpPacket<B> {
        UdpPacket {
            source_ip,
            destination_ip,
            buffer,
        }
    }
    pub fn new(source_ip: IpAddr, destination_ip: IpAddr, buffer: B) -> Result<UdpPacket<B>> {
        if buffer.as_ref().len() < 8 {
            Err(Error::SmallBuffer)?
        }
        let packet = Self::unchecked(source_ip, destination_ip, buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> UdpPacket<B> {
    /// 源端口
    pub fn source_port(&self) -> u16 {
        (&self.buffer.as_ref()[0..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// 目标端口
    pub fn destination_port(&self) -> u16 {
        (&self.buffer.as_ref()[2..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// 总字节数
    pub fn length(&self) -> u16 {
        (&self.buffer.as_ref()[4..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Checksum of the packet.
    pub fn checksum(&self) -> u16 {
        (&self.buffer.as_ref()[6..])
            .read_u16::<BigEndian>()
            .unwrap()
    }
    /// 验证校验和,ipv4中为0表示不使用校验和，ipv6校验和不能为0
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || self.cal_checksum() == 0
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[8..]
    }
    fn cal_checksum(&self) -> u16 {
        match self.source_ip {
            IpAddr::V4(src) => {
                if let IpAddr::V4(dest) = self.destination_ip {
                    return crate::ipv4_cal_checksum(
                        self.buffer.as_ref(),
                        &src,
                        &dest,
                        17,
                        self.length(),
                    );
                }
            }
            IpAddr::V6(_src) => {}
        }
        unimplemented!()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<B> {
    fn header_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..8]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<B> {
    /// 设置源端口
    pub fn set_source_port(&mut self, value: u16) -> &mut Self {
        Cursor::new(&mut self.header_mut()[0..])
            .write_u16::<BigEndian>(value)
            .unwrap();
        self
    }

    /// 设置目的端口
    pub fn set_destination_port(&mut self, value: u16) -> &mut Self {
        Cursor::new(&mut self.header_mut()[2..])
            .write_u16::<BigEndian>(value)
            .unwrap();
        self
    }
    fn set_checknum(&mut self, value: u16) {
        Cursor::new(&mut self.header_mut()[6..])
            .write_u16::<BigEndian>(value)
            .unwrap();
    }
    pub fn update_checknum(&mut self) {
        //先写0
        self.set_checknum(0);
        self.set_checknum(self.cal_checksum());
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for UdpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("udp::Packet")
            .field("source", &self.source_port())
            .field("destination", &self.destination_port())
            .field("length", &self.length())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("payload", &self.payload())
            .finish()
    }
}
