use std::{fmt, io};
use std::net::Ipv4Addr;

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
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    buffer: B,
}

impl<B: AsRef<[u8]>> UdpPacket<B> {
    pub fn unchecked(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, buffer: B) -> UdpPacket<B> {
        UdpPacket {
            source_ip,
            destination_ip,
            buffer,
        }
    }
    pub fn new(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, buffer: B) -> io::Result<UdpPacket<B>> {
        if buffer.as_ref().len() < 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let packet = Self::unchecked(source_ip, destination_ip, buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> UdpPacket<B> {
    /// 源端口
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
    }

    /// 目标端口
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }

    /// 总字节数
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap())
    }

    /// Checksum of the packet.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap())
    }
    /// 验证校验和,ipv4中为0表示不使用校验和，ipv6校验和不能为0
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || self.cal_checksum() == 0
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[8..]
    }
    fn cal_checksum(&self) -> u16 {
        crate::ipv4_cal_checksum(
            self.buffer.as_ref(),
            &self.source_ip,
            &self.destination_ip,
            17,
        )
    }
}

// impl<B: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<B> {
//     fn header_mut(&mut self) -> &mut [u8] {
//         &mut self.buffer.as_mut()[..8]
//     }
// }

impl<B: AsRef<[u8]> + AsMut<[u8]>> UdpPacket<B> {
    /// 设置源端口
    pub fn set_source_port(&mut self, value: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&value.to_be_bytes())
    }

    /// 设置目的端口
    pub fn set_destination_port(&mut self, value: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&value.to_be_bytes())
    }
    fn set_checksum(&mut self, value: u16) {
        self.buffer.as_mut()[6..8].copy_from_slice(&value.to_be_bytes())
    }
    pub fn update_checksum(&mut self) {
        //先写0
        self.set_checksum(0);
        self.set_checksum(self.cal_checksum());
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
