use std::{fmt, io};
use std::net::Ipv4Addr;
use crate::cal_checksum;

/// igmp v1
/* https://datatracker.ietf.org/doc/html/rfc1112
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |Version| Type  |    Unused     |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Group Address                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/// v1版本的报文
pub struct IgmpV1Packet<B> {
    pub buffer: B,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IgmpV1Type {
    /// 0x11 所有组224.0.0.1或者特定组
    Query,
    /// 0x12
    ReportV1,
    Unknown(u8),
}

impl From<u8> for IgmpV1Type {
    fn from(value: u8) -> IgmpV1Type {
        use self::IgmpV1Type::*;

        match value {
            0x11 => Query,
            0x12 => ReportV1,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for IgmpV1Type {
    fn into(self) -> u8 {
        match self {
            IgmpV1Type::Query => 0x11,
            IgmpV1Type::ReportV1 => 0x12,
            IgmpV1Type::Unknown(v) => v
        }
    }
}

impl<B: AsRef<[u8]>> IgmpV1Packet<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() != 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        } else {
            let packet = Self::unchecked(buffer);
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]>> IgmpV1Packet<B> {
    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }
    pub fn igmp_type(&self) -> IgmpV1Type {
        IgmpV1Type::from(self.buffer.as_ref()[0] & 0x0F)
    }
    pub fn unused(&self) -> u8 {
        self.buffer.as_ref()[1]
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || cal_checksum(self.buffer.as_ref()) == 0
    }
    pub fn group_address(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[4..8].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IgmpV1Packet<B> {
    pub fn set_version(&mut self, version: u8) {
        self.buffer.as_mut()[0] = (version << 4) | 0x0F & self.buffer.as_mut()[0]
    }
    pub fn set_type(&mut self, igmp_type: IgmpV1Type) {
        let t: u8 = igmp_type.into();
        self.buffer.as_mut()[0] = self.buffer.as_mut()[0] & 0xF0 | t
    }
    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    pub fn update_checksum(&mut self) {
        self.set_checksum(0);
        self.set_checksum(cal_checksum(self.buffer.as_ref()));
    }
    pub fn set_group_address(&mut self, group_address: Ipv4Addr) {
        self.buffer.as_mut()[4..8].copy_from_slice(&group_address.octets());
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IgmpV1Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("igmp::V1")
            .field("version", &self.version())
            .field("type", &self.igmp_type())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("group_address", &self.group_address())
            .finish()
    }
}