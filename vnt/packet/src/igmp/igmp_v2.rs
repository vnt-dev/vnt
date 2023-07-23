use std::{fmt, io};
use std::net::Ipv4Addr;
use crate::cal_checksum;

/// igmp v2
/* https://www.rfc-editor.org/rfc/rfc2236.html

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Type     | Max Resp Time |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Group Address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/// v2版本的报文
pub struct IgmpV2Packet<B> {
    pub buffer: B,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IgmpV2Type {
    /// 0x11 所有组224.0.0.1或者特定组
    Query,
    /// 0x16
    ReportV2,
    LeaveV2,
    Unknown(u8),
}

impl From<u8> for IgmpV2Type {
    fn from(value: u8) -> IgmpV2Type {
        use self::IgmpV2Type::*;

        match value {
            0x11 => Query,
            0x16 => ReportV2,
            0x17 => LeaveV2,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for IgmpV2Type {
    fn into(self) -> u8 {
        match self {
            IgmpV2Type::Query => 0x11,
            IgmpV2Type::ReportV2 => 0x16,
            IgmpV2Type::LeaveV2 => 0x17,
            IgmpV2Type::Unknown(v) => v
        }
    }
}

impl<B: AsRef<[u8]>> IgmpV2Packet<B> {
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

impl<B: AsRef<[u8]>> IgmpV2Packet<B> {
    pub fn igmp_type(&self) -> IgmpV2Type {
        IgmpV2Type::from(self.buffer.as_ref()[0])
    }
    pub fn max_resp_time(&self) -> u8 {
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

impl<B: AsRef<[u8]> + AsMut<[u8]>> IgmpV2Packet<B> {
    pub fn set_type(&mut self, igmp_type: IgmpV2Type) {
        self.buffer.as_mut()[0] = igmp_type.into()
    }
    pub fn set_max_resp_time(&mut self, resp: u8) {
        self.buffer.as_mut()[1] = resp
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

impl<B: AsRef<[u8]>> fmt::Debug for IgmpV2Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("igmp::V2")
            .field("type", &self.igmp_type())
            .field("max_resp_time", &self.max_resp_time())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("group_address", &self.group_address())
            .finish()
    }
}
