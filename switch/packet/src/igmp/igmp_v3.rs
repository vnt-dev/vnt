use std::{fmt, io};
use std::net::Ipv4Addr;

use crate::cal_checksum;

/// igmp v3
/* https://www.rfc-editor.org/rfc/rfc3376
Query:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Type = 0x11  | Max Resp Code |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Group Address                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                              .                              -+
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

-----------------------------------------------------------------------------

Report:
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Type = 0x22  |    Reserved   |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |           Reserved            |  Number of Group Records (M)  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [1]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [2]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                               .                               |
      .                               .                               .
      |                               .                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                        Group Record [M]                       .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Group Record:

      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Multicast Address                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                                                             -+
      .                               .                               .
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      .                                                               .
      .                         Auxiliary Data                        .
      .                                                               .
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Record Type:
    1    MODE_IS_INCLUDE 表示主机希望加入指定组播组并指定了一个或多个源地址
    2    MODE_IS_EXCLUDE 表示主机希望加入指定组播组但排除了一个或多个源地址
    3    CHANGE_TO_INCLUDE_MODE 表示主机正在将组播组的过滤模式从排除切换为包括，指定了一个或多个源地址
    4    CHANGE_TO_EXCLUDE_MODE 表示主机正在将组播组的过滤模式从包括切换为排除，指定了一个或多个源地址
    5    ALLOW_NEW_SOURCES 表示主机希望在已有的源地址列表中添加新的源地址，指定了一个或多个源地址
    6    BLOCK_OLD_SOURCES 表示主机希望在已有的源地址列表中删除旧的源地址，指定了一个或多个源地址
 */
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IgmpV3Type {
    /// 0x11 所有组224.0.0.1或者特定组
    Query,
    /// 0x22
    ReportV3,
    Unknown(u8),
}

impl From<u8> for IgmpV3Type {
    fn from(value: u8) -> IgmpV3Type {
        use self::IgmpV3Type::*;

        match value {
            0x11 => Query,
            0x22 => ReportV3,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for IgmpV3Type {
    fn into(self) -> u8 {
        match self {
            IgmpV3Type::Query => 0x11,
            IgmpV3Type::ReportV3 => 0x22,
            IgmpV3Type::Unknown(v) => v
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum IgmpV3RecordType {
    //1    MODE_IS_INCLUDE 表示主机希望加入指定组播组并指定了一个或多个源地址
    ModeIsInclude,
    //2    MODE_IS_EXCLUDE 表示主机希望加入指定组播组但排除了一个或多个源地址
    ModeIsExclude,
    //3    CHANGE_TO_INCLUDE_MODE 表示主机正在将组播组的过滤模式从排除切换为包括，指定了一个或多个源地址
    ChangeToIncludeMode,
    //4    CHANGE_TO_EXCLUDE_MODE 表示主机正在将组播组的过滤模式从包括切换为排除，指定了一个或多个源地址
    ChangeToExcludeMode,
    //5    ALLOW_NEW_SOURCES 表示主机希望在已有的源地址列表中添加新的源地址，指定了一个或多个源地址
    AllowNewSources,
    //6    BLOCK_OLD_SOURCES 表示主机希望在已有的源地址列表中删除旧的源地址，指定了一个或多个源地址
    BlockOldSources,
    Unknown(u8),
}

impl From<u8> for IgmpV3RecordType {
    fn from(value: u8) -> IgmpV3RecordType {
        use self::IgmpV3RecordType::*;

        match value {
            1 => ModeIsInclude,
            2 => ModeIsExclude,
            3 => ChangeToIncludeMode,
            4 => ChangeToExcludeMode,
            5 => AllowNewSources,
            6 => BlockOldSources,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for IgmpV3RecordType {
    fn into(self) -> u8 {
        use self::IgmpV3RecordType::*;

        match self {
            ModeIsInclude => 1,
            ModeIsExclude => 2,
            ChangeToIncludeMode => 3,
            ChangeToExcludeMode => 4,
            AllowNewSources => 5,
            BlockOldSources => 6,
            Unknown(v) => v,
        }
    }
}

/// v3版本的query报文
pub struct IgmpV3QueryPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IgmpV3QueryPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 12 {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        } else {
            let packet = Self::unchecked(buffer);
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IgmpV3QueryPacket<B> {
    pub fn set_igmp_type(&mut self) {
        self.buffer.as_mut()[0] = IgmpV3Type::Query.into();
    }
    pub fn set_max_resp_code(&mut self, code: u8) {
        self.buffer.as_mut()[1] = code;
    }
    pub fn set_group_address(&mut self, addr: Ipv4Addr) {
        self.buffer.as_mut()[4..8].copy_from_slice(&addr.octets())
    }
    pub fn set_checksum(&mut self, checksum: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&checksum.to_be_bytes())
    }
    pub fn set_qrv(&mut self, qrv: u8) {
        self.buffer.as_mut()[8] = (self.buffer.as_ref()[8]&(!0x07)) | (qrv & 0x07)
    }
    pub fn set_qqic(&mut self, qqic: u8) {
        self.buffer.as_mut()[9] = qqic
    }

    pub fn update_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = cal_checksum(self.buffer.as_ref());
        self.set_checksum(checksum);
    }
}

impl<B: AsRef<[u8]>> IgmpV3QueryPacket<B> {
    pub fn igmp_type(&self) -> IgmpV3Type {
        IgmpV3Type::from(self.buffer.as_ref()[0])
    }
    pub fn max_resp_code(&self) -> u8 {
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
    /// 保留字段，设置为0
    pub fn resv(&self) -> u8 {
        self.buffer.as_ref()[8] >> 4
    }
    /// 标志位
    /// 该比特位为1时，所有收到此查询报文的其他路由器不启动定时器刷新过程，但是此查询报文并不抑制查询者选举过程和路由器的主机侧处理过程；默认未置位。
    pub fn s(&self) -> u8 {
        (self.buffer.as_ref()[8] & 0x0F) >> 3
    }
    /// 查询者向网络通告的健壮系数
    /// 此参数可使查询者使用自己的健壮系统同步其他组播路由器的健壮系数；
    /// 其他路由器接收到查询报文时，如果发现该字段非0,则将自己的健壮系数调整为该字段的值;如果发现该字段为0，则不做处理。默认健壮系数值为2。
    pub fn qrv(&self) -> u8 {
        self.buffer.as_ref()[8] & 0x07
    }
    /// IGMP查询者的查询间隔
    /// 非查询者收到查询报文时，如果发现该字段非0，则将自己的查询间隔参数调整为该字段的值:如果发现该字段为0，则不做处理。默认值为60。
    pub fn qqic(&self) -> u8 {
        self.buffer.as_ref()[9]
    }
    /// 报文中包含的组播源的数量
    /// 对于普遍组查询报文和特定组查询报文，该字段为0；对于特定源组查询报文，该字段非0
    pub fn source_number(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[10..12].try_into().unwrap())
    }
    pub fn source_addresses(&self) -> Option<Vec<Ipv4Addr>> {
        let num = self.source_number();
        if num == 0 {
            None
        } else {
            let num = num as usize;
            let mut list = Vec::with_capacity(num);
            let buf = self.buffer.as_ref();
            let len = buf.len();
            for index in 0..num {
                let start = (12 + index * 4) as usize;
                let end = start + 4;
                if end > len {
                    return None;
                }
                let tmp: [u8; 4] = buf[start..end].try_into().unwrap();
                list.push(Ipv4Addr::from(tmp));
            }
            Some(list)
        }
    }
    pub fn source_address(&self, index: u16) -> Option<Ipv4Addr> {
        if self.source_number() >= index {
            None
        } else {
            let start = (12 + index * 4) as usize;
            let end = start + 4;
            let buf = self.buffer.as_ref();
            let len = buf.len();
            if end > len {
                return None;
            }
            let tmp: [u8; 4] = buf[start..end].try_into().unwrap();
            Some(Ipv4Addr::from(tmp))
        }
    }
}

/// v3版本的query报文
pub struct IgmpV3ReportPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IgmpV3ReportPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        } else {
            let packet = Self::unchecked(buffer);
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]>> IgmpV3ReportPacket<B> {
    pub fn igmp_type(&self) -> IgmpV3Type {
        IgmpV3Type::from(self.buffer.as_ref()[0])
    }
    pub fn reserved1(&self) -> u8 {
        self.buffer.as_ref()[1]
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || cal_checksum(self.buffer.as_ref()) == 0
    }
    pub fn reserved2(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap())
    }
    pub fn record_number(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap())
    }
    pub fn group_records(&self) -> Option<Vec<IgmpV3RecordPacket<&[u8]>>> {
        let num = self.record_number();
        if num == 0 {
            None
        } else {
            let num = num as usize;
            let mut list = Vec::with_capacity(num);
            let mut start = 8 as usize;
            let buf = self.buffer.as_ref();
            let len = buf.len();
            for _ in 0..num {
                if start >= len {
                    return None;
                }
                if let Ok(record) = IgmpV3RecordPacket::new(&buf[start..]) {
                    let end = start + 8 + record.aux_data_len() as usize * 4 + record.source_number() as usize * 4;
                    if end > len {
                        return None;
                    }
                    list.push(IgmpV3RecordPacket::new(&buf[start..end]).unwrap());
                    start = end;
                } else {
                    return None;
                }
            }
            Some(list)
        }
    }
}


/// group record
pub struct IgmpV3RecordPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IgmpV3RecordPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))
        } else {
            let packet = Self::unchecked(buffer);
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]>> IgmpV3RecordPacket<B> {
    pub fn record_type(&self) -> IgmpV3RecordType {
        IgmpV3RecordType::from(self.buffer.as_ref()[0])
    }
    /// 辅助数据长度 以4字节为单位
    pub fn aux_data_len(&self) -> u8 {
        self.buffer.as_ref()[1]
    }
    /// 源地址数
    pub fn source_number(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    ///多播地址
    pub fn multicast_address(&self) -> Ipv4Addr {
        let tmp: [u8; 4] = self.buffer.as_ref()[4..8].try_into().unwrap();
        Ipv4Addr::from(tmp)
    }
    pub fn source_addresses(&self) -> Option<Vec<Ipv4Addr>> {
        let num = self.source_number();
        if num == 0 {
            None
        } else {
            let num = num as usize;
            let mut list = Vec::with_capacity(num);
            let buf = self.buffer.as_ref();
            let len = buf.len();
            for index in 0..num {
                let start = (8 + index * 4) as usize;
                let end = start + 4;
                if end > len {
                    return None;
                }
                let tmp: [u8; 4] = buf[start..end].try_into().unwrap();
                list.push(Ipv4Addr::from(tmp));
            }
            Some(list)
        }
    }
    pub fn source_address(&self, index: u16) -> Option<Ipv4Addr> {
        if self.source_number() >= index {
            None
        } else {
            let start = (8 + index * 4) as usize;
            let end = start + 4;
            if end > self.buffer.as_ref().len() {
                return None;
            }
            let tmp: [u8; 4] = self.buffer.as_ref()[start..end].try_into().unwrap();
            Some(Ipv4Addr::from(tmp))
        }
    }
    /// 在文档中没有定义辅助数据的作用，通常应该是空的
    pub fn auxiliary_data(&self) -> &[u8] {
        let start = 8 + self.source_number() as usize * 4;
        let end = start + self.aux_data_len() as usize * 4;
        if end > self.buffer.as_ref().len() {
            return &[];
        }
        &self.buffer.as_ref()[start..end]
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IgmpV3QueryPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("igmp::V3Query")
            .field("type", &self.igmp_type())
            .field("max_resp_code", &self.max_resp_code())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("group_address", &self.group_address())
            .field("s", &self.s())
            .field("qrv", &self.qrv())
            .field("qqic", &self.qqic())
            .field("number of sources", &self.source_number())
            .field("source_addresses", &self.source_addresses())
            .finish()
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IgmpV3ReportPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("igmp::V3Report")
            .field("type", &self.igmp_type())
            .field("reserved1", &self.reserved1())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("reserved2", &self.reserved2())
            .field("record_number", &self.record_number())
            .field("group_records", &self.group_records())
            .finish()
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IgmpV3RecordPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("igmp::V3Record")
            .field("record_type", &self.record_type())
            .field("aux_data_len", &self.aux_data_len())
            .field("source_number", &self.source_number())
            .field("multicast_address", &self.multicast_address())
            .field("source_addresses", &self.source_addresses())
            .field("auxiliary_data", &self.auxiliary_data())
            .finish()
    }
}