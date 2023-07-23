use std::{fmt, io};
use std::net::Ipv4Addr;


use crate::cal_checksum;
use crate::ip::ipv4::protocol::Protocol;

/// ip协议
/*
RFC:  791   https://www.ietf.org/rfc/rfc791.txt

    0                                            15                                              31
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  版本(4) | 头部长度(4) |      服务类型(8)       |                     总字节数(16)                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   标识(16)                   | 标志(3) |                片偏移(13)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     生存时间(8)       |        协议(8)         |                     头部校验和(16)              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                          源ip地址(32)                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                          目的ip地址(32)                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                           选项 + 填充                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                                               数据体
 注：头部长度单位是4字节，所以ip头最长60字节，选项最长40字节，选项填充按4字节对齐
*/

pub struct IpV4Packet<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IpV4Packet<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 20 {
            Err(io::Error::new(io::ErrorKind::InvalidData, "len < 20"))?;
        }
        if buffer.as_ref()[0] >> 4 != 4 {
            Err(io::Error::new(io::ErrorKind::InvalidData, "not ipv4"))?;
        }
        let packet = Self::unchecked(buffer);
        if packet.buffer.as_ref().len() < packet.header_len() as usize * 4 {
            Err(io::Error::new(io::ErrorKind::InvalidData, "head_len err"))?;
        }
        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> IpV4Packet<B> {
    pub fn header(&self) -> &[u8] {
        &self.buffer.as_ref()[..(self.header_len() as usize * 4)]
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[(self.header_len() as usize * 4)..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IpV4Packet<B> {
    pub fn header_mut(&mut self) -> &mut [u8] {
        let len = self.header_len() as usize * 4;
        &mut self.buffer.as_mut()[..len]
    }
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let len = self.header_len() as usize * 4;
        &mut self.buffer.as_mut()[len..]
    }
    pub fn set_protocol(&mut self, value: Protocol) {
        self.header_mut()[9] = value.into();
    }
    pub fn set_source_ip(&mut self, value: Ipv4Addr) {
        self.header_mut()[12..16].copy_from_slice(&value.octets());
    }
    pub fn set_destination_ip(&mut self, value: Ipv4Addr) {
        self.header_mut()[16..20].copy_from_slice(&value.octets());
    }
    pub fn set_flags(&mut self, flags: u8) {
        self.buffer.as_mut()[6] = (self.buffer.as_ref()[6] & 0b11100000) | (flags << 5)
    }
    fn set_checksum(&mut self, value: u16) {
        self.header_mut()[10..12].copy_from_slice(&value.to_be_bytes())
    }
    /// 更新校验和
    pub fn update_checksum(&mut self) {
        //先将校验和置0
        self.set_checksum(0);
        self.set_checksum(cal_checksum(self.header()))
    }
}

impl<B: AsRef<[u8]>> IpV4Packet<B> {
    /// 版本号，ipv4的为4
    pub fn version(&self) -> u8 {
        self.buffer.as_ref()[0] >> 4
    }

    /// 头部长度，以4字节为单位
    pub fn header_len(&self) -> u8 {
        self.buffer.as_ref()[0] & 0b1111
    }

    /// 差异化服务编码点
    ///
    /// 类别(3)+丢失概率(2)+用途(1)
    ///
    ///
    /// 类别子字段值	|  名称
    /// ---|:---
    /// 000	 | 常规(Routine)
    /// 001  | 优先(Priority)
    /// 010	 | 立即(Immediate)
    /// 011	 | 瞬间(Flash)
    /// 100	 | 瞬间覆盖(Flash Override)
    /// 101	 | 严重(CRITIC/ECP)
    /// 110	 | 网间控制(Internetwork Control)
    /// 111	 | 网络控制(Network Control)
    ///
    ///
    /// 参考：https://www.modb.pro/db/477116
    pub fn dscp(&self) -> u8 {
        self.buffer.as_ref()[1] >> 2
    }

    /// 显示拥塞  00：发送主机不支持ECN  01或者10：发送主机支持ECN 11：路由器正在经历拥塞
    pub fn ecn(&self) -> u8 {
        self.buffer.as_ref()[1] & 0b11
    }

    /// ip报总字节数
    pub fn length(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }

    /// 标识. ip报文在数据链路层可能会被拆分，同一报文的不同分组标识字段相同
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap())
    }

    /// 标志 3位.
    /// 第1位没有使用
    /// 第2位表示不分段位（DF）
    ///     0:允许数据报分段
    ///     1:数据报不能分段
    ///     置1之后路由器不能对其分段处理，如果超过MTU值则路由器不能对其转发将其丢弃，并向源点发送错误消息
    /// 第3位表示更多段位
    ///     0:数据包后面没有包，该包为最后的包
    ///     1:数据包后面有更多的包
    pub fn flags(&self) -> u8 {
        self.buffer.as_ref()[6] >> 5
    }

    /// 片偏移 13位.
    /// 以字节为单位,用于指明分段起始点相对于包头起始点的偏移量
    /// 由于分段到达时可能错序，所以分段的偏移字段可以使接收者按照正确的顺序重组数据包
    pub fn offset(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap()) & 0x1fff
    }

    /// 生存时间.
    /// 每一跳 减1 到0了则会被丢弃
    pub fn ttl(&self) -> u8 {
        self.buffer.as_ref()[8]
    }

    /// 协议.
    pub fn protocol(&self) -> Protocol {
        self.buffer.as_ref()[9].into()
    }

    /// 首部校验和
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[10..12].try_into().unwrap())
    }
    /// 验证校验和
    ///
    /// TCP/IP协议栈不会自己计算校验和，而是简单地将一个空的校验和字段(零或随机填充)交给网卡硬件。
    /// 所以抓到发出去的包校验和可能是错误的
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || cal_checksum(self.header()) == 0
    }
    /// 源ip.
    pub fn source_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[12],
            self.buffer.as_ref()[13],
            self.buffer.as_ref()[14],
            self.buffer.as_ref()[15],
        )
    }

    /// 目标ip.
    pub fn destination_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[16],
            self.buffer.as_ref()[17],
            self.buffer.as_ref()[18],
            self.buffer.as_ref()[19],
        )
    }

    /// 选项.
    pub fn options(&self) -> &[u8] {
        &self.buffer.as_ref()[20..(self.header_len() as usize * 4)]
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IpV4Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ip::v4::Packet")
            .field("version", &self.version())
            .field("header_len", &self.header_len())
            .field("dscp", &self.dscp())
            .field("ecn", &self.ecn())
            .field("length", &self.length())
            .field("id", &self.id())
            .field("flags", &self.flags())
            .field("offset", &self.offset())
            .field("ttl", &self.ttl())
            .field("protocol", &self.protocol())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("source", &self.source_ip())
            .field("destination", &self.destination_ip())
            .field("options", &self.options())
            .field("payload", &self.payload())
            .finish()
    }
}
