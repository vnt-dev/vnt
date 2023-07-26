use std::{fmt, io};
use std::net::Ipv4Addr;

use crate::tcp::Flags;

/// tcp
/*
  https://www.rfc-editor.org/rfc/rfc793
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Source Port          |       Destination Port        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        Sequence Number                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Acknowledgment Number                      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Data |           |U|A|P|R|S|F|                               |
  | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  |       |           |G|K|H|T|N|N|                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Checksum            |         Urgent Pointer        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Options                    |    Padding    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             data                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Source Port: 16位 源端口
  Destination Port:16位 目的端口
  Sequence Number:32位 序列号，如果存在syn标志，则为初始序列号
  Acknowledgment Number:32位 如果设置了ack标志，这个表示确认收到的序号
  Data Offset:4位 数据的开始偏移位，单位是4字节
  Reserved:6位 未使用，全零
  控制位：6位 从左到右
    URG: 紧急指针 表示数据要优先处理
    ACK: 确认位
    PSH: 推送 要求把数据尽快的交给应用层，不做处理
    RST: 重置连接
    SYN: 同步序列号
    FIN: 结束发送
  Window: 16位 能接收的数据大小
  Checksum:16位 校验和，需要加入伪首部
  Urgent Pointer:16位 紧急指针
  Options+Padding:32位整数倍，最多40个字节
*/
pub struct TcpPacket<B> {
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    buffer: B,
}

impl<B: AsRef<[u8]>> TcpPacket<B> {
    pub fn unchecked(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, buffer: B) -> TcpPacket<B> {
        TcpPacket {
            source_ip,
            destination_ip,
            buffer,
        }
    }
    pub fn new(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, buffer: B) -> io::Result<TcpPacket<B>> {
        let packet = TcpPacket::unchecked(source_ip, destination_ip, buffer);

        if packet.buffer.as_ref().len() < 20 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }

        if packet.buffer.as_ref().len() < packet.data_offset() as usize * 4 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }

        Ok(packet)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> TcpPacket<B> {
    fn set_checksum(&mut self, value: u16) {
        self.buffer.as_mut()[16..18].copy_from_slice(&value.to_be_bytes())
    }
    pub fn set_source_port(&mut self, value: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&value.to_be_bytes())
    }
    pub fn set_destination_port(&mut self, value: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&value.to_be_bytes())
    }
    /// 更新校验和
    pub fn update_checksum(&mut self) {
        //先将校验和置0
        self.set_checksum(0);
        self.set_checksum(self.cal_checksum())
    }
}

impl<B: AsRef<[u8]>> TcpPacket<B> {
    /// 源端口
    pub fn source_port(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
    }

    /// 目标端口
    pub fn destination_port(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    /// 序列号
    pub fn sequence(&self) -> u32 {
        u32::from_be_bytes(self.buffer.as_ref()[4..8].try_into().unwrap())
    }
    /// 确认号
    pub fn acknowledgment(&self) -> u32 {
        u32::from_be_bytes(self.buffer.as_ref()[8..12].try_into().unwrap())
    }
    /// 数据偏移 4字节为单位
    pub fn data_offset(&self) -> u8 {
        self.buffer.as_ref()[12] >> 4
    }
    pub fn flags(&self) -> Flags {
        Flags(self.buffer.as_ref()[13])
    }
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[14..16].try_into().unwrap())
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[16..18].try_into().unwrap())
    }
    /// 验证校验和,ipv4中为0表示不使用校验和，ipv6校验和不能为0
    /// TCP/IP协议栈不会自己计算校验和，而是简单地将一个空的校验和字段(零或随机填充)交给网卡硬件。
    /// 所以抓到发出去的包校验和可能是错误的
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || self.cal_checksum() == 0
    }
    fn cal_checksum(&self) -> u16 {
        crate::ipv4_cal_checksum(
            self.buffer.as_ref(),
            &self.source_ip,
            &self.destination_ip,
            6,
        )
    }
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[18..20].try_into().unwrap())
    }
    pub fn options(&self) -> &[u8] {
        &self.buffer.as_ref()[20..(self.data_offset() as usize * 4)]
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[(self.data_offset() as usize * 4)..]
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for TcpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("tcp::Packet")
            .field("source", &self.source_port())
            .field("destination", &self.destination_port())
            .field("sequence", &self.sequence())
            .field("acknowledgment", &self.acknowledgment())
            .field("offset", &self.data_offset())
            .field("flags", &self.flags())
            .field("window", &self.window())
            .field("checksum", &self.checksum())
            .field("is_valid", &self.is_valid())
            .field("pointer", &self.urgent_pointer())
            .field("options", &self.options())
            .field("payload", &self.payload())
            .finish()
    }
}
