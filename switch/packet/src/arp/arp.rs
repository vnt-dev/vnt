use std::{fmt, io};

/// 地址解析协议，由IP地址找到MAC地址
/// https://www.ietf.org/rfc/rfc6747.txt
/*
   0      2       4         5          6      8      10  (字节)
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | 硬件类型|协议类型|硬件地址长度|协议地址长度|操作类型|
  |          源MAC地址                  |    源ip地址    |
  |          目的MAC地址                 |   目的ip地址   |
 */

pub struct ArpPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> ArpPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() != 28 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let packet = Self::unchecked(buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> ArpPacket<B> {
    /// 硬件类型 以太网类型为1
    pub fn hardware_type(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[0..2].try_into().unwrap())
    }
    /// 上层协议类型,ipv4是0x0800
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    /// 如果是MAC地址 则长度为6
    pub fn hardware_size(&self) -> u8 {
        self.buffer.as_ref()[4]
    }
    /// 如果是IPv4 则长度为4
    pub fn protocol_size(&self) -> u8 {
        self.buffer.as_ref()[5]
    }
    /// 操作类型，请求和响应 1：ARP请求，2：ARP响应，3：RARP请求，4：RARP响应
    pub fn op_code(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap())
    }
    /// 发送端硬件地址，仅支持以太网
    pub fn sender_hardware_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[8..14]
    }
    /// 发送端协议地址，仅支持IPv4
    pub fn sender_protocol_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[14..18]
    }
    /// 接收端硬件地址，仅支持以太网
    pub fn target_hardware_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[18..24]
    }
    /// 接收端协议地址，仅支持IPv4
    pub fn target_protocol_addr(&self) -> &[u8] {
        &self.buffer.as_ref()[24..28]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> ArpPacket<B> {
    /// 硬件类型 以太网类型为1
    pub fn set_hardware_type(&mut self, value: u16) {
        self.buffer.as_mut()[0..2].copy_from_slice(&value.to_be_bytes())
    }
    /// 上层协议类型,ipv4是0x0800
    pub fn set_protocol_type(&mut self, value: u16) {
        self.buffer.as_mut()[2..4].copy_from_slice(&value.to_be_bytes())
    }
    /// 如果是MAC地址 则长度为6
    pub fn set_hardware_size(&mut self, value: u8) {
        self.buffer.as_mut()[4] = value
    }
    /// 如果是IPv4 则长度为4
    pub fn set_protocol_size(&mut self, value: u8) {
        self.buffer.as_mut()[5] = value
    }
    /// 操作类型，请求和响应 1：ARP请求，2：ARP响应，3：RARP请求，4：RARP响应
    pub fn set_op_code(&mut self, value: u16) {
        self.buffer.as_mut()[6..8].copy_from_slice(&value.to_be_bytes())
    }
    /// 发送端硬件地址，仅支持以太网
    pub fn set_sender_hardware_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[8..14].copy_from_slice(buf)
    }
    /// 发送端协议地址，仅支持IPv4
    pub fn set_sender_protocol_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[14..18].copy_from_slice(buf)
    }
    /// 接收端硬件地址，仅支持以太网
    pub fn set_target_hardware_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[18..24].copy_from_slice(buf)
    }
    /// 接收端协议地址，仅支持IPv4
    pub fn set_target_protocol_addr(&mut self, buf: &[u8]) {
        self.buffer.as_mut()[24..28].copy_from_slice(buf)
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for ArpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArpPacket")
            .field("hardware_type", &self.hardware_type())
            .field("protocol_type", &self.protocol_type())
            .field("hardware_size", &self.hardware_size())
            .field("protocol_size", &self.protocol_size())
            .field("op_code", &self.op_code())
            .field("sender_hardware_addr", &self.sender_hardware_addr())
            .field("sender_protocol_addr", &self.sender_protocol_addr())
            .field("target_hardware_addr", &self.target_hardware_addr())
            .field("target_protocol_addr", &self.target_protocol_addr())
            .finish()
    }
}