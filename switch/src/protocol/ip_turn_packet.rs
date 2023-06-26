use std::io;
use std::net::Ipv4Addr;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Protocol {
    Icmp,
    Igmp,
    Ipv4,
    Ipv4Broadcast,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Icmp,
            2 => Protocol::Igmp,
            4 => Protocol::Ipv4,
            201 => Protocol::Ipv4Broadcast,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Icmp => 1,
            Protocol::Igmp => 2,
            Protocol::Ipv4 => 4,
            Protocol::Ipv4Broadcast => 201,
            Protocol::Unknown(val) => val,
        }
    }
}

pub struct BroadcastPacketEnd<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> BroadcastPacketEnd<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        let len = buffer.as_ref().len();
        let packet = Self::unchecked(buffer);
        if len < 1 || packet.len() != len {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ))
        } else {
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]>> BroadcastPacketEnd<B> {
    pub fn len(&self) -> usize {
        1 + self.num() as usize * 4
    }
    pub fn num(&self) -> u8 {
        let len = self.buffer.as_ref().len();
        self.buffer.as_ref()[len - 1]
    }
    /// 已经发送给了这些地址
    /// 从尾往头拿
    pub fn addresses(&self) -> Vec<Ipv4Addr> {
        let num = self.num() as usize;
        let mut list = Vec::with_capacity(num);
        let buf = self.buffer.as_ref();
        let mut offset = buf.len() + 4 - 2;
        for _ in 0..num {
            offset -= 4;
            list.push(Ipv4Addr::new(buf[offset - 3], buf[offset - 2], buf[offset - 1], buf[offset]));
        }
        list
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> BroadcastPacketEnd<B> {
    /// 从头往尾放
    pub fn set_address(&mut self, addr: &[Ipv4Addr]) -> io::Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < 1 + addr.len() * 4 || addr.len() > u8::MAX as usize {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ))
        } else {
            let mut offset = 0;
            for ip in addr {
                buf[offset..offset + 4].copy_from_slice(&ip.octets());
                offset += 4;
            }
            self.buffer.as_mut()[offset] = addr.len() as u8;
            Ok(())
        }
    }
}




