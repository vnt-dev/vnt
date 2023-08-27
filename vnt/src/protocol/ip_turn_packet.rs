use std::io;
use std::net::Ipv4Addr;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Protocol {
    Ipv4,
    Ipv4Broadcast,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            4 => Protocol::Ipv4,
            201 => Protocol::Ipv4Broadcast,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Ipv4 => 4,
            Protocol::Ipv4Broadcast => 201,
            Protocol::Unknown(val) => val,
        }
    }
}

pub struct BroadcastPacket<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> BroadcastPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        let len = buffer.as_ref().len();
        let packet = Self::unchecked(buffer);
        if len < 2 + 4 || packet.addr_num() == 0 {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ))
        } else {
            Ok(packet)
        }
    }
}

impl<B: AsRef<[u8]>> BroadcastPacket<B> {
    pub fn addr_num(&self) -> u8 {
        self.buffer.as_ref()[1]
    }
    /// 已经发送给了这些地址
    pub fn addresses(&self) -> Vec<Ipv4Addr> {
        let num = self.addr_num() as usize;
        let mut list = Vec::with_capacity(num);
        let buf = self.buffer.as_ref();
        let mut offset = 1;
        for _ in 0..num {
            list.push(Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]));
            offset += 4;
        }
        list
    }
    pub fn data(&self) -> io::Result<&[u8]> {
        let start = 1 + self.addr_num() as usize * 4;
        if start > self.buffer.as_ref().len() {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ))
        } else {
            Ok(&self.buffer.as_ref()[start..])
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> BroadcastPacket<B> {
    pub fn set_address(&mut self, addr: &[Ipv4Addr]) -> io::Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < 1 + addr.len() * 4 || addr.len() > u8::MAX as usize {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ))
        } else {
            buf[0] = addr.len() as u8;
            let mut offset = 1;
            for ip in addr {
                buf[offset..offset + 4].copy_from_slice(&ip.octets());
                offset += 4;
            }
            Ok(())
        }
    }
    pub fn set_data(&mut self, data: &[u8]) -> io::Result<()> {
        let num = self.addr_num() as usize;
        let start = 1 + 4 * num;
        let buf = self.buffer.as_mut();
        if start > buf.len() || start + data.len() != buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "InvalidData",
            ));
        }
        buf[start..].copy_from_slice(data);
        Ok(())
    }
}




