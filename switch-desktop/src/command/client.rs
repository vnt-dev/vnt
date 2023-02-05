use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub struct CommandClient {
    udp: UdpSocket,
}

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        let port = crate::config::read_command_port().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_read_timeout(Some(Duration::from_secs(5)))?;
        udp.connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
        )))?;
        Ok(Self { udp })
    }
}

impl CommandClient {
    pub fn list(&self) -> io::Result<String> {
        self.udp.send(b"list")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        Ok(String::from_utf8(buf[..len].to_vec()).unwrap())
    }
    pub fn status(&self) -> io::Result<String> {
        self.udp.send(b"status")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        Ok(String::from_utf8(buf[..len].to_vec()).unwrap())
    }
}
