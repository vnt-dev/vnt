use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::command::entity::{DeviceItem, RouteItem, Status};

pub struct CommandClient {
    udp: UdpSocket,
}

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        let port = crate::config::read_command_port()?;
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_read_timeout(Some(Duration::from_secs(2)))?;
        udp.connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
        )))?;
        Ok(Self { udp })
    }
}

impl CommandClient {
    pub fn list(&self) -> io::Result<Vec<DeviceItem>> {
        self.udp.send(b"list")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        match serde_json::from_slice::<Vec<DeviceItem>>(&buf[..len]) {
            Ok(val) => {
                Ok(val)
            }
            Err(e) => {
                log::error!("{:?}",e);
                Err(io::Error::new(io::ErrorKind::Other, "data error"))
            }
        }
    }
    pub fn route(&self) -> io::Result<Vec<RouteItem>> {
        self.udp.send(b"route")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        match serde_json::from_slice::<Vec<RouteItem>>(&buf[..len]) {
            Ok(val) => {
                Ok(val)
            }
            Err(e) => {
                log::error!("{:?}",e);
                Err(io::Error::new(io::ErrorKind::Other, "data error"))
            }
        }
    }
    pub fn status(&self) -> io::Result<Status> {
        self.udp.send(b"status")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        match serde_json::from_slice::<Status>(&buf[..len]) {
            Ok(val) => {
                Ok(val)
            }
            Err(e) => {
                log::error!("{:?},{:?}",&buf[..len],e);
                Err(io::Error::new(io::ErrorKind::Other, "data error"))
            }
        }
    }
    #[cfg(any(unix))]
    pub fn stop(&self) -> io::Result<String> {
        self.udp.send(b"stop")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        Ok(String::from_utf8(buf[..len].to_vec()).unwrap())
    }
}
