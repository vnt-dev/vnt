use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use crate::command::entity::{DeviceItem, RouteItem, Info};

pub struct CommandClient {
    udp: UdpSocket,
}

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        let path_buf = crate::app_home()?.join("command-port");
        if !path_buf.exists() {
            return Err(io::Error::new(io::ErrorKind::Other, "not started"));
        }
        let port = std::fs::read_to_string(path_buf)?;
        let port = match u16::from_str(&port) {
            Ok(port) => { port }
            Err(_) => {
                return Err(io::Error::new(io::ErrorKind::Other, "'command-port' file error"));
            }
        };
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
    pub fn info(&self) -> io::Result<Info> {
        self.udp.send(b"info")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        match serde_json::from_slice::<Info>(&buf[..len]) {
            Ok(val) => {
                Ok(val)
            }
            Err(e) => {
                log::error!("{:?},{:?}",&buf[..len],e);
                Err(io::Error::new(io::ErrorKind::Other, "data error"))
            }
        }
    }
    pub fn stop(&self) -> io::Result<String> {
        self.udp.send(b"stop")?;
        let mut buf = [0; 10240];
        let len = self.udp.recv(&mut buf)?;
        Ok(String::from_utf8(buf[..len].to_vec()).unwrap())
    }
}
