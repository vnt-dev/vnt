use serde::Deserialize;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use crate::command::entity::{DeviceItem, Info, RouteItem};

pub struct CommandClient {
    buf: [u8; 10240],
    udp: UdpSocket,
}

impl CommandClient {
    pub fn new() -> io::Result<Self> {
        let path_buf = crate::app_home()?.join("command-port");
        let port = if path_buf.exists() {
            let port = std::fs::read_to_string(path_buf)?;
            match u16::from_str(&port) {
                Ok(port) => port,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "'command-port' file error",
                    ));
                }
            }
        } else {
            39271
        };
        let udp = UdpSocket::bind("127.0.0.1:0")?;
        udp.set_read_timeout(Some(Duration::from_secs(5)))?;
        udp.connect(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
        )))?;
        Ok(Self {
            udp,
            buf: [0; 10240],
        })
    }
}

impl CommandClient {
    pub fn list(&mut self) -> io::Result<Vec<DeviceItem>> {
        self.send_cmd(b"list")
    }
    pub fn route(&mut self) -> io::Result<Vec<RouteItem>> {
        self.send_cmd(b"route")
    }
    pub fn info(&mut self) -> io::Result<Info> {
        self.send_cmd(b"info")
    }
    fn send_cmd<'a, V: Deserialize<'a>>(&'a mut self, cmd: &[u8]) -> io::Result<V> {
        self.udp.send(cmd)?;
        let len = self.udp.recv(&mut self.buf)?;
        match serde_yaml::from_slice::<V>(&self.buf[..len]) {
            Ok(val) => Ok(val),
            Err(e) => {
                log::error!("{:?},{:?}", &self.buf[..len], e);
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
