use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// 锥形网络，使用一个端口
pub struct Channel {
    udp: UdpSocket,
    server_address: SocketAddr,
}

impl Channel {
    pub async fn new(server_address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            udp: UdpSocket::bind("0:0").await?,
            server_address,
        })
    }
}

impl Channel {
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.udp.recv_from(buf).await
    }
}

impl Channel {
    #[inline]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.udp.send_to(buf, addr).await
    }
    #[inline]
    pub async fn send_server(&self, buf: &[u8]) -> io::Result<usize> {
        self.udp.send_to(buf, self.server_address).await
    }
}


