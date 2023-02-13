use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;
use tokio::net::UdpSocket;

/// 对称网络，绑定多个端口
///
///
/// 假设一方是对称网络，一方是锥形网络
/// 如果对称网络一方绑定n个端口，通过NAT对外映射出n个 公网ip:公网端口，随机尝试k次的情况下
/// 猜中的概率 p = 1-((65535-n)/65535)*((65535-n-1)/(65535-1))*...*((65535-n-k+1)/(65535-k+1))
/// n取76，k取600，猜中的概率就超过50%了
pub struct Channel {
    udp_list: Vec<Arc<UdpSocket>>,
    addr_map: SkipMap<SocketAddr, usize>,
    server_address: SocketAddr,
}

impl Channel {
    pub async fn new(server_address: SocketAddr, num: usize) -> io::Result<Self> {
        let mut udp_list = Vec::with_capacity(num);
        for _ in 0..num {
            udp_list.push(Arc::new(UdpSocket::bind("0:0").await?));
        }
        Ok(Self {
            udp_list,
            addr_map: SkipMap::new(),
            server_address,
        })
    }
}

impl Channel {
    #[inline]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut list = Vec::with_capacity(self.udp_list.len());
        for udp in &self.udp_list {
            let udp = udp.clone();
            list.push(Box::pin(async move {
                udp.readable().await
            }));
        }
        let (rs, index, _) = futures::future::select_all(list.into_iter()).await;
        let _ = rs?;
        let (len, addr) = self.udp_list[index].try_recv_from(buf)?;
        self.addr_map.insert(addr, index);
        Ok((len, addr))
    }
}

impl Channel {
    /// 向一个已经穿透成功洞地址发数据
    #[inline]
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if let Some(entry) = self.addr_map.get(&addr) {
            self.udp_list[*entry.value()].send_to(buf, addr).await
        } else {
            Err(io::Error::from(io::ErrorKind::NotConnected))
        }
    }
    /// 向所有渠道发数据，用于打洞
    #[inline]
    pub async fn send_all(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        for udp in &self.udp_list {
            udp.send_to(buf, addr).await?;
        }
        Ok(())
    }
    /// 向服务器发送数据
    #[inline]
    pub async fn send_server(&self, buf: &[u8]) -> io::Result<usize> {
        self.udp_list[0].send_to(buf, self.server_address).await
    }
}

impl Channel {
    pub fn remove_hole(&self, hole: &SocketAddr) {
        self.addr_map.remove(hole);
    }
}


