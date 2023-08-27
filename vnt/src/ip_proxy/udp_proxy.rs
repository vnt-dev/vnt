use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use dashmap::DashMap;
use tokio::net::UdpSocket;

/// 一个udp代理，作用是利用系统协议栈，将udp数据报解析出来再转发到目的地址
pub struct UdpProxy {
    udp_socket: Arc<UdpSocket>,
    map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
}

impl UdpProxy {
    pub fn new(udp_socket: UdpSocket, map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>) -> Self {
        let udp_socket = Arc::new(udp_socket);
        Self {
            udp_socket,
            map,
        }
    }
    pub async fn start(self) {
        let map = self.map;
        let udp_socket = self.udp_socket;
        let mut buf = [0u8; 65536];
        let inner_map: Arc<DashMap<SocketAddrV4, Arc<UdpSocket>>> = Arc::new(DashMap::new());

        loop {
            match udp_socket.recv_from(&mut buf).await {
                Ok((len, sender_addr)) => {
                    match sender_addr {
                        SocketAddr::V4(sender_addr) => {
                            match start0(&buf[..len], sender_addr, &inner_map, &map, &udp_socket).await {
                                Ok(_) => {}
                                Err(e) => {
                                    log::warn!("udp代理异常:{:?},来源:{}",e,sender_addr);
                                }
                            }
                        }
                        SocketAddr::V6(_) => {}
                    }
                }
                Err(e) => {
                    log::warn!("udp代理异常:{:?}",e);
                }
            };
        }
    }
}

async fn start0(buf: &[u8], sender_addr: SocketAddrV4, inner_map: &Arc<DashMap<SocketAddrV4, Arc<UdpSocket>>>, map: &Arc<DashMap<SocketAddrV4, SocketAddrV4>>, udp_socket: &Arc<UdpSocket>) -> io::Result<()> {
    if let Some(entry) = inner_map.get(&sender_addr) {
        let udp = entry.value().clone();
        drop(entry);
        udp.send(buf).await?;
    } else if let Some(entry) = map.get(&sender_addr) {
        let dest_addr = *entry.value();
        drop(entry);
        let peer_udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        peer_udp_socket.connect(dest_addr).await?;
        peer_udp_socket.send(buf).await?;
        let peer_udp_socket = Arc::new(peer_udp_socket);
        let inner_map = inner_map.clone();
        inner_map.insert(sender_addr, peer_udp_socket.clone());
        let udp_socket = udp_socket.clone();
        let map = map.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match tokio::time::timeout(Duration::from_secs(300), peer_udp_socket.recv(&mut buf)).await {
                    Ok(rs) => {
                        match rs {
                            Ok(len) => {
                                match udp_socket.send_to(&buf[..len], sender_addr).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        log::warn!("udp代理异常:{:?},来源:{},目标：{}",e,sender_addr,dest_addr);
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("udp代理异常:{:?},来源:{},目标：{}",e,sender_addr,dest_addr);
                                break;
                            }
                        }
                    }
                    Err(_) => {
                        //超时关闭
                        log::warn!("udp代理超时关闭,来源:{},目标：{}",sender_addr,dest_addr);
                        break;
                    }
                }
            }
            inner_map.remove(&sender_addr);
            map.remove(&sender_addr);
        });
    }
    Ok(())
}