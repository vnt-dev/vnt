use crate::ip_proxy::{DashMapNew, ProxyHandler};
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::udp::udp::UdpPacket;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

/// 一个udp代理，作用是利用系统协议栈，将udp数据报解析出来再转发到目的地址
pub struct UdpProxy {
    udp_proxy_port: u16,
    udp_socket: Arc<UdpSocket>,
    map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
}

impl UdpProxy {
    pub fn new(
        udp_socket: UdpSocket,
        map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    ) -> io::Result<Self> {
        let udp_socket = Arc::new(udp_socket);
        let udp_proxy_port = udp_socket.local_addr()?.port();
        Ok(Self {
            udp_proxy_port,
            udp_socket,
            map,
        })
    }
    pub fn udp_handler(&self) -> UdpHandler {
        UdpHandler(self.udp_proxy_port, self.map.clone())
    }
    pub async fn start(self) {
        let map = self.map;
        let udp_socket = self.udp_socket;
        let mut buf = [0u8; 65536];

        let inner_map: Arc<DashMap<SocketAddrV4, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>> =
            Arc::new(DashMap::new0());

        loop {
            match udp_socket.recv_from(&mut buf).await {
                Ok((len, sender_addr)) => match sender_addr {
                    SocketAddr::V4(sender_addr) => {
                        match start0(&buf[..len], sender_addr, &inner_map, &map, &udp_socket).await
                        {
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!("udp代理异常:{:?},来源:{}", e, sender_addr);
                            }
                        }
                    }
                    SocketAddr::V6(_) => {}
                },
                Err(e) => {
                    log::warn!("udp代理异常:{:?}", e);
                }
            };
        }
    }
}

async fn start0(
    buf: &[u8],
    sender_addr: SocketAddrV4,
    inner_map: &Arc<DashMap<SocketAddrV4, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>>,
    map: &Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    udp_socket: &Arc<UdpSocket>,
) -> io::Result<()> {
    if let Some(entry) = inner_map.get(&sender_addr) {
        entry.value().1.store(Instant::now());
        let udp = entry.value().0.clone();
        drop(entry);
        udp.send(buf).await?;
    } else if let Some(entry) = map.get(&sender_addr) {
        let dest_addr = *entry.value();
        drop(entry);
        //先使用相同的端口，冲突了再随机端口
        let peer_udp_socket = match UdpSocket::bind(format!("0.0.0.0:{}", sender_addr.port())).await
        {
            Ok(udp) => udp,
            Err(_) => UdpSocket::bind("0.0.0.0:0").await?,
        };
        peer_udp_socket.connect(dest_addr).await?;
        peer_udp_socket.send(buf).await?;
        let peer_udp_socket = Arc::new(peer_udp_socket);
        let inner_map = inner_map.clone();
        let time = Arc::new(AtomicCell::new(Instant::now()));
        inner_map.insert(sender_addr, (peer_udp_socket.clone(), time.clone()));
        let udp_socket = udp_socket.clone();
        let map = map.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match tokio::time::timeout(Duration::from_secs(600), peer_udp_socket.recv(&mut buf))
                    .await
                {
                    Ok(rs) => match rs {
                        Ok(len) => match udp_socket.send_to(&buf[..len], sender_addr).await {
                            Ok(_) => {}
                            Err(e) => {
                                log::warn!(
                                    "udp代理异常:{:?},来源:{},目标：{}",
                                    e,
                                    sender_addr,
                                    dest_addr
                                );
                                break;
                            }
                        },
                        Err(e) => {
                            log::warn!(
                                "udp代理异常:{:?},来源:{},目标：{}",
                                e,
                                sender_addr,
                                dest_addr
                            );
                            break;
                        }
                    },
                    Err(_) => {
                        if time.load().elapsed() > Duration::from_secs(580) {
                            //超时关闭
                            log::warn!("udp代理超时关闭,来源:{},目标：{}", sender_addr, dest_addr);
                            break;
                        }
                    }
                }
            }
            inner_map.remove(&sender_addr);
            map.remove(&sender_addr);
        });
    }
    Ok(())
}

#[derive(Clone)]
pub struct UdpHandler(u16, Arc<DashMap<SocketAddrV4, SocketAddrV4>>);

impl ProxyHandler for UdpHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let mut udp_packet = UdpPacket::new(source, destination, ipv4.payload_mut())?;
        let source_port = udp_packet.source_port();
        let dest_port = udp_packet.destination_port();
        udp_packet.set_destination_port(self.0);
        udp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        self.1.insert(key, SocketAddrV4::new(dest_ip, dest_port));
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, udp_packet.destination_port())
        };
        if let Some(entry) = self.1.get(&dest_addr) {
            let source_addr = entry.value();
            let source_ip = *source_addr.ip();
            let mut udp_packet = UdpPacket::new(source_ip, dest_ip, ipv4.payload_mut())?;
            udp_packet.set_source_port(source_addr.port());
            udp_packet.update_checksum();
            ipv4.set_source_ip(source_ip);
            ipv4.update_checksum();
        }
        Ok(())
    }
}
