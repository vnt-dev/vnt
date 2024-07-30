use anyhow::Context;
use crossbeam_utils::atomic::AtomicCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{collections::HashMap, io, net::SocketAddr};

use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::channel::socket::{bind_udp, LocalInterface};
use crate::ip_proxy::ProxyHandler;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::udp::udp::UdpPacket;

#[derive(Clone)]
pub struct UdpProxy {
    port: u16,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
}

impl UdpProxy {
    pub async fn new(default_interface: LocalInterface) -> anyhow::Result<Self> {
        let nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let udp = UdpSocket::bind(format!("0.0.0.0:{}", 0))
            .await
            .context("UdpProxy bind failed")?;
        let port = udp.local_addr()?.port();
        {
            let nat_map = nat_map.clone();
            tokio::spawn(async move {
                if let Err(e) = udp_proxy(udp, nat_map, default_interface).await {
                    log::warn!("udp_proxy:{:?}", e);
                }
            });
        }
        Ok(Self { port, nat_map })
    }
}

impl ProxyHandler for UdpProxy {
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
        udp_packet.set_destination_port(self.port);
        udp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        self.nat_map
            .lock()
            .insert(key.into(), SocketAddrV4::new(dest_ip, dest_port).into());
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let udp_packet = UdpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, udp_packet.destination_port())
        };
        if let Some(source_addr) = self.nat_map.lock().get(&dest_addr) {
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

async fn udp_proxy(
    udp: UdpSocket,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
    default_interface: LocalInterface,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 65536];

    let inner_map: Arc<Mutex<HashMap<SocketAddrV4, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>>> =
        Arc::new(Mutex::new(HashMap::with_capacity(64)));
    let udp_socket = Arc::new(udp);
    loop {
        match udp_socket.recv_from(&mut buf).await {
            Ok((len, sender_addr)) => match sender_addr {
                SocketAddr::V4(sender_addr) => {
                    if let Err(e) = udp_proxy0(
                        &buf[..len],
                        sender_addr,
                        &inner_map,
                        &nat_map,
                        &udp_socket,
                        &default_interface,
                    )
                    .await
                    {
                        log::warn!("udp proxy {} {:?}", sender_addr, e);
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

async fn udp_proxy0(
    buf: &[u8],
    sender_addr: SocketAddrV4,
    inner_map: &Arc<Mutex<HashMap<SocketAddrV4, (Arc<UdpSocket>, Arc<AtomicCell<Instant>>)>>>,
    map: &Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
    udp_socket: &Arc<UdpSocket>,
    default_interface: &LocalInterface,
) -> anyhow::Result<()> {
    let option = inner_map.lock().get(&sender_addr).cloned();
    if let Some((udp, time)) = option {
        time.store(Instant::now());
        udp.send(buf).await?;
    } else {
        let option = map.lock().get(&sender_addr).cloned();
        if let Some(dest_addr) = option {
            //先使用相同的端口，冲突了再随机端口
            let peer_udp_socket = match bind_udp(
                format!("0.0.0.0:{}", sender_addr.port()).parse().unwrap(),
                default_interface,
            ) {
                Ok(udp) => udp,
                Err(_) => bind_udp("0.0.0.0:0".parse().unwrap(), default_interface)?,
            };
            let peer_udp_socket = UdpSocket::from_std(peer_udp_socket.into())?;
            peer_udp_socket.connect(dest_addr).await?;
            peer_udp_socket.send(buf).await?;
            let peer_udp_socket = Arc::new(peer_udp_socket);
            let inner_map = inner_map.clone();
            let time = Arc::new(AtomicCell::new(Instant::now()));
            inner_map
                .lock()
                .insert(sender_addr, (peer_udp_socket.clone(), time.clone()));
            let udp_socket = udp_socket.clone();
            let map = map.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 65536];
                loop {
                    match tokio::time::timeout(
                        Duration::from_secs(600),
                        peer_udp_socket.recv(&mut buf),
                    )
                    .await
                    {
                        Ok(rs) => match rs {
                            Ok(len) => match udp_socket.send_to(&buf[..len], sender_addr).await {
                                Ok(_) => {}
                                Err(e) => {
                                    log::warn!("udp proxy {}->{} {:?}", sender_addr, dest_addr, e);
                                    break;
                                }
                            },
                            Err(e) => {
                                log::warn!("udp proxy {}->{} {:?}", sender_addr, dest_addr, e);

                                break;
                            }
                        },
                        Err(_) => {
                            if time.load().elapsed() > Duration::from_secs(580) {
                                //超时关闭
                                log::warn!("udp proxy timeout {}->{}", sender_addr, dest_addr);
                                break;
                            }
                        }
                    }
                }
                inner_map.lock().remove(&sender_addr);
                map.lock().remove(&sender_addr);
            });
        }
    }
    Ok(())
}
