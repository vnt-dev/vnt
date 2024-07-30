use anyhow::Context;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, io, net::SocketAddr};

use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};

use crate::channel::socket::{create_tcp, LocalInterface};
use crate::ip_proxy::ProxyHandler;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::tcp::tcp::TcpPacket;

#[derive(Clone)]
pub struct TcpProxy {
    port: u16,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
}

impl TcpProxy {
    pub async fn new(default_interface: LocalInterface) -> anyhow::Result<Self> {
        let nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(16)));
        let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", 0))
            .await
            .context("TcpProxy bind failed")?;
        let port = tcp_listener.local_addr()?.port();
        {
            let nat_map = nat_map.clone();
            tokio::spawn(tcp_proxy(tcp_listener, nat_map, default_interface));
        }
        Ok(Self { port, nat_map })
    }
}

impl ProxyHandler for TcpProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        let dest_ip = ipv4.destination_ip();
        //转发到代理目标地址
        let mut tcp_packet = TcpPacket::new(source, destination, ipv4.payload_mut())?;
        let source_port = tcp_packet.source_port();
        let dest_port = tcp_packet.destination_port();
        tcp_packet.set_destination_port(self.port);
        tcp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        self.nat_map
            .lock()
            .insert(key, SocketAddrV4::new(dest_ip, dest_port));
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let tcp_packet = TcpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, tcp_packet.destination_port())
        };
        if let Some(source_addr) = self.nat_map.lock().get(&dest_addr) {
            let source_ip = *source_addr.ip();
            let mut tcp_packet = TcpPacket::new(source_ip, dest_ip, ipv4.payload_mut())?;
            tcp_packet.set_source_port(source_addr.port());
            tcp_packet.update_checksum();
            ipv4.set_source_ip(source_ip);
            ipv4.update_checksum();
        }
        Ok(())
    }
}

async fn tcp_proxy(
    tcp_listener: TcpListener,
    nat_map: Arc<Mutex<HashMap<SocketAddrV4, SocketAddrV4>>>,
    default_interface: LocalInterface,
) {
    loop {
        match tcp_listener.accept().await {
            Ok((tcp_stream, sender_addr)) => match sender_addr {
                SocketAddr::V4(sender_addr) => {
                    if let Some(dest_addr) = nat_map.lock().get(&sender_addr).cloned() {
                        let default_interface = default_interface.clone();
                        tokio::spawn(async move {
                            let peer_tcp_stream = match tcp_connect(
                                sender_addr.port(),
                                dest_addr.into(),
                                &default_interface,
                            )
                            .await
                            {
                                Ok(peer_tcp_stream) => peer_tcp_stream,
                                Err(e) => {
                                    log::warn!(
                                        "tcp代理异常:{:?},来源:{},目标：{}",
                                        e,
                                        sender_addr,
                                        dest_addr
                                    );
                                    return;
                                }
                            };
                            proxy(sender_addr, dest_addr, tcp_stream, peer_tcp_stream).await
                        });
                    } else {
                        log::warn!("tcp代理异常: 来源:{},未找到目标", sender_addr);
                    }
                }
                SocketAddr::V6(_) => {}
            },
            Err(e) => {
                log::warn!("tcp代理监听:{:?}", e);
            }
        }
    }
}
/// 优先使用来源端口建立tcp连接
async fn tcp_connect(
    src_port: u16,
    addr: SocketAddr,
    default_interface: &LocalInterface,
) -> anyhow::Result<TcpStream> {
    let socket = create_tcp(true, default_interface)?;
    if socket
        .bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, src_port).into())
        .is_err()
    {
        socket.bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    }
    let _ = socket.set_nodelay(true);
    let tcp_stream = tokio::time::timeout(Duration::from_secs(5), socket.connect(addr))
        .await
        .with_context(|| format!("TCP connection timeout {}", addr))?
        .with_context(|| format!("TCP connection target failed {}", addr))?;
    Ok(tcp_stream)
}

async fn proxy(
    sender_addr: SocketAddrV4,
    dest_addr: SocketAddrV4,
    client: TcpStream,
    server: TcpStream,
) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut client_read, &mut server_write).await {
            log::warn!("client tcp proxy {}->{},{:?}", sender_addr, dest_addr, e);
        }
    });
    if let Err(e) = tokio::io::copy(&mut server_read, &mut client_write).await {
        log::warn!("server tcp proxy {}->{},{:?}", sender_addr, dest_addr, e);
    }
}
