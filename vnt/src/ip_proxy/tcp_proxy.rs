use crate::ip_proxy::ProxyHandler;
use crossbeam_utils::atomic::AtomicCell;
use dashmap::DashMap;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::tcp::tcp::TcpPacket;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

pub struct TcpProxy {
    tcp_proxy_port: u16,
    tcp_listener: TcpListener,
    //真实源地址 -> 目的地址
    tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
}

impl TcpProxy {
    pub async fn new(
        addr: SocketAddrV4,
        tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    ) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp_proxy_port: tcp_listener.local_addr()?.port(),
            tcp_listener,
            tcp_proxy_map,
        })
    }
    pub fn tcp_handler(&self) -> TcpHandler {
        TcpHandler(self.tcp_proxy_port, self.tcp_proxy_map.clone())
    }
    pub async fn start(self) {
        let tcp_listener = self.tcp_listener;
        let tcp_proxy_map = self.tcp_proxy_map;
        loop {
            match tcp_listener.accept().await {
                Ok((tcp_stream, sender_addr)) => match sender_addr {
                    SocketAddr::V4(sender_addr) => {
                        if let Some(entry) = tcp_proxy_map.get(&sender_addr) {
                            let dest_addr = *entry.value();
                            drop(entry);

                            tokio::spawn(async move {
                                let peer_tcp_stream = match tokio::time::timeout(
                                    Duration::from_secs(5),
                                    TcpStream::connect(dest_addr),
                                )
                                .await
                                {
                                    Ok(peer_tcp_stream) => match peer_tcp_stream {
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
                                    },
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
                                if let Err(e) = proxy(tcp_stream, peer_tcp_stream).await {
                                    log::warn!("{}->{},{}", sender_addr, dest_addr, e);
                                }
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
}

async fn proxy(client: TcpStream, server: TcpStream) -> io::Result<()> {
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    let time = Arc::new(AtomicCell::new(Instant::now()));
    let time1 = time.clone();
    tokio::spawn(async move {
        if let Err(e) = copy(client_read, server_write, &time1).await {
            log::warn!("{:?}", e);
        }
    });
    copy(server_read, client_write, &time).await
}

async fn copy(
    mut read: OwnedReadHalf,
    mut write: OwnedWriteHalf,
    time: &AtomicCell<Instant>,
) -> io::Result<()> {
    let mut buf = [0; 10240];
    loop {
        tokio::select! {
            result = read.read(&mut buf) =>{
                let len = result?;
                if len==0{
                    break;
                }
                write.write_all(&buf[..len]).await?;
                time.store(Instant::now());
            }
            _ = tokio::time::sleep(Duration::from_secs(600)) =>{
                if time.load().elapsed()>=Duration::from_secs(580){
                    //读写均超时再退出
                    break;
                }
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct TcpHandler(u16, Arc<DashMap<SocketAddrV4, SocketAddrV4>>);

impl ProxyHandler for TcpHandler {
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
        tcp_packet.set_destination_port(self.0);
        tcp_packet.update_checksum();
        ipv4.set_destination_ip(destination);
        ipv4.update_checksum();
        let key = SocketAddrV4::new(source, source_port);
        //https://github.com/crossbeam-rs/crossbeam/issues/1023
        self.1.insert(key, SocketAddrV4::new(dest_ip, dest_port));
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        let src_ip = ipv4.source_ip();
        let dest_ip = ipv4.destination_ip();
        let dest_addr = {
            let tcp_packet = TcpPacket::new(src_ip, dest_ip, ipv4.payload_mut())?;
            SocketAddrV4::new(dest_ip, tcp_packet.destination_port())
        };
        if let Some(entry) = self.1.get(&dest_addr) {
            let source_addr = entry.value();
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
