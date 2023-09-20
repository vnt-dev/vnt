use dashmap::DashMap;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};

pub struct TcpProxy {
    tcp_listener: TcpListener,
    tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
}

impl TcpProxy {
    pub fn new(
        tcp_listener: TcpListener,
        tcp_proxy_map: Arc<DashMap<SocketAddrV4, SocketAddrV4>>,
    ) -> Self {
        Self {
            tcp_listener,
            tcp_proxy_map,
        }
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
    tokio::spawn(async move {
        if let Err(e) = copy(client_read, server_write).await {
            log::warn!("{:?}", e);
        }
    });
    copy(server_read, client_write).await
}

async fn copy(mut read: OwnedReadHalf, mut write: OwnedWriteHalf) -> io::Result<()> {
    let mut buf = [0; 10240];
    loop {
        tokio::select! {
            result = read.read(&mut buf) =>{
                let len = result?;
                if len==0{
                    break;
                }
                write.write_all(&buf[..len]).await?;
            }
            _ = tokio::time::sleep(Duration::from_secs(300)) =>{
                break;
            }
        }
    }
    Ok(())
}
