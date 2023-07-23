use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use crossbeam_skiplist::SkipMap;
use tokio::net::{TcpListener, TcpStream};

pub struct TcpProxy {
    tcp_listener: TcpListener,
    map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>>,
}

impl TcpProxy {
    pub fn new(tcp_listener: TcpListener, map: Arc<SkipMap<SocketAddrV4, (SocketAddrV4, SocketAddrV4)>>) -> Self {
        Self {
            tcp_listener,
            map,
        }
    }
    pub async fn start(self)  {
        let tcp_listener = self.tcp_listener;
        let map = self.map;
        loop {
            match tcp_listener.accept().await {
                Ok((tcp_stream, sender_addr)) => {
                    match sender_addr {
                        SocketAddr::V4(sender_addr) => {
                            if let Some(entry) = map.get(&sender_addr) {
                                let (src_addr, dest_addr) = *entry.value();
                                let peer_tcp_stream = match TcpStream::connect(dest_addr).await {
                                    Ok(peer_tcp_stream) => {peer_tcp_stream}
                                    Err(e) => {
                                        log::warn!("tcp代理异常:{:?},来源:{},目标：{}",e,src_addr,dest_addr);
                                        continue;
                                    }
                                };
                                let map = map.clone();
                                tokio::spawn(async move {
                                    match proxy(tcp_stream, peer_tcp_stream).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            log::warn!("tcp代理异常:{:?},来源:{},目标：{}",e,src_addr,dest_addr);
                                        }
                                    }
                                    map.remove(&sender_addr);
                                });
                            }
                        }
                        SocketAddr::V6(_) => {}
                    }

                }
                Err(e) => {
                    log::warn!("tcp代理监听:{:?}",e);
                }
            }

        }
    }
}

async fn proxy(mut client: TcpStream, mut server: TcpStream) -> io::Result<()> {
    let (mut client_reader, mut client_writer) = client.split();
    let (mut server_reader, mut server_writer) = server.split();

    let client_to_server = tokio::io::copy(&mut client_reader, &mut server_writer);
    let server_to_client = tokio::io::copy(&mut server_reader, &mut client_writer);

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}