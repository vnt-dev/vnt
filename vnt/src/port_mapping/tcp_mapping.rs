use anyhow::Context;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

pub async fn tcp_mapping(bind_addr: SocketAddr, destination: String) -> anyhow::Result<()> {
    let tcp_listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("TCP binding {:?} failed", bind_addr))?;
    tokio::spawn(async move {
        if let Err(e) = tcp_mapping_(bind_addr, tcp_listener, destination).await {
            log::warn!("tcp_mapping {:?}", e);
        }
    });
    Ok(())
}

async fn tcp_mapping_(
    bind_addr: SocketAddr,
    tcp_listener: TcpListener,
    destination: String,
) -> anyhow::Result<()> {
    loop {
        let (tcp_stream, _) = tcp_listener.accept().await?;

        let destination = destination.clone();
        tokio::spawn(async move {
            if let Err(e) = copy(tcp_stream, &destination).await {
                log::warn!("tcp port mapping {}->{} {:?}", bind_addr, destination, e);
            }
        });
    }
}

async fn copy(source_tcp: TcpStream, destination: &String) -> anyhow::Result<()> {
    // 或许这里也应该绑定最匹配的网卡，不然全局代理会影响映射
    let dest_tcp = TcpStream::connect(destination)
        .await
        .with_context(|| format!("TCP connection target failed {:?}", destination))?;
    let _ = source_tcp.set_nodelay(true);
    let _ = dest_tcp.set_nodelay(true);

    let destination = dest_tcp.peer_addr()?;
    let (mut client_read, mut client_write) = source_tcp.into_split();
    let (mut server_read, mut server_write) = dest_tcp.into_split();
    tokio::spawn(async move {
        if let Err(e) = tokio::io::copy(&mut client_read, &mut server_write).await {
            log::warn!("client tcp proxy ->{:},{:?}", destination, e);
        }
    });
    if let Err(e) = tokio::io::copy(&mut server_read, &mut client_write).await {
        log::warn!("server tcp proxy ->{:?},{:?}", destination, e);
    }
    Ok(())
}
