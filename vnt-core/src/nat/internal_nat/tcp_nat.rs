use crate::context::SharedNetworkAddr;
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tcp_ip::IpStack;
use tcp_ip::tcp::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, ToSocketAddrs};

pub async fn start_tcp_nat(
    task_group: &TaskGroup,
    ip_stack: &IpStack,
    no_tun: bool,
    network: SharedNetworkAddr,
) -> anyhow::Result<()> {
    let tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;
    let group = task_group.clone();
    task_group.spawn(async move {
        if let Err(e) = listen_task(&group, tcp_listener, no_tun, network).await {
            log::error!("listen task error: {:?}", e);
        }
    });
    Ok(())
}

async fn listen_task(
    task_group: &TaskGroup,
    mut tcp_listener: TcpListener,
    no_tun: bool,
    network: SharedNetworkAddr,
) -> anyhow::Result<()> {
    loop {
        let (stream, _addr) = tcp_listener.accept().await?;
        let mut local_addr = stream.local_addr()?;
        let peer_addr = stream.peer_addr()?;
        if no_tun {
            let IpAddr::V4(ip) = local_addr.ip() else {
                continue;
            };
            if ip == network.ip().context("not ip")? {
                // 无tun的情况下写入本机的则写到localhost
                local_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
        }
        task_group.spawn(async move {
            if let Err(e) = stream_task(stream, local_addr).await {
                log::error!("stream task Error: {:?},{peer_addr}->{local_addr}", e);
            }
        });
    }
}

async fn stream_task(
    mut inner_stream: tcp_ip::tcp::TcpStream,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut tokio_stream = TcpStream::connect(addr).await?;
    tokio::io::copy_bidirectional(&mut inner_stream, &mut tokio_stream).await?;
    Ok(())
}

pub(crate) async fn stream_nat<R, W, A: ToSocketAddrs + Debug>(
    mut recv_stream: R,
    mut send_stream: W,
    addr: A,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tokio_stream = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("error connecting to {:?}", addr))?;
    let (mut tcp_r, mut tcp_w) = tokio_stream.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv_stream, &mut tcp_w) => {},
        _ = tokio::io::copy(&mut tcp_r, &mut send_stream) => {},
    }
    Ok(())
}
