use crate::context::SharedNetworkAddr;
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use rust_p2p_core::socket::LocalInterface;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tcp_ip::IpStack;
use tcp_ip::tcp::TcpListener;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::ToSocketAddrs;

pub async fn start_tcp_nat(
    task_group: &TaskGroup,
    ip_stack: &IpStack,
    no_tun: bool,
    network: SharedNetworkAddr,
    default_interface: Option<LocalInterface>,
) -> anyhow::Result<()> {
    let tcp_listener = TcpListener::bind_all(ip_stack.clone()).await?;
    let group = task_group.clone();
    task_group.spawn(async move {
        if let Err(e) = listen_task(&group, tcp_listener, no_tun, network, default_interface).await
        {
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
    default_interface: Option<LocalInterface>,
) -> anyhow::Result<()> {
    loop {
        // 单次 accept/地址查询失败不能拖垮整个监听任务：
        // 记录日志后继续，短暂休眠避免持续性错误造成空转
        let (stream, _addr) = match tcp_listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                log::warn!("tcp nat accept error: {e:?}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let (mut local_addr, peer_addr) = match (stream.local_addr(), stream.peer_addr()) {
            (Ok(local_addr), Ok(peer_addr)) => (local_addr, peer_addr),
            (Err(e), _) | (_, Err(e)) => {
                log::warn!("tcp nat get addr error: {e:?}");
                continue;
            }
        };
        if no_tun {
            let IpAddr::V4(ip) = local_addr.ip() else {
                continue;
            };
            // 虚拟地址未就绪（None）时跳过重写，而不是终止任务
            if let Some(net_ip) = network.ip()
                && ip == net_ip
            {
                // 无tun的情况下写入本机的则写到localhost
                local_addr.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
        }
        let default_interface = default_interface.clone();
        task_group.spawn(async move {
            if let Err(e) = stream_task(stream, local_addr, default_interface.as_ref()).await {
                log::error!("stream task Error: {:?},{peer_addr}->{local_addr}", e);
            }
        });
    }
}

async fn stream_task(
    mut inner_stream: tcp_ip::tcp::TcpStream,
    addr: SocketAddr,
    default_interface: Option<&LocalInterface>,
) -> anyhow::Result<()> {
    let mut tokio_stream = crate::utils::socket::connect_tcp(addr, default_interface).await?;
    tokio::io::copy_bidirectional(&mut inner_stream, &mut tokio_stream).await?;
    Ok(())
}

pub(crate) async fn stream_nat<R, W, A: ToSocketAddrs + Debug>(
    recv_stream: R,
    send_stream: W,
    addr: A,
    default_interface: Option<&LocalInterface>,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut tokio_stream = crate::utils::socket::connect_tcp_resolved(addr, default_interface)
        .await
        .context("error connecting to NAT destination")?;
    crate::port_mapping::tcp_port_mapping::copy_bidirectional_split(
        &mut tokio_stream,
        recv_stream,
        send_stream,
    )
    .await?;
    Ok(())
}
