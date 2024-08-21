use anyhow::{anyhow, Context};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{channel, Receiver};

use crate::channel::context::ChannelContext;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::PacketSender;
use crate::channel::socket::create_tcp0;
use crate::channel::{ConnectProtocol, RouteKey, BUFFER_SIZE, TCP_MAX_PACKET_SIZE};
use crate::util::StopManager;

/// 监听tcp端口，等待客户端连接
pub fn tcp_listen<H>(
    tcp_server: std::net::TcpListener,
    receiver: Receiver<(Vec<u8>, Option<u16>, SocketAddr)>,
    recv_handler: H,
    context: ChannelContext,
    stop_manager: StopManager,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("tcpChannel".into(), move || {
        let _ = stop_sender.send(());
    })?;
    let bind_port = tcp_server.local_addr()?.port();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("tcp tokio runtime build failed")?;
    thread::Builder::new()
        .name("tcpChannel".into())
        .spawn(move || {
            runtime.spawn(async move {
                {
                    let recv_handler = recv_handler.clone();
                    let context = context.clone();
                    tokio::spawn(async move {
                        if let Err(e) = tcp_accept(tcp_server, recv_handler, context).await {
                            log::warn!("tcp_listen {:?}", e);
                        }
                    });
                }
                tokio::spawn(async move {
                    connect_tcp_handle(receiver, recv_handler, context, bind_port).await
                });
            });
            runtime.block_on(async {
                let _ = stop_receiver.await;
            });
            runtime.shutdown_background();
            worker.stop_all();
        })
        .context("tcp thread build failed")?;
    Ok(())
}

async fn connect_tcp_handle<H>(
    mut receiver: Receiver<(Vec<u8>, Option<u16>, SocketAddr)>,
    recv_handler: H,
    context: ChannelContext,
    listener_bind_port: u16,
) where
    H: RecvChannelHandler,
{
    while let Some((data, bind_port, addr)) = receiver.recv().await {
        let recv_handler = recv_handler.clone();
        let context = context.clone();
        let bind_port = if let Some(bind_port) = bind_port {
            bind_port
        } else {
            listener_bind_port
        };
        tokio::spawn(async move {
            if let Err(e) = connect_tcp0(data, addr, recv_handler, context, bind_port).await {
                log::warn!("连接失败,链接终止:{:?},{:?}", addr, e);
            }
        });
    }
}

async fn connect_tcp0<H>(
    data: Vec<u8>,
    addr: SocketAddr,
    recv_handler: H,
    context: ChannelContext,
    bind_port: u16,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let socket = if bind_port != 0 {
        match create_tcp0(addr.is_ipv4(), bind_port, context.default_interface()) {
            Ok(socket) => socket,
            Err(e) => {
                log::warn!("{:?}", e);
                create_tcp0(addr.is_ipv4(), 0, context.default_interface())?
            }
        }
    } else {
        create_tcp0(addr.is_ipv4(), 0, context.default_interface())?
    };
    let mut stream = tokio::time::timeout(Duration::from_secs(3), socket.connect(addr)).await??;
    tcp_write(&mut stream, &data).await?;

    tcp_stream_handle(stream, addr, recv_handler, context).await;
    Ok(())
}

async fn tcp_accept<H>(
    tcp_server: std::net::TcpListener,
    recv_handler: H,
    context: ChannelContext,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let tcp_server = TcpListener::from_std(tcp_server)?;

    loop {
        let (stream, addr) = tcp_server.accept().await?;

        tcp_stream_handle(stream, addr, recv_handler.clone(), context.clone()).await;
    }
}

pub async fn tcp_stream_handle<H>(
    stream: TcpStream,
    addr: SocketAddr,
    recv_handler: H,
    context: ChannelContext,
) where
    H: RecvChannelHandler,
{
    let _ = stream.set_nodelay(true);
    let local = stream.local_addr();
    #[cfg(windows)]
    let index = stream.as_raw_socket() as usize;
    #[cfg(unix)]
    let index = stream.as_raw_fd() as usize;
    let route_key = RouteKey::new(ConnectProtocol::TCP, index, addr);
    let (r, mut w) = stream.into_split();
    let (sender, mut receiver) = channel::<Vec<u8>>(100);
    context
        .packet_map
        .write()
        .insert(route_key, PacketSender::new(sender));
    tokio::spawn(async move {
        while let Some(data) = receiver.recv().await {
            if let Err(e) = tcp_write(&mut w, &data).await {
                log::info!("发送失败,tcp链接终止:{:?},{:?}", addr, e);
                break;
            }
        }
        let _ = w.shutdown().await;
    });
    tokio::spawn(async move {
        if let Err(e) = tcp_read(r, addr, &context, recv_handler, route_key).await {
            log::warn!("tcp_read {:?} {local:?}-{addr}", e)
        }
        context.packet_map.write().remove(&route_key);
    });
}

async fn tcp_write<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) -> anyhow::Result<()> {
    let len = buf.len();
    if len > TCP_MAX_PACKET_SIZE {
        return Err(anyhow!("超过了tcp的最大长度传输"));
    }
    w.write_all(&[0, (len >> 16) as u8, (len >> 8) as u8, len as u8])
        .await?;
    w.write_all(&buf).await?;
    Ok(())
}

async fn tcp_read<H>(
    mut read: OwnedReadHalf,
    addr: SocketAddr,
    context: &ChannelContext,
    recv_handler: H,
    route_key: RouteKey,
) -> anyhow::Result<()>
where
    H: RecvChannelHandler,
{
    let mut head = [0; 4];
    let mut buf = [0; BUFFER_SIZE];
    let mut extend = [0; BUFFER_SIZE];
    loop {
        read.read_exact(&mut head).await?;
        if head[0] != 0 {
            return Err(anyhow!("tcp数据流错误 {}", addr));
        }
        let len = ((head[1] as usize) << 16) | ((head[2] as usize) << 8) | head[3] as usize;
        if len < 12 || len > buf.len() {
            return Err(anyhow!("tcp数据长度无效 {}", addr));
        }
        read.read_exact(&mut buf[..len]).await?;
        recv_handler.handle(&mut buf[..len], &mut extend, route_key, context);
    }
}
