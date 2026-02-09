use crate::nat::internal_nat::{InternalNatInbound, PortMappingManager};
use crate::protocol::client_message::QuicProxyHandshake;
use crate::protocol::client_message::quic_proxy_handshake::Handshake;
use crate::utils::task_control::TaskGroup;
use anyhow::{Context, bail};
use futures::StreamExt;
use pnet_packet::ip::IpNextHeaderProtocol;
use prost::Message;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tcp_ip::IpStack;
use tcp_ip::ip::IpSocket;
use tokio::io::AsyncReadExt;
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};

pub async fn server_listen(
    task_group: &TaskGroup,
    endpoint: Endpoint,
    ip_socket: Option<Arc<IpSocket>>,
    ip_stack: Option<IpStack>,
    internal_nat_manager: Option<InternalNatInbound>,
    port_mapping_manager: PortMappingManager,
) {
    task_group.spawn(quic_endpoint_accept(
        ip_stack,
        task_group.clone(),
        endpoint,
        ip_socket,
        internal_nat_manager,
        port_mapping_manager,
    ));
}

async fn quic_endpoint_accept(
    ip_stack: Option<IpStack>,
    task_group: TaskGroup,
    endpoint: Endpoint,
    ip_socket: Option<Arc<IpSocket>>,
    internal_nat_manager: Option<InternalNatInbound>,
    port_mapping_manager: PortMappingManager,
) {
    while let Some(connecting) = endpoint.accept().await {
        let remote_addr = connecting.remote_address();
        let task_group_clone = task_group.clone();
        let ip_socket = ip_socket.clone();
        let ip_stack = ip_stack.clone();
        let internal_nat_manager = internal_nat_manager.clone();
        let port_mapping_manager = port_mapping_manager.clone();
        task_group.spawn(async move {
            match connecting.await {
                Ok(connection) => {
                    log::info!("QUIC connection: {}", remote_addr);
                    if let Err(e) = quic_accept(
                        ip_stack,
                        task_group_clone,
                        connection,
                        ip_socket,
                        internal_nat_manager,
                        port_mapping_manager,
                    )
                    .await
                    {
                        log::info!("quic close: {remote_addr},{e:?}",);
                    }
                }
                Err(e) => {
                    log::error!("connect: {:?},remote_addr={remote_addr}", e);
                }
            }
        });
    }
    log::warn!("quic server closed");
}

async fn quic_accept(
    ip_stack: Option<IpStack>,
    task_group_clone: TaskGroup,
    connection: Connection,
    ip_socket: Option<Arc<IpSocket>>,
    internal_nat_manager: Option<InternalNatInbound>,
    port_mapping_manager: PortMappingManager,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            rs = connection.accept_bi()=>{
                let (send_stream, recv_stream) = rs?;
                let ip_stack = ip_stack.clone();
                let internal_nat_manager = internal_nat_manager.clone();
                let port_mapping_manager = port_mapping_manager.clone();
                task_group_clone.spawn(async move {
                    if let Err(e) = quic_stream_bi_handle(ip_stack,send_stream, recv_stream,&internal_nat_manager,port_mapping_manager).await{
                        log::error!("quic_stream_bi_handle: {e:?}");
                    }
                });
            }
            rs = connection.accept_uni()=>{
                let recv_stream = rs?;
                let ip_socket = ip_socket.clone();
                let internal_nat_manager = internal_nat_manager.clone();
                task_group_clone.spawn(async move {
                    if let Err(e) = quic_stream_uni_handle(recv_stream, ip_socket,&internal_nat_manager).await{
                        log::error!("quic_stream_uni_handle: {e:?}");
                    }
                });
            }
        }
    }
}

async fn quic_stream_bi_handle(
    ip_stack: Option<IpStack>,
    mut send_stream: SendStream,
    mut recv_stream: RecvStream,
    internal_nat_manager: &Option<InternalNatInbound>,
    port_mapping_manager: PortMappingManager,
) -> anyhow::Result<()> {
    let handshake = recv_handshake(&mut recv_stream).await?;
    let Some(handshake) = handshake.handshake else {
        return Ok(());
    };
    match handshake {
        Handshake::Tcp(handshake) => {
            let src = SocketAddr::new(
                Ipv4Addr::from(handshake.src_ip).into(),
                handshake.src_port as _,
            );
            let dst_ip = Ipv4Addr::from(handshake.dst_ip);
            let dst = SocketAddr::new(dst_ip.into(), handshake.dst_port as _);
            if src == dst {
                bail!("tcp handshake failed, ip: {}", src);
            }
            log::debug!("accept TCP stream {src}->{dst}");
            // 如果不是网段内的，并且启用了内置nat，则直接转发
            if let Some(internal_nat_manager) = internal_nat_manager {
                if internal_nat_manager.use_nat(&dst_ip) {
                    internal_nat_manager
                        .tcp_nat(recv_stream, send_stream, dst_ip, dst.port())
                        .await?;
                    return Ok(());
                }
                if internal_nat_manager.no_tun() {
                    return Ok(());
                }
            }
            if let Some(ip_stack) = ip_stack {
                let stream = tcp_ip::tcp::TcpStream::bind(ip_stack, src)?
                    .connect_to(dst)
                    .await?;
                let (mut tcp_w, mut tcp_r) = stream.split()?;
                tokio::select! {
                    _ = tokio::io::copy(&mut recv_stream, &mut tcp_w) => {},
                    _ = tokio::io::copy(&mut tcp_r, &mut send_stream) => {},
                }
                log::debug!("accept close TCP stream {src}->{dst}");
            }
        }
        Handshake::Ip(_) => {}
        Handshake::TcpPortMapping(handshake) => {
            port_mapping_manager
                .tcp_mapping(
                    recv_stream,
                    send_stream,
                    handshake.dst_host,
                    handshake.dst_port as _,
                )
                .await?;
        }
        Handshake::UdpPortMapping(handshake) => {
            port_mapping_manager
                .udp_mapping(
                    recv_stream,
                    send_stream,
                    handshake.dst_host,
                    handshake.dst_port as _,
                )
                .await?;
        }
    }
    Ok(())
}

async fn recv_handshake(recv_stream: &mut RecvStream) -> anyhow::Result<QuicProxyHandshake> {
    let len = recv_stream.read_u16().await?;
    let mut buf = vec![0u8; len as usize];
    recv_stream.read_exact(&mut buf).await?;
    let handshake = QuicProxyHandshake::decode(&buf[..])?;
    Ok(handshake)
}
async fn quic_stream_uni_handle(
    mut recv_stream: RecvStream,
    ip_socket: Option<Arc<IpSocket>>,
    internal_nat_manager: &Option<InternalNatInbound>,
) -> anyhow::Result<()> {
    let handshake = recv_handshake(&mut recv_stream).await?;
    let Some(handshake) = handshake.handshake else {
        return Ok(());
    };
    match handshake {
        Handshake::Tcp(_) => {}
        Handshake::Ip(handshake) => {
            let ip_next_header_protocol =
                IpNextHeaderProtocol::new(handshake.ip_next_header_protocol as _);
            let src_ip = Ipv4Addr::from(handshake.src_ip);
            let dest_ip = Ipv4Addr::from(handshake.dst_ip);
            log::debug!("recv IP({ip_next_header_protocol}) packet {src_ip}->{dest_ip}");
            let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());
            // 如果不是网段内的，并且启用了内置nat，则直接转发
            if let Some(internal_nat_manager) = internal_nat_manager {
                if internal_nat_manager.use_nat(&dest_ip) {
                    loop {
                        let buf = framed_read
                            .next()
                            .await
                            .context("receive quic stream failed")??;
                        internal_nat_manager
                            .send_ipv4_payload(ip_next_header_protocol, src_ip, dest_ip, buf)
                            .await?;
                    }
                }
                if internal_nat_manager.no_tun() {
                    return Ok(());
                }
            }
            let Some(ip_socket) = ip_socket else {
                return Ok(());
            };
            let src_ip = src_ip.into();
            let dest_ip = dest_ip.into();
            loop {
                let buf = framed_read
                    .next()
                    .await
                    .context("receive quic stream failed")??;

                ip_socket
                    .send_protocol_from_to(&buf, ip_next_header_protocol, src_ip, dest_ip)
                    .await?;
            }
        }
        Handshake::TcpPortMapping(_) => {}
        Handshake::UdpPortMapping(_) => {}
    }
    Ok(())
}
