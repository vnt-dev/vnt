use crate::enhanced_tunnel::quic_over::quic_client::{QuicTunnelClient, send_handshake};
use crate::port_mapping::PortMapping;
use crate::protocol::client_message::{
    PortProxyHandshake, QuicProxyHandshake, quic_proxy_handshake,
};
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use pnet_packet::ip::IpNextHeaderProtocols;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::{TcpListener, TcpStream};

pub async fn start(
    task_group: &TaskGroup,
    list: &Vec<PortMapping>,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    for x in list {
        if x.protocol != IpNextHeaderProtocols::Tcp {
            continue;
        }
        log::info!("Starting TCP port mapping on {}", x);
        let listener = TcpListener::bind(x.src_addr)
            .await
            .with_context(|| format!("Tcp port mapping Failed to bind to {}", x.src_addr))?;
        let group = task_group.clone();
        let tunnel_client = quic_tunnel_client.clone();
        let mapping = x.clone();
        task_group.spawn(async move {
            if let Err(e) = listen(&group, listener, &mapping, tunnel_client).await {
                log::error!("listen {:?},mapping:{mapping}", e);
            }
        });
    }
    Ok(())
}

async fn listen(
    task_group: &TaskGroup,
    listener: TcpListener,
    mapping: &PortMapping,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let tunnel_client = quic_tunnel_client.clone();
        let target_ip = mapping.virtual_target_ip;
        let dst_host = mapping.dst_host.clone();
        let dst_port = mapping.dst_port;
        task_group.spawn(async move {
            if let Err(e) =
                stream_copy(stream, addr, target_ip, dst_host, dst_port, tunnel_client).await
            {
                log::error!("TCP TCP Stream Error: {:?}", e);
            }
        });
    }
}

async fn stream_copy(
    mut tcp_stream: TcpStream,
    src: SocketAddr,
    target_ip: Ipv4Addr,
    dst_host: String,
    dst_port: u16,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    let (mut send_stream, mut recv_stream) = quic_tunnel_client.open_bi(target_ip).await?;
    let handshake = QuicProxyHandshake {
        handshake: Some(quic_proxy_handshake::Handshake::TcpPortMapping(
            PortProxyHandshake {
                src_ip: src.ip().to_string(),
                src_port: src.port().into(),
                dst_host,
                dst_port: dst_port as _,
            },
        )),
    };
    send_handshake(&mut send_stream, handshake).await?;
    let (mut tcp_r, mut tcp_w) = tcp_stream.split();
    tokio::select! {
        _ = tokio::io::copy(&mut recv_stream, &mut tcp_w) => {},
        _ = tokio::io::copy(&mut tcp_r, &mut send_stream) => {},
    }
    Ok(())
}
