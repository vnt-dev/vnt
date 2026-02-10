use crate::enhanced_tunnel::quic_over::quic_client::{QuicTunnelClient, send_handshake};
use crate::port_mapping::PortMapping;
use crate::protocol::client_message::{
    PortProxyHandshake, QuicProxyHandshake, quic_proxy_handshake,
};
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use pnet_packet::ip::IpNextHeaderProtocols;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub async fn start(
    task_group: &TaskGroup,
    list: &Vec<PortMapping>,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    for x in list {
        if x.protocol != IpNextHeaderProtocols::Udp {
            continue;
        }
        log::info!("Starting UDP port mapping on {}", x);
        let udp = UdpSocket::bind(x.src_addr)
            .await
            .with_context(|| format!("Udp port mapping Failed to bind to {}", x.src_addr))?;
        let udp_socket = Arc::new(udp);
        let group = task_group.clone();
        let tunnel_client = quic_tunnel_client.clone();
        let mapping = x.clone();
        task_group.spawn(async move {
            if let Err(e) = recv(&group, udp_socket, &mapping, tunnel_client).await {
                log::error!("recv {:?},mapping:{mapping}", e);
            }
        });
    }
    Ok(())
}

async fn recv(
    task_group: &TaskGroup,
    udp_socket: Arc<UdpSocket>,
    mapping: &PortMapping,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65536];
    let dest_map = Arc::new(Mutex::new(HashMap::<SocketAddr, Sender<Bytes>>::new()));
    loop {
        let (len, src) = udp_socket.recv_from(&mut buf).await?;
        let bytes = Bytes::copy_from_slice(&buf[..len]);

        let tx = {
            let mut map = dest_map.lock();
            if let Some(tx) = map.get(&src) {
                tx.clone()
            } else {
                let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(128);
                let udp_socket = udp_socket.clone();
                let virtual_target_ip = mapping.virtual_target_ip;
                let dst_host = mapping.dst_host.clone();
                let dst_port = mapping.dst_port;
                let tunnel_client = quic_tunnel_client.clone();
                task_group.spawn(async move {
                    if let Err(e) = udp_mapping_handle(
                        udp_socket,
                        src,
                        virtual_target_ip,
                        dst_host,
                        dst_port,
                        rx,
                        tunnel_client,
                    )
                    .await
                    {
                        log::error!("udp_mapping_handle {e:?},src:{src}");
                    }
                });

                map.insert(src, tx.clone());
                tx
            }
        };

        if let Err(err) = tx.try_send(bytes) {
            match err {
                TrySendError::Full(_) => {}
                TrySendError::Closed(_) => {
                    let mut map = dest_map.lock();
                    map.remove(&src);
                }
            }
        }
    }
}

async fn udp_mapping_handle(
    udp_socket: Arc<UdpSocket>,
    src: SocketAddr,
    target_ip: Ipv4Addr,
    dst_host: String,
    dst_port: u16,
    mut rx: tokio::sync::mpsc::Receiver<Bytes>,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    let (mut send_stream, recv_stream) = quic_tunnel_client.open_bi(target_ip).await?;

    let handshake = QuicProxyHandshake {
        handshake: Some(quic_proxy_handshake::Handshake::UdpPortMapping(
            PortProxyHandshake {
                src_ip: src.ip().to_string(),
                src_port: src.port().into(),
                dst_host,
                dst_port: dst_port as _,
            },
        )),
    };
    send_handshake(&mut send_stream, handshake).await?;
    let mut framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
    let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());
    loop {
        tokio::select! {
            Some(buf) = framed_read.next()=>{
                let buf = buf?;
                udp_socket.send_to(&buf, src).await?;
            },
            Some(buf) = rx.recv()=>{
                framed_write.send(buf).await?
            },
            _ = tokio::time::sleep(Duration::from_secs(60)) =>{
              break;
            },
            else => {
                break;
            }
        }
    }
    Ok(())
}
