use crate::enhanced_tunnel::quic_over::quic_client::{QuicTunnelClient, send_handshake};
use crate::port_mapping::PortMapping;
use crate::protocol::client_message::{
    PortProxyHandshake, QuicProxyHandshake, quic_proxy_handshake,
};
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use pnet_packet::ip::IpNextHeaderProtocols;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// 双向转发：任一方向 EOF 时对另一端执行 shutdown 并继续转发剩余方向，
/// 直到两个方向都完成。避免 select! 下任一方向先结束就 drop 另一方向
/// 造成的半关闭截断（如对端半关闭后响应数据丢失）。
pub(crate) async fn copy_bidirectional_split<T, R, W>(
    stream: &mut T,
    reader: R,
    writer: W,
) -> anyhow::Result<(u64, u64)>
where
    T: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut other = tokio::io::join(reader, writer);
    Ok(tokio::io::copy_bidirectional(stream, &mut other).await?)
}

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
    let (mut send_stream, recv_stream) = quic_tunnel_client.open_bi(target_ip).await?;
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
    copy_bidirectional_split(&mut tcp_stream, recv_stream, send_stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 半关闭场景：客户端发完请求后 shutdown 写方向，
    /// 服务端的响应必须完整送达，不能被截断。
    #[tokio::test]
    async fn test_half_close_no_truncation() {
        let (mut client, mut relay_tcp) = tokio::io::duplex(64);
        let (relay_tunnel, mut server) = tokio::io::duplex(64);
        let (relay_tunnel_r, relay_tunnel_w) = tokio::io::split(relay_tunnel);

        let relay = tokio::spawn(async move {
            copy_bidirectional_split(&mut relay_tcp, relay_tunnel_r, relay_tunnel_w)
                .await
                .unwrap();
        });

        // 客户端发请求后立即半关闭写方向
        client.write_all(b"ping").await.unwrap();
        client.shutdown().await.unwrap();

        // 服务端读到完整请求（读到 EOF 前数据不能丢）
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // 服务端回响应并关闭
        server.write_all(b"pong").await.unwrap();
        server.shutdown().await.unwrap();

        // 客户端必须能读到完整响应（旧实现此处会被截断为空）
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"pong");

        relay.await.unwrap();
    }
}
