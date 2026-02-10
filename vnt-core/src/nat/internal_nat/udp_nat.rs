use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tcp_ip::IpStack;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::ToSocketAddrs;
use tokio::sync::Mutex;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

struct NatEntry {
    socket: Arc<tokio::net::UdpSocket>,
    last_active: Instant,
}

type NatTable = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), NatEntry>>>;

const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const NAT_GC_INTERVAL: Duration = Duration::from_secs(60);

pub async fn start_udp_nat(task_group: &TaskGroup, ip_stack: &IpStack) -> anyhow::Result<()> {
    let inner_socket = tcp_ip::udp::UdpSocket::bind_all(ip_stack.clone()).await?;
    let inner_socket = Arc::new(inner_socket);
    let nat_table: NatTable = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65536];
    let group = task_group.clone();
    let nat_table_clone = nat_table.clone();
    task_group.spawn(async move {
        loop {
            let (len, src, dst) = match inner_socket.recv_from_to(&mut buf).await {
                Ok(rs) => rs,
                Err(e) => {
                    log::warn!("{e:?}");
                    break;
                }
            };

            if let Err(e) =
                handle_outbound(&group, &inner_socket, &nat_table, src, dst, &buf[..len]).await
            {
                log::warn!("udp nat outbound error: {e:?}");
            }
        }
    });
    spawn_nat_gc(task_group, nat_table_clone);
    Ok(())
}

async fn handle_outbound(
    task_group: &TaskGroup,
    inner: &Arc<tcp_ip::udp::UdpSocket>,
    nat: &NatTable,
    src: SocketAddr,
    dst: SocketAddr,
    packet: &[u8],
) -> anyhow::Result<()> {
    let key = (src, dst);

    let socket = {
        let mut table = nat.lock().await;
        if let Some(entry) = table.get_mut(&key) {
            entry.last_active = Instant::now();
            entry.socket.clone()
        } else {
            // 创建真实 UDP socket
            let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            sock.connect(dst).await?;
            let sock = Arc::new(sock);
            table.insert(
                key,
                NatEntry {
                    socket: sock.clone(),
                    last_active: Instant::now(),
                },
            );

            // 启动反向转发
            spawn_inbound(
                task_group,
                inner.clone(),
                nat.clone(),
                src,
                dst,
                sock.clone(),
            );

            sock
        }
    };

    socket.send(packet).await?;
    Ok(())
}

fn spawn_inbound(
    task_group: &TaskGroup,
    inner: Arc<tcp_ip::udp::UdpSocket>,
    nat: NatTable,
    src: SocketAddr,
    dst: SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
) {
    task_group.spawn(async move {
        let mut buf = vec![0u8; 65536];

        loop {
            let len = match socket.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => break,
            };

            // 反向写回 inner socket
            if inner.send_from_to(&buf[..len], dst, src).await.is_err() {
                break;
            }

            // 更新活跃时间
            if let Some(entry) = nat.lock().await.get_mut(&(src, dst)) {
                entry.last_active = Instant::now();
            }
        }

        // 回收 NAT
        nat.lock().await.remove(&(src, dst));
    });
}

fn spawn_nat_gc(task_group: &TaskGroup, nat: NatTable) {
    task_group.spawn(async move {
        let mut interval = tokio::time::interval(NAT_GC_INTERVAL);

        loop {
            interval.tick().await;

            let now = Instant::now();
            let mut table = nat.lock().await;

            table.retain(|(src, dst), entry| {
                let alive = now.duration_since(entry.last_active) < NAT_IDLE_TIMEOUT;
                if !alive {
                    log::debug!("udp nat expired: {} -> {}", src, dst);
                }
                alive
            });
        }
    });
}

pub(crate) async fn stream_nat<R, W, A: ToSocketAddrs + Debug>(
    recv_stream: R,
    send_stream: W,
    addr: A,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    udp_socket
        .connect(&addr)
        .await
        .with_context(|| format!("error connecting to {:?}", addr))?;
    let mut framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());
    let mut framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
    let mut buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            Some(buf) = framed_read.next() => {
                let buf = buf?;
                udp_socket.send(&buf).await?;
            },
            rs = udp_socket.recv(&mut buf) =>{
                let len = rs?;
                framed_write.send(Bytes::copy_from_slice(&buf[..len])).await?;
            },
            else => {
                break
            }
        }
    }
    Ok(())
}
