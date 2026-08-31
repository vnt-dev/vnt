use crate::utils::task_control::{SubTask, TaskGroup};
use anyhow::Context;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use rustp2p_core::socket::LocalInterface;
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
    /// 反向转发任务，条目过期回收时需要一并终止，否则任务与 socket 永久残留
    inbound_task: SubTask,
}

type NatTable = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), NatEntry>>>;

const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(60 * 5);
const NAT_GC_INTERVAL: Duration = Duration::from_secs(60);

pub async fn start_udp_nat(
    task_group: &TaskGroup,
    ip_stack: &IpStack,
    default_interface: Option<LocalInterface>,
) -> anyhow::Result<()> {
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

            if let Err(e) = handle_outbound(
                &group,
                &inner_socket,
                &nat_table,
                src,
                dst,
                &buf[..len],
                default_interface.as_ref(),
            )
            .await
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
    default_interface: Option<&LocalInterface>,
) -> anyhow::Result<()> {
    let key = (src, dst);

    let socket = {
        let mut table = nat.lock().await;
        if let Some(entry) = table.get_mut(&key) {
            entry.last_active = Instant::now();
            entry.socket.clone()
        } else {
            // 创建真实 UDP socket
            let bind_addr = if dst.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0; 8], 0))
            };
            let interface = if dst.ip().is_loopback() {
                None
            } else {
                default_interface
            };
            let sock = crate::utils::socket::bind_udp(bind_addr, interface)?;
            sock.connect(dst).await?;
            let sock = Arc::new(sock);

            // 启动反向转发
            let inbound_task = spawn_inbound(
                task_group,
                inner.clone(),
                nat.clone(),
                src,
                dst,
                sock.clone(),
            );

            table.insert(
                key,
                NatEntry {
                    socket: sock.clone(),
                    last_active: Instant::now(),
                    inbound_task,
                },
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
) -> SubTask {
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

        // 回收 NAT：仅当表中的条目仍是本任务持有的 socket 时才删除，
        // 避免条目过期被 GC 回收并重建后，旧任务误删新条目
        let mut table = nat.lock().await;
        remove_if_current(&mut table, &(src, dst), &socket);
    })
}

/// 仅当映射中的条目仍持有同一个 socket（即仍是当前任务对应的条目）时才删除
fn remove_if_current(
    table: &mut HashMap<(SocketAddr, SocketAddr), NatEntry>,
    key: &(SocketAddr, SocketAddr),
    socket: &Arc<tokio::net::UdpSocket>,
) -> bool {
    if let Some(entry) = table.get(key)
        && Arc::ptr_eq(&entry.socket, socket)
    {
        table.remove(key);
        return true;
    }
    false
}

fn spawn_nat_gc(task_group: &TaskGroup, nat: NatTable) {
    task_group.spawn(async move {
        let mut interval = tokio::time::interval(NAT_GC_INTERVAL);

        loop {
            interval.tick().await;

            let now = Instant::now();
            let expired_tasks = {
                let mut table = nat.lock().await;
                let expired_keys: Vec<(SocketAddr, SocketAddr)> = table
                    .iter()
                    .filter(|(_, entry)| now.duration_since(entry.last_active) >= NAT_IDLE_TIMEOUT)
                    .map(|(key, _)| *key)
                    .collect();
                let mut tasks = Vec::with_capacity(expired_keys.len());
                for key in expired_keys {
                    if let Some(entry) = table.remove(&key) {
                        log::debug!("udp nat expired: {} -> {}", key.0, key.1);
                        tasks.push(entry.inbound_task);
                    }
                }
                tasks
            };

            // 终止过期条目的反向转发任务，释放其持有的 socket
            for task in expired_tasks {
                task.stop().await;
            }
        }
    });
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
    let destination = tokio::net::lookup_host(addr)
        .await?
        .next()
        .context("UDP NAT destination resolved to no address")?;
    let bind_addr = if destination.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0; 8], 0))
    };
    let interface = if destination.ip().is_loopback() {
        None
    } else {
        default_interface
    };
    let udp_socket = crate::utils::socket::bind_udp(bind_addr, interface)?;
    udp_socket.connect(destination).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::task_control::TaskGroupManager;

    async fn new_entry() -> (NatEntry, Arc<tokio::net::UdpSocket>) {
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();
        let inbound_task = group.spawn(async {});
        (
            NatEntry {
                socket: socket.clone(),
                last_active: Instant::now(),
                inbound_task,
            },
            socket,
        )
    }

    fn test_key() -> (SocketAddr, SocketAddr) {
        (
            "10.0.0.1:1000".parse().unwrap(),
            "8.8.8.8:53".parse().unwrap(),
        )
    }

    /// 误删竞态：条目过期被 GC 回收并以新 socket 重建后，
    /// 旧任务退出时不允许把新条目删掉。
    #[tokio::test]
    async fn test_remove_if_current_only_removes_same_socket() {
        let key = test_key();
        let mut table = HashMap::new();
        let (entry, socket) = new_entry().await;
        table.insert(key, entry);

        // 旧任务持有的 socket 与表中条目不同（条目已重建）：不允许删除
        let stale_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        assert!(!remove_if_current(&mut table, &key, &stale_socket));
        assert!(table.contains_key(&key));

        // 同一个 socket（条目确属本任务）：允许删除
        assert!(remove_if_current(&mut table, &key, &socket));
        assert!(!table.contains_key(&key));
    }

    /// 条目中的 inbound_task 可被正常终止（GC 回收路径依赖此能力释放任务与 socket）
    #[tokio::test]
    async fn test_entry_inbound_task_stoppable() {
        let manager = TaskGroupManager::new();
        let (group, _guard) = manager.create_task().unwrap();
        let task = group.spawn(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        assert!(task.is_running());
        task.stop().await;
        assert!(!task.is_running());
    }
}
