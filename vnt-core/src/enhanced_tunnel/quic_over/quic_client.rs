use crate::context::AppState;

use crate::nat::SubnetExternalRoute;
use crate::protocol::client_message::{
    IpProxyHandshake, QuicProxyHandshake, TcpProxyHandshake, quic_proxy_handshake,
};
use crate::utils::task_control::TaskGroup;
use anyhow::{Context, bail};
use bytes::Bytes;
use futures::SinkExt;
use parking_lot::Mutex;
use pnet_packet::ip::IpNextHeaderProtocol;
use prost::Message;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tcp_ip::IpStack;
use tcp_ip::ip::IpSocket;
use tcp_ip::tcp::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::sync::OnceCell;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::{FramedWrite, LengthDelimitedCodec};

#[derive(Clone)]
pub struct QuicTunnelClient {
    app_state: AppState,
    endpoint: Endpoint,
    connection_map: Arc<Mutex<HashMap<Ipv4Addr, Arc<OnceCell<Connection>>>>>,
    external_route: SubnetExternalRoute,
}

impl QuicTunnelClient {
    pub fn new(
        app_state: AppState,
        endpoint: Endpoint,
        external_route: SubnetExternalRoute,
    ) -> QuicTunnelClient {
        Self {
            app_state,
            endpoint,
            connection_map: Arc::new(Default::default()),
            external_route,
        }
    }

    pub async fn open_bi(&self, mut dest: Ipv4Addr) -> anyhow::Result<(SendStream, RecvStream)> {
        let Some(net) = self.app_state.get_network() else {
            bail!("no network found");
        };
        if !net.network().contains(&dest) {
            if let Some(v) = self.external_route.route(&dest) {
                dest = v;
            } else {
                bail!("invalid route found:{dest}");
            }
        }
        let mut count = 0;
        loop {
            count += 1;
            let cell = self
                .connection_map
                .lock()
                .entry(dest)
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone();
            let connection = cell
                .get_or_try_init(|| async {
                    self.endpoint
                        .connect(SocketAddr::new(dest.into(), 10000), "localhost")?
                        .await
                        .context("connect failed")
                })
                .await?;

            return match connection.open_bi().await {
                Ok(rs) => Ok(rs),
                Err(e) => {
                    self.connection_map.lock().remove(&dest);
                    if count == 1 {
                        continue;
                    }
                    Err(e.into())
                }
            };
        }
    }
    pub async fn open_uni(&self, mut dest: Ipv4Addr) -> anyhow::Result<SendStream> {
        let Some(net) = self.app_state.get_network() else {
            bail!("no network found");
        };
        if !net.network().contains(&dest) {
            if let Some(v) = self.external_route.route(&dest) {
                dest = v;
            } else {
                bail!("invalid route found:{dest}");
            }
        }
        let mut count = 0;
        loop {
            count += 1;
            let cell = self
                .connection_map
                .lock()
                .entry(dest)
                .or_insert_with(|| Arc::new(OnceCell::new()))
                .clone();
            let connection = cell
                .get_or_try_init(|| async {
                    self.endpoint
                        .connect(SocketAddr::new(dest.into(), 10000), "localhost")?
                        .await
                        .context("connect failed")
                })
                .await?;
            return match connection.open_uni().await {
                Ok(rs) => Ok(rs),
                Err(e) => {
                    self.connection_map.lock().remove(&dest);
                    if count == 1 {
                        continue;
                    }
                    Err(e.into())
                }
            };
        }
    }
}
pub(crate) async fn send_handshake(
    send_stream: &mut SendStream,
    handshake: QuicProxyHandshake,
) -> anyhow::Result<()> {
    let handshake = handshake.encode_to_vec();
    send_stream.write_u16(handshake.len() as u16).await?;
    send_stream.write_all(&handshake).await?;
    Ok(())
}

pub async fn create_client(
    quic_client: QuicTunnelClient,
    task_group: TaskGroup,
    ip_stack: IpStack,
    ip_socket: Arc<IpSocket>,
) {
    task_group.spawn(tcp_listen(
        task_group.clone(),
        ip_stack.clone(),
        quic_client.clone(),
    ));
    task_group.spawn(ip_listen(task_group.clone(), ip_socket, quic_client));
}

async fn tcp_listen(
    task_group: TaskGroup,
    ip_stack: IpStack,
    quic_tunnel_client: QuicTunnelClient,
) {
    if let Err(e) = tcp_listen_impl(task_group, ip_stack, quic_tunnel_client).await {
        log::error!("tcp_listen {e:?}");
    }
}

async fn tcp_listen_impl(
    task_group: TaskGroup,
    ip_stack: IpStack,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    let mut listener = tcp_ip::tcp::TcpListener::bind_all(ip_stack).await?;
    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        let quic_tunnel_client = quic_tunnel_client.clone();
        task_group.spawn(async move {
            if let Err(e) = tcp_stream_handle(tcp_stream, quic_tunnel_client).await {
                log::error!("TCP stream handle failed with error: {e:?},addr={addr}");
            }
        });
    }
}

async fn tcp_stream_handle(
    tcp_stream: TcpStream,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    // 连接方向是反过来的，因为自己充当目标做了tcp卸载
    let SocketAddr::V4(peer_addr) = tcp_stream.local_addr()? else {
        bail!("invalid IP address");
    };
    let SocketAddr::V4(local_addr) = tcp_stream.peer_addr()? else {
        bail!("invalid IP address");
    };
    log::debug!("connect TCP stream {}->{}", local_addr, peer_addr);

    let (mut send_stream, mut recv_stream) = quic_tunnel_client.open_bi(*peer_addr.ip()).await?;
    let handshake = QuicProxyHandshake {
        handshake: Some(quic_proxy_handshake::Handshake::Tcp(TcpProxyHandshake {
            src_ip: (*local_addr.ip()).into(),
            src_port: local_addr.port().into(),
            dst_ip: (*peer_addr.ip()).into(),
            dst_port: peer_addr.port().into(),
        })),
    };
    send_handshake(&mut send_stream, handshake).await?;
    let (mut tcp_w, mut tcp_r) = tcp_stream.split()?;
    tokio::select! {
        _ = tokio::io::copy(&mut recv_stream, &mut tcp_w) => {},
        _ = tokio::io::copy(&mut tcp_r, &mut send_stream) => {},
    }
    log::debug!("disconnect TCP stream {}->{}", local_addr, peer_addr);
    Ok(())
}

async fn ip_listen(
    task_group: TaskGroup,
    ip_socket: Arc<IpSocket>,
    quic_tunnel_client: QuicTunnelClient,
) {
    if let Err(e) = ip_listen_impl(task_group, ip_socket, quic_tunnel_client).await {
        log::error!("ip_listen {e:?}");
    }
}
#[derive(Eq, PartialEq, Hash, Copy, Clone, Debug)]
struct IpKey {
    protocol: IpNextHeaderProtocol,
    src: Ipv4Addr,
    dest: Ipv4Addr,
}
async fn ip_listen_impl(
    task_group: TaskGroup,
    ip_socket: Arc<IpSocket>,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 65536];
    let dest_map = Arc::new(Mutex::new(HashMap::<IpKey, Sender<Bytes>>::new()));

    loop {
        let (len, protocol, src, dest) = ip_socket.recv_protocol_from_to(&mut buf).await?;
        let (IpAddr::V4(src), IpAddr::V4(dest)) = (src, dest) else {
            continue;
        };
        let key = IpKey {
            protocol,
            src,
            dest,
        };
        let bytes = Bytes::copy_from_slice(&buf[..len]);

        let tx = {
            let mut map = dest_map.lock();
            if let Some(tx) = map.get(&key) {
                tx.clone()
            } else {
                let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(128);

                spawn_dest_sender(task_group.clone(), key, rx, quic_tunnel_client.clone());

                map.insert(key, tx.clone());
                tx
            }
        };

        if let Err(err) = tx.try_send(bytes) {
            match err {
                TrySendError::Full(_) => {}
                TrySendError::Closed(_) => {
                    let mut map = dest_map.lock();
                    map.remove(&key);
                }
            }
        }
    }
}

fn spawn_dest_sender(
    task_group: TaskGroup,
    key: IpKey,
    mut rx: tokio::sync::mpsc::Receiver<Bytes>,
    quic_tunnel_client: QuicTunnelClient,
) {
    log::info!("send ip({}) packet {}->{}", key.protocol, key.src, key.dest);
    task_group.spawn(async move {
        let result = async {
            let mut send_stream = quic_tunnel_client.open_uni(key.dest).await?;

            let handshake = QuicProxyHandshake {
                handshake: Some(quic_proxy_handshake::Handshake::Ip(IpProxyHandshake {
                    ip_next_header_protocol: key.protocol.0 as _,
                    src_ip: key.src.into(),
                    dst_ip: key.dest.into(),
                })),
            };
            send_handshake(&mut send_stream, handshake).await?;

            let mut framed = FramedWrite::new(send_stream, LengthDelimitedCodec::new());

            while let Some(pkt) = rx.recv().await {
                framed.send(pkt).await?;
            }

            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(e) = result {
            log::error!("key {:?} sender task exit: {:?}", key, e);
        }
    });
}
