use super::transport::{
    self, TransportClient,
    config::{ConnectConfig, ProtocolType},
};
use crate::context::NetworkAddr;
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::reverse_proxy::{self as wire, Offer, Protocol};
use crate::protocol::transmission::TransmissionBytes;
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tokio_tungstenite::tungstenite::{self, Message};

const SETUP: Duration = Duration::from_secs(10);

pub(super) struct ReverseProxyClient {
    config: Option<ConnectConfig>,
    policy: watch::Receiver<bool>,
    advertised: Option<(Ipv4Addr, bool)>,
    flows: JoinSet<()>,
}

impl ReverseProxyClient {
    pub fn new(config: Option<ConnectConfig>, policy: watch::Receiver<bool>) -> Self {
        Self {
            config,
            policy,
            advertised: None,
            flows: JoinSet::new(),
        }
    }

    pub async fn sync(
        &mut self,
        transport: &mut TransportClient,
        current: Option<NetworkAddr>,
    ) -> Result<()> {
        let allowed = *self.policy.borrow_and_update();
        if self.config.is_none() {
            return Ok(());
        }
        let Some(network) = current else {
            self.flows.abort_all();
            self.advertised = None;
            return Ok(());
        };
        let Some(gateway) = network.gateway else {
            return Ok(());
        };
        if self.advertised == Some((network.ip, allowed)) {
            return Ok(());
        }
        self.flows.abort_all();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed_size(HEAD_LENGTH + 1, 0))?;
        packet.set_msg_type(MsgType::ReverseProxy);
        packet.set_gateway_flag(true);
        packet.set_ttl(1);
        packet.set_src_id(network.ip.into());
        packet.set_dest_id(gateway.into());
        packet.set_payload(&[u8::from(allowed)])?;
        transport.send_turn(packet).await?;
        self.advertised = Some((network.ip, allowed));
        Ok(())
    }

    pub async fn changed(&mut self) {
        tokio::select! {
            _ = self.policy.changed() => {}
            _ = self.flows.join_next(), if !self.flows.is_empty() => {}
        }
    }

    pub fn handle(&mut self, packet: &NetPacket<impl AsRef<[u8]>>, local: Option<NetworkAddr>) {
        let Some(config) = &self.config else {
            return;
        };
        let Some(local) = local else {
            return;
        };
        if !*self.policy.borrow()
            || self.advertised != Some((local.ip, true))
            || !packet.is_gateway()
            || local.gateway != Some(packet.src_id().into())
            || u32::from(local.ip) != packet.dest_id()
            || self.flows.len() >= 128
        {
            return;
        }
        let Ok(offer) = Offer::decode(packet.payload()) else {
            return;
        };
        let config = config.clone();
        let mut policy = self.policy.clone();
        let connect_policy = policy.clone();
        self.flows.spawn(async move {
            tokio::select! {
                _ = policy.wait_for(|allowed| !allowed) => {}
                _ = connect(&config, offer, connect_policy) => {}
            }
        });
    }
}

async fn connect(
    config: &ConnectConfig,
    offer: Offer,
    policy: watch::Receiver<bool>,
) -> Result<()> {
    let deadline = Instant::now() + SETUP;
    match config.protocol_type {
        ProtocolType::TlsTcp => {
            let framed = timeout_at(deadline, transport::tcp::connect_tls_tcp(config)).await??;
            let (send, recv) = framed.split();
            run(send, recv, offer, policy, deadline).await
        }
        #[cfg(feature = "quic")]
        ProtocolType::Quic => {
            let (send, recv) =
                timeout_at(deadline, transport::quic::connect_quic(config)).await??;
            run(send, recv, offer, policy, deadline).await
        }
        #[cfg(not(feature = "quic"))]
        ProtocolType::Quic => anyhow::bail!("QUIC is disabled in this build"),
        ProtocolType::Wss => {
            let socket = timeout_at(deadline, transport::wss::connect_wss(config)).await??;
            let (send, recv) = socket.split();
            let send = send.with(|bytes| {
                std::future::ready(Ok::<_, tungstenite::Error>(Message::Binary(bytes)))
            });
            let recv = recv.filter_map(|item| {
                std::future::ready(match item {
                    Ok(Message::Binary(bytes)) => Some(Ok(bytes)),
                    Ok(Message::Close(_)) => Some(Err(tungstenite::Error::ConnectionClosed)),
                    Ok(_) => None,
                    Err(error) => Some(Err(error)),
                })
            });
            run(send, recv, offer, policy, deadline).await
        }
        ProtocolType::Dynamic => anyhow::bail!("unresolved reverse proxy transport"),
    }
}

async fn run<S, R, B, E>(
    send: S,
    recv: R,
    offer: Offer,
    policy: watch::Receiver<bool>,
    deadline: Instant,
) -> Result<()>
where
    S: Sink<Bytes> + Unpin,
    S::Error: Into<anyhow::Error>,
    R: Stream<Item = std::result::Result<B, E>> + Unpin,
    B: Into<Bytes>,
    E: Into<anyhow::Error>,
{
    let mut send = send.sink_map_err(Into::into);
    let mut recv = recv.map(|frame| frame.map(Into::into).map_err(Into::into));
    let socket = timeout_at(deadline, async {
        send.send(wire::attach(&offer.token)).await?;
        let accepted: Bytes = recv
            .next()
            .await
            .context("reverse proxy setup disconnected")??;
        ensure!(
            accepted == wire::ACCEPT && *policy.borrow(),
            "reverse proxy attachment refused"
        );
        let socket = match offer.protocol {
            Protocol::Tcp => Target::Tcp(TcpStream::connect(offer.target).await?),
            Protocol::Udp => {
                let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
                socket.connect(offer.target).await?;
                Target::Udp(socket)
            }
        };
        ensure!(*policy.borrow(), "reverse proxy permission revoked");
        send.send(Bytes::from_static(wire::READY)).await?;
        Ok::<_, anyhow::Error>(socket)
    })
    .await??;

    match socket {
        Target::Tcp(socket) => wire::relay_tcp(socket, send, recv).await,
        Target::Udp(socket) => {
            tokio::try_join!(
                async {
                    let mut buffer = vec![0; 65_535];
                    loop {
                        let len = socket.recv(&mut buffer).await?;
                        if len <= wire::MAX_DATAGRAM {
                            send.send(wire::data_frame(&buffer[..len])).await?;
                        }
                    }
                    #[allow(unreachable_code)]
                    Ok::<(), anyhow::Error>(())
                },
                async {
                    while let Some(frame) = recv.next().await {
                        socket.send(wire::datagram(&frame?)?).await?;
                    }
                    Err::<(), _>(anyhow::anyhow!("reverse proxy disconnected"))
                },
            )?;
            Ok(())
        }
    }
}

enum Target {
    Tcp(TcpStream),
    Udp(UdpSocket),
}
