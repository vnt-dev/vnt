use crate::context::{NetworkAddr, SharedNetworkAddr};
use crate::nat::AllowSubnetExternalRoute;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::HybridOutbound;
use crate::utils::task_control::TaskGroup;
use anyhow::Context;
use bytes::BytesMut;
use pnet_packet::ip::IpNextHeaderProtocol;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tcp_ip::{IpStackConfig, IpStackRecv, IpStackSend};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(not(target_os = "android"))]
mod icmp_nat;
mod tcp_nat;
mod udp_nat;
#[derive(Clone)]
pub(crate) struct InternalNatInbound {
    no_tun: bool,
    ip_stack_send: Arc<IpStackSend>,
    allow_subnet: AllowSubnetExternalRoute,
    network: SharedNetworkAddr,
}
impl InternalNatInbound {
    pub async fn create(
        task_group: &TaskGroup,
        mtu: u16,
        hybrid_outbound: HybridOutbound,
        allow_subnet: AllowSubnetExternalRoute,
        network: SharedNetworkAddr,
        no_tun: bool,
    ) -> anyhow::Result<Self> {
        let ip_stack_config = IpStackConfig {
            mtu,
            ..Default::default()
        };
        let (ip_stack, ip_stack_send, ip_stack_recv) = tcp_ip::ip_stack(ip_stack_config)?;
        #[cfg(not(target_os = "android"))]
        icmp_nat::start_icmp_nat(task_group, &ip_stack, no_tun, network.clone()).await?;
        tcp_nat::start_tcp_nat(task_group, &ip_stack, no_tun, network.clone()).await?;
        udp_nat::start_udp_nat(task_group, &ip_stack).await?;
        task_group.spawn(async move {
            if let Err(e) = ip_stack_recv_task(ip_stack_recv, hybrid_outbound).await {
                log::error!("ip stack recv task error: {e:?}");
            }
        });
        Ok(Self {
            no_tun,
            ip_stack_send: Arc::new(ip_stack_send),
            allow_subnet,
            network,
        })
    }
    pub async fn send(&self, data: &[u8], net: &NetworkAddr) -> anyhow::Result<()> {
        if data[0] >> 4 != 4 {
            return Ok(());
        }
        let Some(ipv4) = Ipv4Packet::new(data) else {
            return Ok(());
        };
        let dest = ipv4.get_destination();
        if net.network().contains(&dest)
            || dest == net.broadcast
            || dest.is_broadcast()
            || dest.is_multicast()
            || self.allow_subnet.allow(&dest)
        {
            self.ip_stack_send.send_ip_packet(data).await?;
        }
        Ok(())
    }
    pub async fn send_ipv4_payload(
        &self,
        protocol: IpNextHeaderProtocol,
        src_ip: Ipv4Addr,
        dest_ip: Ipv4Addr,
        payload: BytesMut,
    ) -> anyhow::Result<()> {
        self.ip_stack_send
            .send_ipv4_payload(protocol, src_ip, dest_ip, payload)
            .await?;
        Ok(())
    }
}

async fn ip_stack_recv_task(
    mut ip_stack_recv: IpStackRecv,
    hybrid_outbound: HybridOutbound,
) -> anyhow::Result<()> {
    loop {
        let mut bytes = TransmissionBytes::new_offset_zeroed(HEAD_LENGTH);
        let len = ip_stack_recv.recv(&mut bytes).await?;
        bytes.set_len(len)?;
        if let Err(e) = hybrid_outbound.ipv4_outbound_common(bytes).await {
            log::warn!("ip_stack_recv_task,{e:?}");
        }
    }
}

impl InternalNatInbound {
    fn network_contains(&self, ip: &Ipv4Addr) -> bool {
        self.network
            .network()
            .map(|net| net.contains(ip))
            .unwrap_or(false)
    }
    pub fn use_nat(&self, dst: &Ipv4Addr) -> bool {
        if self.no_tun {
            return self.allow_nat(dst);
        }
        if self.network_contains(dst) {
            return false;
        }
        self.allow_subnet.allow(dst)
    }
    pub fn no_tun(&self) -> bool {
        self.no_tun
    }
    pub fn allow_nat(&self, dst: &Ipv4Addr) -> bool {
        self.allow_subnet.allow(dst) || self.network_contains(dst)
    }
    pub async fn tcp_nat<R, W>(
        &self,
        recv_stream: R,
        send_stream: W,
        mut dest_ip: Ipv4Addr,
        dest_port: u16,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if self.no_tun {
            let net = self.network.get().context("no network")?;
            if dest_ip == net.ip {
                dest_ip = Ipv4Addr::LOCALHOST;
            } else if net.network().contains(&dest_ip) {
                return Ok(());
            }
        }
        let dst = SocketAddr::new(dest_ip.into(), dest_port);
        tcp_nat::stream_nat(recv_stream, send_stream, dst).await
    }
}

#[derive(Clone)]
pub(crate) struct PortMappingManager {
    no_tun: bool,
    allow_port_mapping: bool,
    network: SharedNetworkAddr,
}

impl PortMappingManager {
    pub fn new(no_tun: bool, allow_port_mapping: bool, network: SharedNetworkAddr) -> Self {
        Self {
            no_tun,
            allow_port_mapping,
            network,
        }
    }
    pub async fn tcp_mapping<R, W>(
        &self,
        recv_stream: R,
        send_stream: W,
        dest: String,
        dest_port: u16,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if !self.allow_port_mapping {
            log::debug!("port mapping not enabled");
            return Ok(());
        }
        if self.no_tun
            && let Ok(dest_ip) = Ipv4Addr::from_str(&dest)
        {
            let net = self.network.get().context("no network")?;

            if dest_ip == net.ip {
                let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), dest_port);
                return tcp_nat::stream_nat(recv_stream, send_stream, dst).await;
            } else if net.network().contains(&dest_ip) {
                return Ok(());
            }
        }
        let dst = format!("{}:{}", dest, dest_port);
        tcp_nat::stream_nat(recv_stream, send_stream, dst).await
    }
    pub async fn udp_mapping<R, W>(
        &self,
        recv_stream: R,
        send_stream: W,
        dest: String,
        dest_port: u16,
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        if !self.allow_port_mapping {
            log::debug!("port mapping not enabled");
            return Ok(());
        }
        if self.no_tun
            && let Ok(dest_ip) = Ipv4Addr::from_str(&dest)
        {
            let net = self.network.get().context("no network")?;

            if dest_ip == net.ip {
                let dst = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), dest_port);
                return udp_nat::stream_nat(recv_stream, send_stream, dst).await;
            } else if net.network().contains(&dest_ip) {
                return Ok(());
            }
        }
        let dst = format!("{}:{}", dest, dest_port);
        udp_nat::stream_nat(recv_stream, send_stream, dst).await
    }
}
