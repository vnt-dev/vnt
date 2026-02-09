use crate::enhanced_tunnel::quic_over::enhanced_io::enhanced_inbound::QuicInnerInboundReceiver;
use crate::enhanced_tunnel::quic_over::enhanced_io::enhanced_outbound::QuicInnerOutbound;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::fmt::{Debug, Formatter};
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct ExtendedQuicSocket {
    inbound: QuicInnerInboundReceiver,
    outbound: QuicInnerOutbound,
}
impl Debug for ExtendedQuicSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicSocket").finish()
    }
}
impl ExtendedQuicSocket {
    pub fn new(inbound: QuicInnerInboundReceiver, outbound: QuicInnerOutbound) -> Self {
        Self { inbound, outbound }
    }
}

impl AsyncUdpSocket for ExtendedQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.outbound.create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        let IpAddr::V4(dest) = transmit.destination.ip() else {
            return Ok(());
        };

        self.outbound.try_outbound(transmit.contents, dest)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        self.inbound.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            10000,
        )))
    }
}
