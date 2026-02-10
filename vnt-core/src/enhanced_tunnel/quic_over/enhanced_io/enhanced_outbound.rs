use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::outbound::HybridOutbound;
use crate::utils::task_control::TaskGroup;
use quinn::UdpPoller;
use std::fmt::{Debug, Formatter};
use std::io;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc::{Sender, error::TrySendError};
use tokio_util::sync::PollSender;

#[derive(Clone)]
pub struct QuicInnerOutbound {
    sender: Sender<(Ipv4Addr, NetPacket<TransmissionBytes>)>,
}

pub async fn create_enhanced_outbound(
    task_group: TaskGroup,
    hybrid_outbound: HybridOutbound,
) -> QuicInnerOutbound {
    let (s, mut r) = tokio::sync::mpsc::channel(256);

    task_group.spawn(async move {
        while let Some((dst, packet)) = r.recv().await {
            if let Err(e) = hybrid_outbound.outbound_raw(dst, packet).await {
                log::debug!("outbound error: {e:?}, dst={dst}");
            }
        }
    });

    QuicInnerOutbound { sender: s }
}

impl QuicInnerOutbound {
    pub fn try_outbound(&self, buf: &[u8], dest: Ipv4Addr) -> io::Result<()> {
        let send = match self.sender.try_reserve() {
            Ok(send) => send,
            Err(TrySendError::Full(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "outbound channel full",
                ));
            }
            Err(TrySendError::Closed(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "outbound channel closed",
                ));
            }
        };
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + buf.len()))?;
        packet.set_ttl(5);
        packet.set_msg_type(MsgType::Quic);
        packet.set_dest_id(dest.into());
        packet.set_payload(buf)?;
        send.send((dest, packet));
        Ok(())
    }
    pub fn create_io_poller(&self) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(EnhancedOutboundPoller {
            sender: PollSender::new(self.sender.clone()),
        })
    }
}
pub struct EnhancedOutboundPoller {
    sender: PollSender<(Ipv4Addr, NetPacket<TransmissionBytes>)>,
}
impl Debug for EnhancedOutboundPoller {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedOutboundPoller").finish()
    }
}
impl UdpPoller for EnhancedOutboundPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.sender.poll_reserve(cx) {
            Poll::Ready(Ok(_)) => {
                self.sender.abort_send();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "outbound channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
