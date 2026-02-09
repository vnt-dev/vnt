use anyhow::anyhow;
use bytes::Bytes;
use parking_lot::Mutex;
use quinn::udp::RecvMeta;
use std::fmt::{Debug, Formatter};
use std::io::IoSliceMut;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::mpsc::{Receiver, Sender};

#[derive(Clone)]
pub struct QuicInnerInboundReceiver {
    receiver: Arc<Mutex<Receiver<(Bytes, Ipv4Addr)>>>,
}
#[derive(Clone)]
pub struct QuicDataInbound {
    sender: Sender<(Bytes, Ipv4Addr)>,
}
impl QuicDataInbound {
    pub async fn send(&self, data: Bytes, addr: Ipv4Addr) -> anyhow::Result<()> {
        self.sender
            .send((data, addr))
            .await
            .map_err(|_e| anyhow!("quic data inbound error"))
    }
}
impl Debug for QuicInnerInboundReceiver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnhancedInbound").finish()
    }
}
pub fn create_enhanced_inbound() -> (QuicDataInbound, QuicInnerInboundReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(256);
    (
        QuicDataInbound { sender },
        QuicInnerInboundReceiver::new(receiver),
    )
}
impl QuicInnerInboundReceiver {
    pub fn new(receiver: Receiver<(Bytes, Ipv4Addr)>) -> Self {
        Self {
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        let mut guard = self.receiver.lock();
        let rs = guard.poll_recv(cx);
        drop(guard);
        match rs {
            Poll::Ready(Some((buf, ip))) => {
                let (buf_mut, meta) = match (bufs.get_mut(0), meta.get_mut(0)) {
                    (Some(b), Some(m)) => (b, m),
                    _ => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "no buffer available",
                        )));
                    }
                };

                if buf_mut.len() < buf.len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "buffer too small: need {}, got {}",
                            buf.len(),
                            buf_mut.len()
                        ),
                    )));
                }

                buf_mut[..buf.len()].copy_from_slice(&buf);

                meta.len = buf.len();
                meta.stride = buf.len();
                meta.addr = SocketAddr::V4(SocketAddrV4::new(ip, 10000));
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "inbound channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
