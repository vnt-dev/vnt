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
        match self.sender.try_send((data, addr)) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // 消费端处理不过来时丢包：channel 满不能阻塞整条 QUIC 接收循环，
                // 否则一个慢消费者会卡住所有对端的入站流量
                log::warn!("quic data inbound channel full, dropping packet from {addr}");
                Ok(())
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                Err(anyhow!("quic data inbound error"))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// channel 满时 send 必须立即返回（丢包），不能阻塞接收循环
    #[tokio::test]
    async fn test_send_drops_when_channel_full() {
        let (inbound, _receiver) = create_enhanced_inbound();
        // 填满 channel（容量 256）
        for _ in 0..256 {
            inbound
                .send(Bytes::from_static(b"x"), Ipv4Addr::LOCALHOST)
                .await
                .unwrap();
        }
        // 再发送：旧实现会永久阻塞，修复后应立即返回 Ok（丢包）
        let rs = tokio::time::timeout(
            Duration::from_millis(200),
            inbound.send(Bytes::from_static(b"y"), Ipv4Addr::LOCALHOST),
        )
        .await;
        assert!(rs.is_ok(), "send blocked on full channel");
        rs.unwrap().unwrap();
    }

    /// channel 关闭后 send 返回错误
    #[tokio::test]
    async fn test_send_errors_when_channel_closed() {
        let (inbound, receiver) = create_enhanced_inbound();
        drop(receiver);
        let rs = inbound
            .send(Bytes::from_static(b"x"), Ipv4Addr::LOCALHOST)
            .await;
        assert!(rs.is_err());
    }
}
