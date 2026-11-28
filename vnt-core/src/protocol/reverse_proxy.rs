// Keep the wire format in sync with vnt-core's reverse_proxy protocol.
use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, SinkExt, Stream, StreamExt};
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub(crate) const TOKEN_LEN: usize = 32;
const ATTACH_MAGIC: &[u8] = b"\0VNT reverse proxy v1\0";
pub(crate) const ACCEPT: &[u8] = &[2];
pub(crate) const READY: &[u8] = &[3];
pub(crate) const MAX_DATAGRAM: usize = 65_507;
const FIN: &[u8] = &[1];
const TCP_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum Protocol {
    Tcp = 1,
    Udp = 2,
}

pub(crate) struct Offer {
    pub protocol: Protocol,
    pub target: SocketAddrV4,
    pub token: [u8; TOKEN_LEN],
}

impl Offer {
    pub fn decode(data: &[u8]) -> Result<Self> {
        ensure!(data.len() == 7 + TOKEN_LEN, "invalid reverse proxy offer");
        let protocol = match data[0] {
            1 => Protocol::Tcp,
            2 => Protocol::Udp,
            _ => anyhow::bail!("invalid reverse proxy protocol"),
        };
        let port = u16::from_be_bytes(data[5..7].try_into()?);
        ensure!(port != 0, "invalid reverse proxy port");
        let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&data[1..5])?);
        ensure!(valid_target(ip), "invalid reverse proxy IP");
        Ok(Self {
            protocol,
            target: SocketAddrV4::new(ip, port),
            token: data[7..].try_into()?,
        })
    }
}

pub(crate) fn valid_target(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

pub(crate) fn attach(token: &[u8; TOKEN_LEN]) -> Bytes {
    let mut data = BytesMut::with_capacity(ATTACH_MAGIC.len() + TOKEN_LEN);
    data.extend_from_slice(ATTACH_MAGIC);
    data.extend_from_slice(token);
    data.freeze()
}

pub(crate) fn data_frame(payload: &[u8]) -> Bytes {
    let mut frame = BytesMut::with_capacity(payload.len() + 1);
    frame.put_u8(0);
    frame.extend_from_slice(payload);
    frame.freeze()
}

pub(crate) fn datagram(frame: &[u8]) -> Result<&[u8]> {
    match frame.split_first() {
        Some((&0, payload)) if payload.len() <= MAX_DATAGRAM => Ok(payload),
        _ => anyhow::bail!("invalid reverse proxy datagram"),
    }
}

pub(crate) async fn relay_tcp<S, R>(socket: TcpStream, mut send: S, mut recv: R) -> Result<()>
where
    S: Sink<Bytes, Error = anyhow::Error> + Unpin,
    R: Stream<Item = Result<Bytes>> + Unpin,
{
    let (mut read, mut write) = socket.into_split();
    tokio::try_join!(
        async {
            let mut buffer = vec![0; TCP_CHUNK];
            loop {
                let len = read.read(&mut buffer).await?;
                if len == 0 {
                    send.send(Bytes::from_static(FIN)).await?;
                    return Ok::<(), anyhow::Error>(());
                }
                send.send(data_frame(&buffer[..len])).await?;
            }
        },
        async {
            loop {
                let frame = recv.next().await.context("reverse proxy disconnected")??;
                if frame == FIN {
                    write.shutdown().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                let (kind, payload) = frame.split_first().context("empty reverse proxy frame")?;
                ensure!(
                    *kind == 0 && payload.len() <= TCP_CHUNK,
                    "invalid TCP frame"
                );
                write.write_all(payload).await?;
            }
        }
    )?;
    Ok(())
}
