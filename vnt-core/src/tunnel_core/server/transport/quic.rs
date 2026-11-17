use crate::protocol::transmission::TransmissionBytes;
use crate::tls::verifier::CertValidationMode;
use crate::tunnel_core::server::transport::config::ConnectConfig;
use anyhow::{Context, bail};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use quinn::{
    ClientConfig, Endpoint, MtuDiscoveryConfig, RecvStream, SendStream, TokioRuntime,
    TransportConfig,
};
use std::sync::Arc;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Default)]
pub struct QuicTransport {
    framed: Option<(
        FramedWrite<SendStream, LengthDelimitedCodec>,
        FramedRead<RecvStream, LengthDelimitedCodec>,
    )>,
}
impl QuicTransport {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn disconnect(&mut self) {
        self.framed = None;
    }
    pub async fn connect(&mut self, config: &ConnectConfig) -> anyhow::Result<()> {
        if self.framed.is_some() {
            bail!("Already connected");
        }
        let (w, r) = connect_quic(config).await?;
        self.framed = Some((w, r));
        Ok(())
    }
    pub async fn send(&mut self, buf: Bytes) -> anyhow::Result<()> {
        let Some((w, _r)) = self.framed.as_mut() else {
            bail!("Not connected");
        };
        w.send(buf).await.context("send to server failed")
    }
    pub async fn next(&mut self) -> anyhow::Result<TransmissionBytes> {
        let Some((_w, r)) = self.framed.as_mut() else {
            bail!("Not connected");
        };
        r.next()
            .await
            .context("EOF")?
            .context("receive from server failed")
            .map(TransmissionBytes::from)
    }
}
pub async fn connect_quic(
    config: &ConnectConfig,
) -> anyhow::Result<(
    FramedWrite<SendStream, LengthDelimitedCodec>,
    FramedRead<RecvStream, LengthDelimitedCodec>,
)> {
    let server_addr = config.server_addr();
    let server_name = config.server_name();
    let payload_limit = match crate::utils::socket::udp_route_mtu(
        server_addr,
        config.default_interface.as_ref(),
    ) {
        Ok(mtu) => quic_payload_limit(mtu, server_addr.is_ipv6())?,
        Err(error) => {
            log::warn!(
                "Cannot query QUIC route MTU for {server_addr}: {error}; using a 1300-byte UDP payload upper bound"
            );
            1300
        }
    };
    log::debug!("QUIC UDP payload upper bound for {server_addr}: {payload_limit}");
    let quic_config = create_client_config(&config.cert_mode, payload_limit)?;
    let bind_addr = if server_addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = crate::utils::socket::bind_udp(bind_addr, config.default_interface.as_ref())?;
    let socket = socket.into_std()?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.max_udp_payload_size(payload_limit)?;
    let mut endpoint = Endpoint::new(endpoint_config, None, socket, Arc::new(TokioRuntime))
        .context("Failed to create QUIC endpoint")?;

    endpoint.set_default_client_config(quic_config);
    let connection = endpoint
        .connect(server_addr, server_name)?
        .await
        .context("Failed to establish QUIC connection")?;
    let (send_stream, recv_stream) = connection
        .open_bi()
        .await
        .context("Failed to open bidirectional stream")?;
    let framed_write = FramedWrite::new(send_stream, LengthDelimitedCodec::new());
    let framed_read = FramedRead::new(recv_stream, LengthDelimitedCodec::new());
    Ok((framed_write, framed_read))
}

// Reserve the headers for the endpoint's address family. Never raise Quinn's
// default Ethernet-sized discovery limit.
fn quic_payload_limit(ip_mtu: u32, is_ipv6: bool) -> anyhow::Result<u16> {
    let overhead = if is_ipv6 { 48 } else { 28 };
    let limit = ip_mtu.saturating_sub(overhead).min(1452);
    if limit < 1200 {
        bail!(
            "Route MTU {ip_mtu} cannot carry a 1200-byte QUIC payload with {overhead}-byte IP/UDP overhead"
        );
    }
    Ok(limit as u16)
}

fn create_client_config(
    cert_mode: &CertValidationMode,
    payload_limit: u16,
) -> anyhow::Result<ClientConfig> {
    let config = cert_mode.create_tls_client_config()?;
    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(config)
            .context("Failed to create QUIC client config")?,
    ));
    let mut discovery = MtuDiscoveryConfig::default();
    discovery.upper_bound(payload_limit);
    let mut transport = TransportConfig::default();
    transport.mtu_discovery_config(Some(discovery));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_payload_fits_pppoe_and_ipv6_minimum_mtu() {
        assert_eq!(quic_payload_limit(1492, true).unwrap(), 1444);
        assert_eq!(quic_payload_limit(1492, false).unwrap(), 1452);
        assert_eq!(quic_payload_limit(1280, true).unwrap(), 1232);
        for is_ipv6 in [false, true] {
            assert_eq!(quic_payload_limit(1500, is_ipv6).unwrap(), 1452);
            assert_eq!(quic_payload_limit(9000, is_ipv6).unwrap(), 1452);
            for mtu in [0, 27, 47, 1200, 1227] {
                assert!(quic_payload_limit(mtu, is_ipv6).is_err());
            }
        }
    }

    #[test]
    fn ipv4_low_mtu_paths_can_still_carry_quic_initial_packets() {
        for mtu in 1228..1248 {
            let limit = quic_payload_limit(mtu, false).unwrap();
            assert!(limit >= 1200);
            assert!(u32::from(limit) + 28 <= mtu);
            assert!(quic_payload_limit(mtu, true).is_err());
        }
        assert_eq!(quic_payload_limit(1228, false).unwrap(), 1200);
        assert_eq!(quic_payload_limit(1248, true).unwrap(), 1200);
    }

    #[tokio::test]
    async fn quic_discovery_respects_payload_limits_on_both_families() {
        use std::time::Duration;

        for (addr, limit) in [
            ("127.0.0.1:0", 1300),
            ("[::1]:0", 1300),
            ("127.0.0.1:0", quic_payload_limit(1492, false).unwrap()),
            ("[::1]:0", quic_payload_limit(1492, true).unwrap()),
            ("127.0.0.1:0", quic_payload_limit(1228, false).unwrap()),
        ] {
            let (cert, key) = crate::tls::cert::generate_deterministic_cert("mtu-test").unwrap();
            let server_config = quinn::ServerConfig::with_single_cert(vec![cert], key).unwrap();
            let server = Endpoint::server(server_config, addr.parse().unwrap()).unwrap();
            let mut client = Endpoint::new(
                Default::default(),
                None,
                std::net::UdpSocket::bind(addr).unwrap(),
                Arc::new(TokioRuntime),
            )
            .unwrap();
            client.set_default_client_config(
                create_client_config(&CertValidationMode::InsecureSkipVerification, limit).unwrap(),
            );
            let (connection, accepted) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    client
                        .connect(server.local_addr().unwrap(), "localhost")
                        .unwrap(),
                    async { server.accept().await.unwrap().await },
                )
            })
            .await
            .unwrap();
            let connection = connection.unwrap();
            let accepted = accepted.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while connection.stats().path.current_mtu < limit - 20 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // Allow the remaining probes to finish, including any probe above
            // the configured bound if that configuration regresses.
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(connection.stats().path.current_mtu <= limit);
            let ((), received) = tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(
                    async {
                        let mut stream = connection.open_uni().await.unwrap();
                        stream.write_all(&vec![42; 16 * 1024]).await.unwrap();
                        stream.finish().unwrap();
                    },
                    async {
                        accepted
                            .accept_uni()
                            .await
                            .unwrap()
                            .read_to_end(32 * 1024)
                            .await
                            .unwrap()
                    },
                )
            })
            .await
            .unwrap();
            assert_eq!(received, vec![42; 16 * 1024]);
            client.close(0u32.into(), b"test complete");
            server.close(0u32.into(), b"test complete");
        }
    }
}
