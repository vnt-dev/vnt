use crate::context::NetworkAddr;
use crate::ethernet::{strip_ip, strip_ipv4};
use crate::nat::internal_nat::InternalNatInbound;
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::TunDataInbound;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub enum EnhancedTunInbound {
    Tun(TunDataInbound),
    Tap(TunDataInbound),
    Nat(InternalNatInbound),
}
impl EnhancedTunInbound {
    pub async fn inbound(
        &self,
        data: TransmissionBytes,
        net: &NetworkAddr,
        src_node: Ipv4Addr,
        ethernet: bool,
    ) -> anyhow::Result<()> {
        match self {
            EnhancedTunInbound::Tun(tun) => {
                let data = if ethernet {
                    let Some(ip) = strip_ip(data) else {
                        return Ok(());
                    };
                    ip
                } else {
                    data
                };
                tun.send_ip(data, net, src_node).await
            }
            EnhancedTunInbound::Tap(tap) => {
                if ethernet {
                    tap.send_frame(data).await
                } else {
                    tap.send_ip(data, net, src_node).await
                }
            }
            EnhancedTunInbound::Nat(nat) => {
                let data = if ethernet {
                    let Some(ip) = strip_ipv4(data) else {
                        return Ok(());
                    };
                    ip
                } else {
                    data
                };
                if data.first().is_some_and(|v| v >> 4 == 6) {
                    return Ok(());
                }
                nat.send(&data, net).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::config::DeviceMode;
    use crate::ethernet::{parse_frame, wrap_ipv4};
    use crate::nat::AllowSubnetExternalRoute;
    use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
    use crate::tun::{TunDataInbound, tun_channel};
    use pnet_packet::ethernet::EtherTypes;

    #[tokio::test]
    async fn ipv6_tun_tap_conversion_and_destination_filter() {
        use crate::ethernet::{strip_ip, wrap_ipv6};
        let net = network();
        let source = Ipv4Addr::new(10, 26, 0, 8);
        let make_packet = |destination: std::net::Ipv6Addr| {
            let mut data = TransmissionBytes::with_capacity(HEAD_LENGTH + 14, 128);
            let mut bytes = [0u8; 48];
            bytes[0] = 0x60;
            bytes[5] = 8;
            bytes[6] = 17;
            bytes[8..24].copy_from_slice(&crate::virtual_ipv6::address(source).octets());
            bytes[24..40].copy_from_slice(&destination.octets());
            data.put(&bytes).unwrap();
            data
        };
        let (tx, mut rx) = tun_channel();
        let tun = EnhancedTunInbound::Tun(TunDataInbound::new(
            tx,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tun,
        ));
        let expected = make_packet(crate::virtual_ipv6::address(net.ip));
        let frame = wrap_ipv6(expected, source, &net).unwrap();
        tun.inbound(frame, &net, source, true).await.unwrap();
        assert_eq!(rx.receiver.recv().await.unwrap().len(), 48);
        tun.inbound(
            make_packet("2001:db8::1".parse().unwrap()),
            &net,
            source,
            false,
        )
        .await
        .unwrap();
        assert!(rx.receiver.try_recv().is_err());
        tun.inbound(
            make_packet(crate::virtual_ipv6::address(source)),
            &net,
            source,
            false,
        )
        .await
        .unwrap();
        assert!(rx.receiver.try_recv().is_err());
        let (tx, mut rx) = tun_channel();
        let tap = EnhancedTunInbound::Tap(TunDataInbound::new(
            tx,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tap,
        ));
        let multicast = "ff02::1234".parse().unwrap();
        tap.inbound(make_packet(multicast), &net, source, false)
            .await
            .unwrap();
        let frame = rx.receiver.recv().await.unwrap();
        assert_eq!(
            parse_frame(&frame).unwrap().destination.octets(),
            [0x33, 0x33, 0, 0, 0x12, 0x34]
        );
        assert_eq!(strip_ip(frame).unwrap().len(), 48);
        let packet = make_packet("2001:db8::2".parse().unwrap());
        let frame = wrap_ipv6(packet, source, &net).unwrap();
        let expected = frame.as_ref().to_vec();
        tap.inbound(frame, &net, source, true).await.unwrap();
        assert_eq!(rx.receiver.recv().await.unwrap().as_ref(), expected);
    }

    fn network() -> NetworkAddr {
        NetworkAddr {
            gateway: Some(Ipv4Addr::new(10, 26, 0, 1)),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
            ip: Ipv4Addr::new(10, 26, 0, 9),
            prefix_len: 24,
        }
    }

    fn ipv4(src: Ipv4Addr, dest: Ipv4Addr) -> TransmissionBytes {
        let mut packet = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + 20);
        packet.put(&[0u8; 20]).unwrap();
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dest.octets());
        packet
    }

    #[tokio::test]
    async fn tap_wraps_ip_and_tun_strips_ethernet() {
        let net = network();
        let src = Ipv4Addr::new(10, 26, 0, 8);

        let (tap_tx, mut tap_rx) = tun_channel();
        let tap = EnhancedTunInbound::Tap(TunDataInbound::new(
            tap_tx,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tap,
        ));
        tap.inbound(ipv4(src, net.ip), &net, src, false)
            .await
            .unwrap();
        let frame = tap_rx.receiver.recv().await.unwrap();
        assert_eq!(
            parse_frame(frame.as_ref()).unwrap().ethertype,
            EtherTypes::Ipv4
        );

        let (tun_tx, mut tun_rx) = tun_channel();
        let tun = EnhancedTunInbound::Tun(TunDataInbound::new(
            tun_tx,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tun,
        ));
        let frame = wrap_ipv4(ipv4(src, net.ip), src, &net).unwrap();
        tun.inbound(frame, &net, src, true).await.unwrap();
        let packet = tun_rx.receiver.recv().await.unwrap();
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(&packet[16..20], &net.ip.octets());
    }

    #[tokio::test]
    async fn tap_keeps_arbitrary_ethernet_frame() {
        let net = network();
        let src = Ipv4Addr::new(10, 26, 0, 8);
        let (tap_tx, mut tap_rx) = tun_channel();
        let tap = EnhancedTunInbound::Tap(TunDataInbound::new(
            tap_tx,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tap,
        ));
        let mut raw = vec![0u8; 32];
        raw[0..6].copy_from_slice(&[0xff; 6]);
        raw[12..14].copy_from_slice(&0x88b5u16.to_be_bytes());
        tap.inbound(raw.as_slice().into(), &net, src, true)
            .await
            .unwrap();
        assert_eq!(tap_rx.receiver.recv().await.unwrap().as_ref(), raw);
    }
}
