use crate::context::NetworkAddr;
use crate::context::config::DeviceMode;
use crate::ethernet::wrap_ipv4;
use crate::nat::AllowSubnetExternalRoute;
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::TunInbound;
use pnet_packet::ipv4::Ipv4Packet;
use std::net::Ipv4Addr;

#[derive(Clone)]
pub struct TunDataInbound {
    allow_subnet: AllowSubnetExternalRoute,
    tun_inbound: TunInbound,
    device_mode: DeviceMode,
}
impl TunDataInbound {
    pub fn new(
        tun_inbound: TunInbound,
        allow_subnet: AllowSubnetExternalRoute,
        device_mode: DeviceMode,
    ) -> Self {
        Self {
            allow_subnet,
            tun_inbound,
            device_mode,
        }
    }
}

impl TunDataInbound {
    pub async fn send_ip(
        &self,
        data: TransmissionBytes,
        net: &NetworkAddr,
        src_node: Ipv4Addr,
    ) -> anyhow::Result<()> {
        if data.is_empty() || data[0] >> 4 != 4 {
            return Ok(());
        }
        let Some(ipv4) = Ipv4Packet::new(data.as_ref()) else {
            return Ok(());
        };
        let dest = ipv4.get_destination();
        if net.network().contains(&dest)
            || dest == net.broadcast
            || dest.is_broadcast()
            || dest.is_multicast()
            || self.allow_subnet.allow(&dest)
        {
            let data = if self.device_mode == DeviceMode::Tap {
                let Some(frame) = wrap_ipv4(data, src_node, net) else {
                    return Ok(());
                };
                frame
            } else {
                data
            };
            self.tun_inbound.sender.send(data).await?;
        }
        Ok(())
    }

    pub async fn send_frame(&self, data: TransmissionBytes) -> anyhow::Result<()> {
        self.tun_inbound.sender.send(data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::AllowSubnetExternalRoute;
    use crate::tun::tun_channel;

    fn test_net() -> NetworkAddr {
        NetworkAddr {
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            broadcast: Ipv4Addr::new(10, 26, 0, 255),
            ip: Ipv4Addr::new(10, 26, 0, 2),
            prefix_len: 24,
        }
    }

    /// 对端构造的零载荷/畸形包必须被静默丢弃，不能 panic 杀死数据面任务
    #[tokio::test]
    async fn test_send_empty_or_short_packet_does_not_panic() {
        let (tun_inbound, _receiver) = tun_channel();
        let inbound = TunDataInbound::new(
            tun_inbound,
            AllowSubnetExternalRoute::new(vec![]),
            DeviceMode::Tun,
        );

        // 零载荷包（头部被剥离后为空）
        inbound
            .send_ip(
                TransmissionBytes::zeroed(0),
                &test_net(),
                Ipv4Addr::new(10, 26, 0, 3),
            )
            .await
            .unwrap();

        // 过短的包（不足 IPv4 头）
        inbound
            .send_ip(
                TransmissionBytes::zeroed(3),
                &test_net(),
                Ipv4Addr::new(10, 26, 0, 3),
            )
            .await
            .unwrap();
    }
}
