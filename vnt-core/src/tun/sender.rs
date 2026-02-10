use crate::context::NetworkAddr;
use crate::nat::AllowSubnetExternalRoute;
use crate::protocol::transmission::TransmissionBytes;
use crate::tun::TunInbound;
use pnet_packet::ipv4::Ipv4Packet;

#[derive(Clone)]
pub struct TunDataInbound {
    allow_subnet: AllowSubnetExternalRoute,
    tun_inbound: TunInbound,
}
impl TunDataInbound {
    pub fn new(tun_inbound: TunInbound, allow_subnet: AllowSubnetExternalRoute) -> Self {
        Self {
            allow_subnet,
            tun_inbound,
        }
    }
}

impl TunDataInbound {
    pub async fn send(&self, data: TransmissionBytes, net: &NetworkAddr) -> anyhow::Result<()> {
        if data[0] >> 4 != 4 {
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
            self.tun_inbound.sender.send(data).await?;
        }
        Ok(())
    }
}
