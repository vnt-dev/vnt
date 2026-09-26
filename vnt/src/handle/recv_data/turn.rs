use crate::channel::context::ChannelContext;
use crate::channel::RouteKey;
use crate::handle::recv_data::PacketHandler;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::{NetPacket, Protocol};
use anyhow::Context;

#[derive(Clone)]
pub struct TurnPacketHandler {}

impl TurnPacketHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl PacketHandler for TurnPacketHandler {
    fn handle(
        &self,
        mut net_packet: NetPacket<&mut [u8]>,
        _extend: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &ChannelContext,
        _current_device: &CurrentDeviceInfo,
    ) -> anyhow::Result<()> {
        let ttl = net_packet.incr_ttl();
        if ttl > 0 {
            if net_packet.is_gateway() {
                return Ok(());
            }
            if !matches!(
                net_packet.protocol(),
                Protocol::IpTurn | Protocol::OtherTurn
            ) {
                return Ok(());
            }
            let destination = net_packet.destination();
            if let Some(route) = context.route_table.route_one(&destination) {
                if route.addr == route_key.addr {
                    log::warn!("来源和目标相同 {:?},{:?}", route_key, net_packet.head());
                    return Ok(());
                }
                if route.metric <= ttl {
                    return context
                        .send_by_key(&net_packet, route.route_key())
                        .context("转发失败");
                }
            }
        }
        Ok(())
    }
}