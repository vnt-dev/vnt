use crate::channel::context::Context;
use crate::channel::RouteKey;
use crate::handle::recv_data::PacketHandler;
use crate::handle::CurrentDeviceInfo;
use crate::protocol::NetPacket;

/// 处理客户端中转包
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
        _route_key: RouteKey,
        context: &Context,
        _current_device: &CurrentDeviceInfo,
    ) -> std::io::Result<()> {
        // ttl减一
        let ttl = net_packet.incr_ttl();
        if ttl > 0 {
            let destination = net_packet.destination();
            if let Some(route) = context.route_table.route_one(&destination) {
                if route.metric <= ttl {
                    context.send_by_key(net_packet.buffer(), route.route_key())?;
                }
            }
            //其他没有路由的不转发
        }

        Ok(())
    }
}
