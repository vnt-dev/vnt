//! 虚拟 IP 变更的传播：注册 IP 同步与向全部已连接服务端的快速注册通告。
//!
//! 诞生时由服务端下发的 UpdateIp 消息在 inbound 里就地触发（服务端主动改
//! IP）；现在触发方是订阅统一流程（apply_network_change /
//! apply_mobile_change_fd），本结构只负责效果的落地。IP 变化后连接保持
//! 不断、客户端也没有周期性重注册，服务端的 ip→会话映射全靠
//! [`IpUpdateContext::announce_ip`] 收敛：不发则发往新 IP 的入站流量在
//! 服务端无映射可投递，Ikev2/WireGuard 中继还会按 src 校验拒包。

use crate::protocol::control_message::{FastRegRequestMsg, RequestMessage};
use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType, NetPacket};
use crate::protocol::transmission::TransmissionBytes;
use crate::tunnel_core::server::outbound::ServerOutbound;
use bytes::Bytes;
use std::net::Ipv4Addr;
use std::time::Duration;

/// IP 变更的快速注册通告。重注册声称的 IP 直接读
/// [`crate::context::SharedNetworkAddr`]，本结构只负责“变化之后通知
/// 所有已连接服务端”。
#[derive(Clone)]
pub(crate) struct IpUpdateContext {
    server_outbound: ServerOutbound,
}

impl IpUpdateContext {
    pub fn new(server_outbound: ServerOutbound) -> Self {
        Self { server_outbound }
    }

    /// 向所有已连接服务端发送快速注册（IP 已由调用方写入共享网络地址）。
    pub(crate) async fn announce_ip(&self, ip: Ipv4Addr) {
        self.send_fast_reg(ip).await;
    }

    fn fast_reg_packet(ip: Ipv4Addr) -> anyhow::Result<Bytes> {
        let payload = RequestMessage::FastReg(FastRegRequestMsg { ip }).encode();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + payload.len()))?;
        packet.set_msg_type(MsgType::FastReg);
        packet.set_ttl(1);
        packet.set_gateway_flag(true);
        packet.set_payload(&payload)?;
        Ok(packet.into_buffer().into_bytes().freeze())
    }

    async fn send_fast_reg(&self, ip: Ipv4Addr) {
        let result = match Self::fast_reg_packet(ip) {
            Ok(packet) => {
                self.server_outbound
                    .send_gateway_to_all(packet, Duration::from_secs(2))
                    .await
            }
            Err(error) => Err(error),
        };
        match result {
            Ok(sent) => log::info!("快速注册已发送到 {sent} 台服务端，新 IP: {ip}"),
            Err(error) => log::warn!("发送快速注册失败，保留新 IP {ip}: {error:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_reg_packet_carries_ip_with_gateway_flag() {
        let buffer = IpUpdateContext::fast_reg_packet(Ipv4Addr::new(10, 26, 0, 9)).unwrap();
        let packet = NetPacket::new(TransmissionBytes::from(buffer)).unwrap();
        assert_eq!(packet.msg_type().unwrap(), MsgType::FastReg);
        assert!(packet.is_gateway());
        assert_eq!(packet.ttl(), 1);
        // 网关包载荷只携带新 IP（proto FastRegRequestMsg 单字段）
        assert!(!packet.payload().is_empty());
    }
}
