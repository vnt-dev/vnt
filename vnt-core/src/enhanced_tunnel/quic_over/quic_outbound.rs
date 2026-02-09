use crate::context::NetworkAddr;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet_packet::tcp::TcpFlags::{ACK, SYN};
use pnet_packet::tcp::TcpPacket;
use std::net::SocketAddr;
use tcp_ip::{IpStack, IpStackSend};

pub struct EnhancedQuicOutbound {
    open_quic_client: bool,
    ip_stack_send: IpStackSend,
    ip_stack: IpStack,
}

impl EnhancedQuicOutbound {
    pub fn new(open_quic_client: bool, ip_stack_send: IpStackSend, ip_stack: IpStack) -> Self {
        Self {
            open_quic_client,
            ip_stack_send,
            ip_stack,
        }
    }
    pub async fn outbound(&self, _net: &NetworkAddr, data: &[u8]) -> bool {
        let Some(ipv4) = Ipv4Packet::new(data) else {
            return true;
        };

        if self.open_quic_client {
            // 针对tcp  如果不是从IpStack建立的连接，则不使用IpStack解析
            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                let more_fragments =
                    ipv4.get_flags() & Ipv4Flags::MoreFragments == Ipv4Flags::MoreFragments;
                let offset = ipv4.get_fragment_offset();
                let segmented = more_fragments || offset > 0;
                if !segmented {
                    let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
                        return true;
                    };
                    // 不是第一个包
                    if !(tcp.get_flags() & SYN == SYN && tcp.get_flags() & ACK != ACK) {
                        let local_addr =
                            SocketAddr::new(ipv4.get_source().into(), tcp.get_source());
                        let peer_addr =
                            SocketAddr::new(ipv4.get_destination().into(), tcp.get_destination());
                        // 在IpStack中找不到连接
                        if !self
                            .ip_stack
                            .has_tcp_connection(local_addr, peer_addr)
                            .unwrap_or(false)
                            && !self
                                .ip_stack
                                .has_tcp_connection(peer_addr, local_addr)
                                .unwrap_or(false)
                            && !self
                                .ip_stack
                                .has_tcp_half_open(peer_addr, local_addr)
                                .unwrap_or(false)
                        {
                            return false;
                        }
                    }
                }
            }
            _ = self.ip_stack_send.send_ip_packet(data).await;
            return true;
        }
        // 判断tcp流
        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            let more_fragments =
                ipv4.get_flags() & Ipv4Flags::MoreFragments == Ipv4Flags::MoreFragments;
            let offset = ipv4.get_fragment_offset();
            let segmented = more_fragments || offset > 0;
            if !segmented && let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                // 如果对端使用IpStack连接了自己，则也需要原路回复
                // 这是连接回复，所以方向是和流方向相反的
                let peer_addr = SocketAddr::new(ipv4.get_source().into(), tcp.get_source());
                let local_addr =
                    SocketAddr::new(ipv4.get_destination().into(), tcp.get_destination());

                if self
                    .ip_stack
                    .has_tcp_connection(local_addr, peer_addr)
                    .unwrap_or(false)
                {
                    _ = self.ip_stack_send.send_ip_packet(data).await;
                    return true;
                }
            }
        }

        false
    }
}
