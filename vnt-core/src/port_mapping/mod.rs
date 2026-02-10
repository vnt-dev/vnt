use crate::enhanced_tunnel::quic_over::quic_client::QuicTunnelClient;
use crate::utils::task_control::TaskGroup;
use pnet_packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;

pub(crate) mod tcp_port_mapping;
pub(crate) mod udp_port_mapping;

pub(crate) async fn port_mapping_start(
    task_group: &TaskGroup,
    list: Vec<PortMapping>,
    quic_tunnel_client: QuicTunnelClient,
) -> anyhow::Result<()> {
    tcp_port_mapping::start(task_group, &list, quic_tunnel_client.clone()).await?;
    udp_port_mapping::start(task_group, &list, quic_tunnel_client).await?;
    Ok(())
}
#[derive(Debug, Clone)]
pub struct PortMapping {
    pub protocol: IpNextHeaderProtocol,
    pub src_addr: SocketAddr,
    pub virtual_target_ip: Ipv4Addr,
    pub dst_host: String,
    pub dst_port: u16,
}

impl fmt::Display for PortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}://{}-{}-{}:{}",
            protocol_to_str(self.protocol),
            self.src_addr,
            self.virtual_target_ip,
            self.dst_host,
            self.dst_port
        )
    }
}

impl FromStr for PortMapping {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (proto_str, rest) = s.split_once("://").ok_or("missing '://'")?;

        let protocol =
            str_to_protocol(proto_str).ok_or_else(|| format!("unknown protocol: {}", proto_str))?;

        let mut parts = rest.splitn(3, '-');

        let src_addr = parts
            .next()
            .ok_or("missing src_addr")?
            .parse::<SocketAddr>()
            .map_err(|e| format!("invalid src_addr: {}", e))?;

        let virtual_target_ip = parts
            .next()
            .ok_or("missing virtual_target_ip")?
            .parse::<Ipv4Addr>()
            .map_err(|e| format!("invalid virtual_target_ip: {}", e))?;

        let dst = parts.next().ok_or("missing destination")?;

        let (dst_host, dst_port) = dst.rsplit_once(':').ok_or("missing dst port")?;

        let dst_port = dst_port
            .parse::<u16>()
            .map_err(|e| format!("invalid dst_port: {}", e))?;
        if dst_port == 0 {
            return Err("invalid dst port: 0".to_string());
        }
        Ok(Self {
            protocol,
            src_addr,
            virtual_target_ip,
            dst_host: dst_host.to_string(),
            dst_port,
        })
    }
}

fn protocol_to_str(p: IpNextHeaderProtocol) -> &'static str {
    match p {
        IpNextHeaderProtocols::Tcp => "tcp",
        IpNextHeaderProtocols::Udp => "udp",
        _ => "unknown",
    }
}

fn str_to_protocol(s: &str) -> Option<IpNextHeaderProtocol> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(IpNextHeaderProtocols::Tcp),
        "udp" => Some(IpNextHeaderProtocols::Udp),
        _ => None,
    }
}
