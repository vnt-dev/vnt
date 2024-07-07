use anyhow::Context;
use std::net::SocketAddr;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct VnLinkConfig {
    pub mapping: Vec<LinkItem>,
}

impl VnLinkConfig {
    pub fn new(mapping: Vec<LinkItem>) -> Self {
        Self { mapping }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum LinkProtocol {
    Tcp,
    Udp,
}

impl LinkProtocol {
    pub fn is_tcp(&self) -> bool {
        self == &LinkProtocol::Tcp
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LinkItem {
    pub protocol: LinkProtocol,
    pub src_port: u16,
    pub dest: SocketAddr,
}

impl LinkItem {
    pub fn new(protocol: LinkProtocol, src_port: u16, dest: SocketAddr) -> Self {
        Self {
            protocol,
            src_port,
            dest,
        }
    }
}

pub fn convert(vec: Vec<String>) -> anyhow::Result<Vec<LinkItem>> {
    let mut rs = Vec::with_capacity(vec.len());
    for x in vec {
        let string = x.trim().to_lowercase();
        if let Some(udp_mapping) = string.strip_prefix("udp:") {
            let mut split = udp_mapping.split("-");
            let bind_port = split
                .next()
                .with_context(|| format!("vnt-mapping error {:?},eg: udp:80-10.26.0.10:8080", x))?;
            let bind_port = u16::from_str(bind_port)
                .with_context(|| format!("udp_mapping error {}", bind_port))?;
            let dest = split
                .next()
                .with_context(|| format!("vnt-mapping error {:?},eg: udp:80-10.26.0.10:8080", x))?;
            let dest_addr = SocketAddr::from_str(dest)
                .with_context(|| format!("udp_mapping error {}", dest))?;
            rs.push(LinkItem::new(LinkProtocol::Udp, bind_port, dest_addr));
            continue;
        }
        if let Some(tcp_mapping) = string.strip_prefix("tcp:") {
            let mut split = tcp_mapping.split("-");
            let bind_port = split
                .next()
                .with_context(|| format!("vnt-mapping error {:?},eg: tcp:80-10.26.0.10:8080", x))?;
            let bind_port = u16::from_str(bind_port)
                .with_context(|| format!("tcp_mapping error {}", bind_port))?;
            let dest = split
                .next()
                .with_context(|| format!("vnt-mapping error {:?},eg: tcp:80-10.26.0.10:8080", x))?;
            let dest_addr = SocketAddr::from_str(dest)
                .with_context(|| format!("tcp_mapping error {}", dest))?;
            rs.push(LinkItem::new(LinkProtocol::Tcp, bind_port, dest_addr));
            continue;
        }
        Err(anyhow::anyhow!(
            "vnt-mapping error {:?},eg: tcp:80-10.26.0.10:8080",
            x
        ))?;
    }
    Ok(rs)
}
