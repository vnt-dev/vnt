use std::net::{Ipv4Addr, SocketAddr};

pub mod handshake_handler;
pub mod heartbeat_handler;
pub mod punch_handler;
pub mod recv_handler;
pub mod registration_handler;
pub mod tun_tap;

pub fn now_time() -> u64 {
    let now = std::time::SystemTime::now();
    if let Ok(timestamp) = now.duration_since(std::time::UNIX_EPOCH) {
        timestamp.as_secs() * 1000 + u64::from(timestamp.subsec_millis())
    } else {
        0
    }
}

/// 是否在一个网段
fn check_dest(dest: Ipv4Addr, virtual_netmask: Ipv4Addr, virtual_network: Ipv4Addr) -> bool {
    u32::from_be_bytes(dest.octets()) & u32::from_be_bytes(virtual_netmask.octets())
        == u32::from_be_bytes(virtual_network.octets())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerDeviceInfo {
    pub virtual_ip: Ipv4Addr,
    pub name: String,
    pub status: PeerDeviceStatus,
    pub client_secret: bool,
}

impl PeerDeviceInfo {
    pub fn new(virtual_ip: Ipv4Addr, name: String, status: u8,client_secret: bool) -> Self {
        Self {
            virtual_ip,
            name,
            status: PeerDeviceStatus::from(status),
            client_secret
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq,Ord, PartialOrd)]
pub enum PeerDeviceStatus {
    Online,
    Offline,
}

impl Into<u8> for PeerDeviceStatus {
    fn into(self) -> u8 {
        match self {
            PeerDeviceStatus::Online => 0,
            PeerDeviceStatus::Offline => 1,
        }
    }
}

impl From<u8> for PeerDeviceStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => PeerDeviceStatus::Online,
            _ => PeerDeviceStatus::Offline,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConnectStatus {
    Connecting,
    Connected,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentDeviceInfo {
    virtual_ip: Ipv4Addr,
    pub virtual_gateway: Ipv4Addr,
    pub virtual_netmask: Ipv4Addr,
    //网络地址
    pub virtual_network: Ipv4Addr,
    //直接广播地址
    pub broadcast_address: Ipv4Addr,
    //链接的服务器地址
    pub connect_server: SocketAddr,

}

impl CurrentDeviceInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        connect_server: SocketAddr,
    ) -> Self {
        let broadcast_address = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_address = Ipv4Addr::from(broadcast_address);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            broadcast_address,
            connect_server,
        }
    }
    #[inline]
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }
    #[inline]
    pub fn virtual_gateway(&self) -> Ipv4Addr {
        self.virtual_gateway
    }
}
