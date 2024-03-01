use std::net::{Ipv4Addr, SocketAddr};

pub mod callback;
pub mod handshaker;
pub mod maintain;
pub mod recv_data;
pub mod registrar;
pub mod tun_tap;

const SELF_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 2);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 1);

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
    pub fn new(virtual_ip: Ipv4Addr, name: String, status: u8, client_secret: bool) -> Self {
        Self {
            virtual_ip,
            name,
            status: PeerDeviceStatus::from(status),
            client_secret,
        }
    }
}

#[derive(Clone, Debug)]
pub struct BaseConfigInfo {
    pub name: String,
    pub token: String,
    pub ip: Option<Ipv4Addr>,
    pub client_secret: bool,
    pub device_id: String,
    pub server_addr: String,
}

impl BaseConfigInfo {
    pub fn new(
        name: String,
        token: String,
        ip: Option<Ipv4Addr>,
        client_secret: bool,
        device_id: String,
        server_addr: String,
    ) -> Self {
        Self {
            name,
            token,
            ip,
            client_secret,
            device_id,
            server_addr,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PeerDeviceStatus {
    Online,
    Offline,
}

impl PeerDeviceStatus {
    pub fn is_online(&self) -> bool {
        self == &PeerDeviceStatus::Online
    }
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

impl ConnectStatus {
    pub fn online(&self) -> bool {
        self == &ConnectStatus::Connected
    }
    pub fn offline(&self) -> bool {
        self == &ConnectStatus::Connecting
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CurrentDeviceInfo {
    //本机虚拟IP
    pub virtual_ip: Ipv4Addr,
    //子网掩码
    pub virtual_netmask: Ipv4Addr,
    //虚拟网关
    pub virtual_gateway: Ipv4Addr,
    //网络地址
    pub virtual_network: Ipv4Addr,
    //直接广播地址
    pub broadcast_ip: Ipv4Addr,
    //链接的服务器地址
    pub connect_server: SocketAddr,
    //连接状态
    pub status: ConnectStatus,
}

impl CurrentDeviceInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
        connect_server: SocketAddr,
    ) -> Self {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            broadcast_ip,
            connect_server,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn new0(connect_server: SocketAddr) -> Self {
        Self {
            virtual_ip: Ipv4Addr::UNSPECIFIED,
            virtual_gateway: Ipv4Addr::UNSPECIFIED,
            virtual_netmask: Ipv4Addr::UNSPECIFIED,
            virtual_network: Ipv4Addr::UNSPECIFIED,
            broadcast_ip: Ipv4Addr::UNSPECIFIED,
            connect_server,
            status: ConnectStatus::Connecting,
        }
    }
    pub fn update(
        &mut self,
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
    ) {
        let broadcast_ip = (!u32::from_be_bytes(virtual_netmask.octets()))
            | u32::from_be_bytes(virtual_gateway.octets());
        let broadcast_ip = Ipv4Addr::from(broadcast_ip);
        let virtual_network = u32::from_be_bytes(virtual_netmask.octets())
            & u32::from_be_bytes(virtual_gateway.octets());
        let virtual_network = Ipv4Addr::from(virtual_network);
        self.virtual_ip = virtual_ip;
        self.virtual_netmask = virtual_netmask;
        self.virtual_gateway = virtual_gateway;
        self.broadcast_ip = broadcast_ip;
        self.virtual_network = virtual_network;
    }
    #[inline]
    pub fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }
    #[inline]
    pub fn virtual_gateway(&self) -> Ipv4Addr {
        self.virtual_gateway
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        &self.virtual_gateway == ip || ip == &GATEWAY_IP
    }
}
