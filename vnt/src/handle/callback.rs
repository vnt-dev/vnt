use crate::handle::PeerDeviceStatus;
#[cfg(feature = "server_encrypt")]
use rsa::RsaPublicKey;
use std::fmt::{Display, Formatter};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub version: String,
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl Display for DeviceInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("name={} ,version={}", self.name, self.version))
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
impl DeviceInfo {
    pub fn new(name: String, version: String) -> Self {
        return Self { name, version };
    }
}

#[derive(Debug)]
pub struct ConnectInfo {
    // 第几次连接，从1开始
    pub count: usize,
    // 服务端地址
    pub address: SocketAddr,
}

impl Display for ConnectInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("count={} ,address={}", self.count, self.address))
    }
}

impl ConnectInfo {
    pub fn new(count: usize, address: SocketAddr) -> Self {
        Self { count, address }
    }
}

#[derive(Debug)]
pub struct HandshakeInfo {
    //服务端公钥
    #[cfg(feature = "server_encrypt")]
    pub public_key: Option<RsaPublicKey>,
    //服务端指纹
    #[cfg(feature = "server_encrypt")]
    pub finger: Option<String>,
    //服务端版本
    pub version: String,
}

impl Display for HandshakeInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "server_encrypt")]
        return match &self.finger {
            None => f.write_str(&format!("no_secret server version={}", self.version)),
            Some(finger) => f.write_str(&format!(
                "finger={} ,server version={}",
                finger, self.version
            )),
        };
        #[cfg(not(feature = "server_encrypt"))]
        f.write_str(&format!("server version={}", self.version))
    }
}

#[cfg(feature = "server_encrypt")]
impl HandshakeInfo {
    pub fn new(public_key: RsaPublicKey, finger: String, version: String) -> Self {
        Self {
            public_key: Some(public_key),
            finger: Some(finger),
            version,
        }
    }
    pub fn new_no_secret(version: String) -> Self {
        Self {
            public_key: None,
            finger: None,
            version,
        }
    }
}

#[cfg(not(feature = "server_encrypt"))]
impl HandshakeInfo {
    pub fn new_no_secret(version: String) -> Self {
        Self { version }
    }
}

#[derive(Debug)]
pub struct RegisterInfo {
    //本机虚拟IP
    pub virtual_ip: Ipv4Addr,
    //子网掩码
    pub virtual_netmask: Ipv4Addr,
    //虚拟网关
    pub virtual_gateway: Ipv4Addr,
}

impl Display for RegisterInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "ip={} ,netmask={} ,gateway={}",
            self.virtual_ip, self.virtual_netmask, self.virtual_gateway,
        ))
    }
}

impl RegisterInfo {
    pub fn new(virtual_ip: Ipv4Addr, virtual_netmask: Ipv4Addr, virtual_gateway: Ipv4Addr) -> Self {
        Self {
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
        }
    }
}

#[derive(Debug)]
pub struct ErrorInfo {
    pub code: ErrorType,
    pub msg: Option<String>,
    pub source: Option<io::Error>,
}

impl Display for ErrorInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("ErrorType={:?} ", self.code))?;
        if let Some(msg) = &self.msg {
            f.write_str(&format!(",msg={:?} ", msg))?;
        }
        if let Some(source) = &self.source {
            f.write_str(&format!(",source={:?} ", source))?;
        }
        Ok(())
    }
}

impl ErrorInfo {
    pub fn new(code: ErrorType) -> Self {
        Self {
            code,
            msg: None,
            source: None,
        }
    }
    pub fn new_msg(code: ErrorType, msg: String) -> Self {
        Self {
            code,
            msg: Some(msg),
            source: None,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorType {
    TokenError,
    Disconnect,
    AddressExhausted,
    IpAlreadyExists,
    InvalidIp,
    LocalIpExists,
    FailedToCrateDevice,
    Warn,
    Unknown,
}

impl Into<u8> for ErrorType {
    fn into(self) -> u8 {
        match self {
            ErrorType::TokenError => 1,
            ErrorType::Disconnect => 2,
            ErrorType::AddressExhausted => 3,
            ErrorType::IpAlreadyExists => 4,
            ErrorType::InvalidIp => 5,
            ErrorType::LocalIpExists => 6,
            ErrorType::FailedToCrateDevice => 101,
            ErrorType::Warn => 102,
            ErrorType::Unknown => 255,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    #[cfg(feature = "integrated_tun")]
    #[cfg(target_os = "windows")]
    pub tap: bool,
    #[cfg(feature = "integrated_tun")]
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    pub device_name: Option<String>,
    //虚拟网卡mtu值
    pub mtu: u32,
    //本机虚拟IP
    pub virtual_ip: Ipv4Addr,
    //子网掩码
    pub virtual_netmask: Ipv4Addr,
    //虚拟网关
    pub virtual_gateway: Ipv4Addr,
    //虚拟网段
    pub virtual_network: Ipv4Addr,
    // 额外的路由
    pub external_route: Vec<(Ipv4Addr, Ipv4Addr)>,
}

impl DeviceConfig {
    pub fn new(
        #[cfg(feature = "integrated_tun")]
        #[cfg(target_os = "windows")]
        tap: bool,
        #[cfg(feature = "integrated_tun")]
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        device_name: Option<String>,
        mtu: u32,
        virtual_ip: Ipv4Addr,
        virtual_netmask: Ipv4Addr,
        virtual_gateway: Ipv4Addr,
        virtual_network: Ipv4Addr,
        external_route: Vec<(Ipv4Addr, Ipv4Addr)>,
    ) -> Self {
        Self {
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap,
            #[cfg(feature = "integrated_tun")]
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            device_name,
            mtu,
            virtual_ip,
            virtual_netmask,
            virtual_gateway,
            virtual_network,
            external_route,
        }
    }
}

impl Display for DeviceConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "ip={} ,netmask={} ,gateway={}, external_route={:?}",
            self.virtual_ip, self.virtual_netmask, self.virtual_gateway, self.external_route
        ))
    }
}

#[derive(Debug)]
pub struct PeerClientInfo {
    pub virtual_ip: Ipv4Addr,
    pub name: String,
    pub status: PeerDeviceStatus,
    pub client_secret: bool,
}

impl PeerClientInfo {
    pub fn new(
        virtual_ip: Ipv4Addr,
        name: String,
        status: PeerDeviceStatus,
        client_secret: bool,
    ) -> Self {
        Self {
            virtual_ip,
            name,
            status,
            client_secret,
        }
    }
}

impl Display for PeerClientInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "ip={} ,name={} ,status={:?}, client_secret={}",
            self.virtual_ip, self.name, self.status, self.client_secret
        ))
    }
}

pub trait VntCallback: Clone + Send + Sync + 'static {
    /// 启动成功
    fn success(&self) {}

    /// 创建网卡的信息
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    #[cfg(feature = "integrated_tun")]
    fn create_tun(&self, _info: DeviceInfo) {}
    /// 连接
    fn connect(&self, _info: ConnectInfo) {}
    /// 握手,返回false则拒绝握手，可在此处检查服务端信息
    fn handshake(&self, _info: HandshakeInfo) -> bool {
        true
    }
    /// 注册，返回false则拒绝注册
    fn register(&self, _info: RegisterInfo) -> bool {
        true
    }
    #[cfg(not(feature = "integrated_tun"))]
    fn create_device(&self, _info: DeviceConfig) {}
    #[cfg(target_os = "android")]
    #[cfg(feature = "integrated_tun")]
    fn generate_tun(&self, _info: DeviceConfig) -> usize {
        0
    }
    fn peer_client_list(&self, _info: Vec<PeerClientInfo>) {}
    /// 异常信息
    fn error(&self, _info: ErrorInfo) {}
    /// 服务停止
    fn stop(&self) {}
}
