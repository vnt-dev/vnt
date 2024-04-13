#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 注册请求
    RegistrationRequest,
    /// 注册响应
    RegistrationResponse,
    /// 拉取设备列表
    PullDeviceList,
    /// 推送设备列表
    PushDeviceList,
    /// 和服务端握手
    HandshakeRequest,
    HandshakeResponse,
    SecretHandshakeRequest,
    SecretHandshakeResponse,
    /// 客户端上报状态
    ClientStatusInfo,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RegistrationRequest,
            2 => Self::RegistrationResponse,
            3 => Self::PullDeviceList,
            4 => Self::PushDeviceList,
            5 => Self::HandshakeRequest,
            6 => Self::HandshakeResponse,
            7 => Self::SecretHandshakeRequest,
            8 => Self::SecretHandshakeResponse,
            9 => Self::ClientStatusInfo,
            val => Self::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Self::RegistrationRequest => 1,
            Self::RegistrationResponse => 2,
            Self::PullDeviceList => 3,
            Self::PushDeviceList => 4,
            Self::HandshakeRequest => 5,
            Self::HandshakeResponse => 6,
            Self::SecretHandshakeRequest => 7,
            Self::SecretHandshakeResponse => 8,
            Self::ClientStatusInfo => 9,
            Self::Unknown(val) => val,
        }
    }
}
