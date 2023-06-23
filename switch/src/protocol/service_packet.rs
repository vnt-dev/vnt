#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 注册请求
    RegistrationRequest,
    /// 注册响应
    RegistrationResponse,
    /// 拉取设备列表
    PollDeviceList,
    /// 推送设备列表
    PushDeviceList,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RegistrationRequest,
            2 => Self::RegistrationResponse,
            3 => Self::PollDeviceList,
            4 => Self::PushDeviceList,
            val => Self::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Self::RegistrationRequest => 1,
            Self::RegistrationResponse => 2,
            Self::PollDeviceList => 3,
            Self::PushDeviceList => 4,
            Self::Unknown(val) => val,
        }
    }
}
