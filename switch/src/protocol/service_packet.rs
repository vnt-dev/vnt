#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Protocol {
    /// 注册请求
    RegistrationRequest,
    /// 注册响应
    RegistrationResponse,
    /// 更新设备列表
    UpdateDeviceList,
    UnKnow(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RegistrationRequest,
            2 => Self::RegistrationResponse,
            3 => Self::UpdateDeviceList,
            val => Self::UnKnow(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Self::RegistrationRequest => 1,
            Self::RegistrationResponse => 2,
            Self::UpdateDeviceList => 3,
            Self::UnKnow(val) => val,
        }
    }
}
