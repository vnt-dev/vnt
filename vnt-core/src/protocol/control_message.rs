use crate::protocol::ProtoToBytesMut;
pub(crate) use crate::protocol::control_message::proto::SelectiveBroadcast;
use crate::protocol::control_message::proto::request_message::RequestPayload;
use crate::protocol::control_message::proto::response_message::ResponsePayload;
use anyhow::bail;
use bytes::BytesMut;
use prost::Message;
use std::net::Ipv4Addr;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.control_message.rs"));
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum RegistrationMode {
    #[default]
    Normal = 0,
    PreRegister = 1,
}

impl From<RegistrationMode> for proto::RegistrationMode {
    fn from(mode: RegistrationMode) -> Self {
        match mode {
            RegistrationMode::Normal => proto::RegistrationMode::Normal,
            RegistrationMode::PreRegister => proto::RegistrationMode::PreRegister,
        }
    }
}

impl From<proto::RegistrationMode> for RegistrationMode {
    fn from(mode: proto::RegistrationMode) -> Self {
        match mode {
            proto::RegistrationMode::Normal => RegistrationMode::Normal,
            proto::RegistrationMode::PreRegister => RegistrationMode::PreRegister,
        }
    }
}
pub(crate) struct RegRequestMsg {
    pub network_code: String,
    pub device_id: String,
    pub ip: Option<Ipv4Addr>,
    pub name: String,
    pub version: String,
    pub key_sign: Option<String>,
    pub ip_variable: bool,
    pub server_id: u32,
    pub registration_mode: RegistrationMode,
}
impl RegRequestMsg {
    // pub fn check(&self) -> anyhow::Result<()> {
    //     if self.network_code.is_empty() {
    //         return Err(anyhow!("network_code cannot be empty"));
    //     }
    //     if self.network_code.len() > MAX_NETWORK_CODE_LEN {
    //         return Err(anyhow!(
    //             "network_code length exceeds {} characters (current: {})",
    //             MAX_NETWORK_CODE_LEN,
    //             self.network_code.len()
    //         ));
    //     }
    //     if self.device_id.is_empty() {
    //         return Err(anyhow!("device_id cannot be empty"));
    //     }
    //     if self.device_id.len() > MAX_DEVICE_ID_LEN {
    //         return Err(anyhow!(
    //             "device_id length exceeds {} characters (current: {})",
    //             MAX_DEVICE_ID_LEN,
    //             self.device_id.len()
    //         ));
    //     }
    //
    //     if self.name.len() > MAX_NAME_LEN {
    //         return Err(anyhow!(
    //             "name length exceeds {} characters (current: {})",
    //             MAX_NAME_LEN,
    //             self.name.len()
    //         ));
    //     }
    //
    //     if self.version.len() > MAX_VERSION_LEN {
    //         return Err(anyhow!(
    //             "version length exceeds {} characters (current: {})",
    //             MAX_VERSION_LEN,
    //             self.version.len()
    //         ));
    //     }
    //
    //     Ok(())
    // }
    // pub fn from(msg: proto::RegRequestMsg) -> anyhow::Result<Self> {
    //     Ok(Self {
    //         network_code: msg.network_code,
    //         device_id: msg.device_id,
    //         ip: msg.ip.map(|ip| ip.into()),
    //         name: msg.name,
    //         version: msg.version,
    //         key_sign: msg.key_sign,
    //         ip_variable: msg.ip_variable,
    //         server_id: msg.server_id,
    //     })
    // }
    pub fn to(self) -> proto::RegRequestMsg {
        proto::RegRequestMsg {
            network_code: self.network_code,
            device_id: self.device_id,
            ip: self.ip.map(|ip| ip.into()),
            name: self.name,
            version: self.version,
            key_sign: self.key_sign,
            ip_variable: self.ip_variable,
            server_id: self.server_id,
            registration_mode: proto::RegistrationMode::from(self.registration_mode).into(),
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegResponseMsg {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub server_version: String,
}
impl RegResponseMsg {
    pub fn from(msg: proto::RegResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            prefix_len: (msg.prefix_len & 0xFF) as u8,
            gateway: msg.gateway.into(),
            server_version: msg.server_version,
        })
    }
    pub fn to(self) -> proto::RegResponseMsg {
        proto::RegResponseMsg {
            ip: self.ip.into(),
            prefix_len: self.prefix_len as _,
            gateway: self.gateway.into(),
            server_version: self.server_version,
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ErrorResponseMsg {
    pub code: u32,
    pub message: String,
}
impl ErrorResponseMsg {
    pub fn from(msg: proto::ErrorResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            code: msg.code,
            message: msg.message,
        })
    }
    pub fn to(self) -> proto::ErrorResponseMsg {
        proto::ErrorResponseMsg {
            code: self.code,
            message: self.message,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfirmRegResponseMsg {
    pub success: bool,
}
impl ConfirmRegResponseMsg {
    pub fn from(msg: proto::ConfirmRegResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            success: msg.success,
        })
    }
    pub fn to(self) -> proto::ConfirmRegResponseMsg {
        proto::ConfirmRegResponseMsg {
            success: self.success,
        }
    }
}
pub(crate) enum RequestMessage {
    Reg(RegRequestMsg),
    ConfirmReg,
}
impl RequestMessage {
    pub fn encode(self) -> BytesMut {
        let request_payload = match self {
            RequestMessage::Reg(reg) => RequestPayload::Reg(reg.to()),
            RequestMessage::ConfirmReg => RequestPayload::ConfirmReg(proto::ConfirmRegMsg {}),
        };
        proto::RequestMessage {
            request_payload: Some(request_payload),
        }
        .encode_bytes_mut()
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ResponseMessage {
    Reg(RegResponseMsg),
    Error(ErrorResponseMsg),
    ConfirmReg(ConfirmRegResponseMsg),
}
impl ResponseMessage {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::ResponseMessage::decode(buf)?;
        let Some(payload) = msg.response_payload else {
            bail!("unsupported")
        };
        match payload {
            ResponsePayload::Reg(reg) => Ok(ResponseMessage::Reg(RegResponseMsg::from(reg)?)),
            ResponsePayload::Error(e) => Ok(ResponseMessage::Error(ErrorResponseMsg::from(e)?)),
            ResponsePayload::ConfirmReg(c) => {
                Ok(ResponseMessage::ConfirmReg(ConfirmRegResponseMsg::from(c)?))
            }
        }
    }
    pub fn encode(self) -> BytesMut {
        let response_payload = match self {
            ResponseMessage::Reg(reg) => ResponsePayload::Reg(reg.to()),
            ResponseMessage::Error(e) => ResponsePayload::Error(e.to()),
            ResponseMessage::ConfirmReg(c) => ResponsePayload::ConfirmReg(c.to()),
        };
        proto::ResponseMessage {
            response_payload: Some(response_payload),
        }
        .encode_bytes_mut()
    }
}

impl SelectiveBroadcast {
    pub fn new(ips: &[Ipv4Addr], data: Vec<u8>) -> Self {
        SelectiveBroadcast {
            ips: ips.iter().map(|v| (*v).into()).collect(),
            data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientSimpleInfo {
    pub ip: Ipv4Addr,
    pub online: bool,
}
impl ClientSimpleInfo {
    pub fn from(msg: proto::ClientSimpleInfo) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            online: msg.online,
        })
    }
    pub fn to(self) -> proto::ClientSimpleInfo {
        proto::ClientSimpleInfo {
            ip: self.ip.into(),
            online: self.online,
        }
    }
}
#[derive(Debug)]
pub struct ClientSimpleInfoList {
    pub data_version: u64,
    pub list: Vec<ClientSimpleInfo>,
    pub is_all: bool,
    pub time: i64,
}
impl ClientSimpleInfoList {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::ClientSimpleInfoList::decode(buf)?;
        let mut list = Vec::with_capacity(msg.list.len());
        for x in msg.list {
            list.push(ClientSimpleInfo::from(x)?);
        }
        Ok(Self {
            data_version: msg.data_version,
            list,
            is_all: msg.is_all,
            time: msg.time,
        })
    }
}
