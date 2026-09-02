use crate::protocol::ProtoToBytesMut;
pub(crate) use crate::protocol::control_message::proto::SelectiveBroadcast;
use crate::protocol::control_message::proto::request_message::RequestPayload;
use crate::protocol::control_message::proto::response_message::ResponsePayload;
use anyhow::bail;
use bytes::BytesMut;
use ipnet::Ipv4Net;
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
    pub advertised_subnets: Vec<Ipv4Net>,
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
            advertised_subnets: self
                .advertised_subnets
                .into_iter()
                .map(ipv4_subnet_to_proto)
                .collect(),
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegResponseMsg {
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub server_version: String,
    pub subnet_sync_supported: bool,
}
impl RegResponseMsg {
    pub fn from(msg: proto::RegResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            prefix_len: (msg.prefix_len & 0xFF) as u8,
            gateway: msg.gateway.into(),
            server_version: msg.server_version,
            subnet_sync_supported: msg.subnet_sync_supported,
        })
    }
    pub fn to(self) -> proto::RegResponseMsg {
        proto::RegResponseMsg {
            ip: self.ip.into(),
            prefix_len: self.prefix_len as _,
            gateway: self.gateway.into(),
            server_version: self.server_version,
            subnet_sync_supported: self.subnet_sync_supported,
        }
    }
}

fn ipv4_subnet_to_proto(net: Ipv4Net) -> proto::Ipv4Subnet {
    let net = net.trunc();
    proto::Ipv4Subnet {
        network: net.network().into(),
        prefix_len: net.prefix_len().into(),
    }
}

fn ipv4_subnet_from_proto(net: proto::Ipv4Subnet) -> anyhow::Result<Ipv4Net> {
    let prefix_len = u8::try_from(net.prefix_len)?;
    Ok(Ipv4Net::new(Ipv4Addr::from(net.network), prefix_len)?.trunc())
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct NodeSubnetRoutes {
    pub ip: Ipv4Addr,
    pub subnets: Vec<Ipv4Net>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct SubnetSyncResponse {
    pub snapshot_hash: Vec<u8>,
    pub nodes: Vec<NodeSubnetRoutes>,
}

pub(crate) fn encode_subnet_sync_request(known_hash: &[u8]) -> BytesMut {
    proto::SubnetSyncRequest {
        known_hash: known_hash.to_vec(),
    }
    .encode_bytes_mut()
}

impl SubnetSyncResponse {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        let msg = proto::SubnetSyncResponse::decode(buf)?;
        let mut nodes = Vec::with_capacity(msg.nodes.len());
        for node in msg.nodes {
            let mut subnets = Vec::with_capacity(node.subnets.len());
            for subnet in node.subnets {
                subnets.push(ipv4_subnet_from_proto(subnet)?);
            }
            nodes.push(NodeSubnetRoutes {
                ip: node.ip.into(),
                subnets,
            });
        }
        Ok(Self {
            snapshot_hash: msg.snapshot_hash,
            nodes,
        })
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FastRegRequestMsg {
    pub ip: Ipv4Addr,
}
impl FastRegRequestMsg {
    pub fn to(self) -> proto::FastRegRequestMsg {
        proto::FastRegRequestMsg { ip: self.ip.into() }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FastRegResponseMsg {
    pub success: bool,
}
impl FastRegResponseMsg {
    pub fn from(msg: proto::FastRegResponseMsg) -> anyhow::Result<Self> {
        Ok(Self {
            success: msg.success,
        })
    }
    pub fn to(self) -> proto::FastRegResponseMsg {
        proto::FastRegResponseMsg {
            success: self.success,
        }
    }
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
    FastReg(FastRegRequestMsg),
}
impl RequestMessage {
    pub fn encode(self) -> BytesMut {
        let request_payload = match self {
            RequestMessage::Reg(reg) => RequestPayload::Reg(reg.to()),
            RequestMessage::ConfirmReg => RequestPayload::ConfirmReg(proto::ConfirmRegMsg {}),
            RequestMessage::FastReg(fast_reg) => RequestPayload::FastReg(fast_reg.to()),
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
    FastReg(FastRegResponseMsg),
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
            ResponsePayload::FastReg(fast_reg) => Ok(ResponseMessage::FastReg(
                FastRegResponseMsg::from(fast_reg)?,
            )),
        }
    }
    pub fn encode(self) -> BytesMut {
        let response_payload = match self {
            ResponseMessage::Reg(reg) => ResponsePayload::Reg(reg.to()),
            ResponseMessage::Error(e) => ResponsePayload::Error(e.to()),
            ResponseMessage::ConfirmReg(c) => ResponsePayload::ConfirmReg(c.to()),
            ResponseMessage::FastReg(fast_reg) => ResponsePayload::FastReg(fast_reg.to()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_registration_request_and_response_round_trip() {
        let ip = Ipv4Addr::new(10, 26, 0, 9);
        let encoded = RequestMessage::FastReg(FastRegRequestMsg { ip }).encode();
        let request = proto::RequestMessage::decode(encoded.as_ref()).unwrap();
        match request.request_payload.unwrap() {
            RequestPayload::FastReg(message) => assert_eq!(Ipv4Addr::from(message.ip), ip),
            payload => panic!("unexpected request payload: {payload:?}"),
        }

        let encoded = ResponseMessage::FastReg(FastRegResponseMsg { success: true }).encode();
        assert_eq!(
            ResponseMessage::from_slice(encoded.as_ref()).unwrap(),
            ResponseMessage::FastReg(FastRegResponseMsg { success: true })
        );
    }

    #[test]
    fn subnet_registration_and_snapshot_round_trip() {
        let advertised = "192.168.1.0/24".parse::<Ipv4Net>().unwrap();
        let encoded = RequestMessage::Reg(RegRequestMsg {
            network_code: "test".to_string(),
            device_id: "device".to_string(),
            ip: None,
            name: "node".to_string(),
            version: "1".to_string(),
            key_sign: None,
            ip_variable: true,
            server_id: 0,
            registration_mode: RegistrationMode::Normal,
            advertised_subnets: vec![advertised],
        })
        .encode();
        let request = proto::RequestMessage::decode(encoded.as_ref()).unwrap();
        let RequestPayload::Reg(request) = request.request_payload.unwrap() else {
            panic!("expected registration request");
        };
        assert_eq!(
            ipv4_subnet_from_proto(request.advertised_subnets[0]).unwrap(),
            advertised
        );

        let encoded = ResponseMessage::Reg(RegResponseMsg {
            ip: Ipv4Addr::new(10, 26, 0, 2),
            prefix_len: 24,
            gateway: Ipv4Addr::new(10, 26, 0, 1),
            server_version: "2".to_string(),
            subnet_sync_supported: true,
        })
        .encode();
        let ResponseMessage::Reg(response) = ResponseMessage::from_slice(encoded.as_ref()).unwrap()
        else {
            panic!("expected registration response");
        };
        assert!(response.subnet_sync_supported);

        let encoded = proto::SubnetSyncResponse {
            snapshot_hash: vec![1, 2, 3],
            nodes: vec![proto::NodeSubnetRoutes {
                ip: Ipv4Addr::new(10, 26, 0, 2).into(),
                subnets: vec![ipv4_subnet_to_proto(advertised)],
            }],
        }
        .encode_to_vec();
        let snapshot = SubnetSyncResponse::from_slice(&encoded).unwrap();
        assert_eq!(snapshot.snapshot_hash, vec![1, 2, 3]);
        assert_eq!(snapshot.nodes[0].subnets, vec![advertised]);
    }
}
