use crate::protocol::ProtoToBytesMut;
pub(crate) use crate::protocol::control_message::proto::SelectiveBroadcast;
use crate::protocol::control_message::proto::request_message::RequestPayload;
use crate::protocol::control_message::proto::response_message::ResponsePayload;
use anyhow::bail;
use bytes::{Bytes, BytesMut};
use ipnet::Ipv4Net;
use prost::Message;
use std::net::Ipv4Addr;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/protocol.control_message.rs"));
}

pub use proto::{ClientType, SubscriptionConfigApplyStatus};

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
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub subscription: Option<SubscriptionRegistration>,
    pub client_instance_id: Vec<u8>,
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
            allow_ikev2: self.allow_ikev2,
            allow_wireguard: self.allow_wireguard,
            subscription: self.subscription.map(SubscriptionRegistration::to),
            client_instance_id: self.client_instance_id,
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
    pub subscription_config_supported: bool,
    pub subscription: Option<SubscriptionServerProof>,
    pub server_instance_id: Vec<u8>,
    pub multi_link_supported: bool,
}
impl RegResponseMsg {
    pub fn from(msg: proto::RegResponseMsg) -> anyhow::Result<Self> {
        if !msg.server_instance_id.is_empty() && msg.server_instance_id.len() != 32 {
            bail!("server_instance_id must contain 32 bytes");
        }
        Ok(Self {
            ip: msg.ip.into(),
            prefix_len: (msg.prefix_len & 0xFF) as u8,
            gateway: msg.gateway.into(),
            server_version: msg.server_version,
            subnet_sync_supported: msg.subnet_sync_supported,
            subscription_config_supported: msg.subscription_config_supported,
            subscription: msg.subscription.map(SubscriptionServerProof::from),
            server_instance_id: msg.server_instance_id,
            multi_link_supported: msg.multi_link_supported,
        })
    }
    pub fn to(self) -> proto::RegResponseMsg {
        proto::RegResponseMsg {
            ip: self.ip.into(),
            prefix_len: self.prefix_len as _,
            gateway: self.gateway.into(),
            server_version: self.server_version,
            subnet_sync_supported: self.subnet_sync_supported,
            subscription_config_supported: self.subscription_config_supported,
            subscription: self.subscription.map(SubscriptionServerProof::to),
            server_instance_id: self.server_instance_id,
            multi_link_supported: self.multi_link_supported,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionRegistration {
    pub network_code: String,
    pub device_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionRegistration {
    fn to(self) -> proto::SubscriptionRegistration {
        proto::SubscriptionRegistration {
            network_code: self.network_code,
            device_id: self.device_id,
            client_nonce: self.client_nonce,
            client_proof: self.client_proof,
            instance_id: self.instance_id,
            applied_revision: self.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionServerProof {
    pub server_nonce: Vec<u8>,
    pub server_proof: Vec<u8>,
    pub target_revision: u64,
}

impl SubscriptionServerProof {
    fn from(value: proto::SubscriptionServerProof) -> Self {
        Self {
            server_nonce: value.server_nonce,
            server_proof: value.server_proof,
            target_revision: value.target_revision,
        }
    }

    fn to(self) -> proto::SubscriptionServerProof {
        proto::SubscriptionServerProof {
            server_nonce: self.server_nonce,
            server_proof: self.server_proof,
            target_revision: self.target_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigFetchRequest {
    pub join_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionConfigFetchRequest {
    fn to(self) -> proto::SubscriptionConfigFetchRequest {
        proto::SubscriptionConfigFetchRequest {
            join_id: self.join_id,
            client_nonce: self.client_nonce,
            client_proof: self.client_proof,
            instance_id: self.instance_id,
            applied_revision: self.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionRegisterRequest {
    pub join_id: String,
    pub client_nonce: Vec<u8>,
    pub client_proof: Vec<u8>,
    pub instance_id: Vec<u8>,
    pub applied_revision: u64,
}

impl SubscriptionRegisterRequest {
    fn to(self) -> proto::SubscriptionRegisterRequest {
        proto::SubscriptionRegisterRequest {
            join_id: self.join_id,
            client_nonce: self.client_nonce,
            client_proof: self.client_proof,
            instance_id: self.instance_id,
            applied_revision: self.applied_revision,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SubscriptionPing {
    pub nonce: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigEnvelope {
    pub revision: u64,
    pub toml: String,
    pub managed_ip: Ipv4Addr,
    pub managed_prefix_len: u8,
    pub managed_device_name: String,
    pub server_proof: SubscriptionServerProof,
    pub network_code: String,
    pub device_id: String,
    pub source_server_id: String,
    pub content_sha256: Vec<u8>,
}

impl SubscriptionConfigEnvelope {
    pub fn from_slice(buf: &[u8]) -> anyhow::Result<Self> {
        Self::from(proto::SubscriptionConfigEnvelope::decode(buf)?)
    }
    fn from(msg: proto::SubscriptionConfigEnvelope) -> anyhow::Result<Self> {
        let config = msg
            .config
            .ok_or_else(|| anyhow::anyhow!("subscription config is missing"))?;
        Ok(Self {
            revision: msg.revision,
            toml: config.toml,
            managed_ip: Ipv4Addr::from(config.managed_ip),
            managed_prefix_len: config
                .managed_prefix_len
                .try_into()
                .map_err(|_| anyhow::anyhow!("subscription managed prefix is invalid"))?,
            managed_device_name: config.managed_device_name,
            server_proof: SubscriptionServerProof::from(
                msg.server_proof
                    .ok_or_else(|| anyhow::anyhow!("subscription server proof is missing"))?,
            ),
            network_code: msg.network_code,
            device_id: msg.device_id,
            source_server_id: msg.source_server_id,
            content_sha256: msg.content_sha256,
        })
    }
    fn to(self) -> proto::SubscriptionConfigEnvelope {
        proto::SubscriptionConfigEnvelope {
            revision: self.revision,
            config: Some(proto::SubscriptionConfigV1 {
                toml: self.toml,
                managed_ip: u32::from(self.managed_ip),
                managed_prefix_len: self.managed_prefix_len.into(),
                managed_device_name: self.managed_device_name,
            }),
            server_proof: Some(self.server_proof.to()),
            network_code: self.network_code,
            device_id: self.device_id,
            source_server_id: self.source_server_id,
            content_sha256: self.content_sha256,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SubscriptionConfigAck {
    pub revision: u64,
    pub status: SubscriptionConfigApplyStatus,
    pub error: String,
    pub overridden_fields: Vec<String>,
    pub apply_mode: String,
    pub changed_fields: Vec<String>,
    pub effective_device_name: String,
    pub effective_ip: Ipv4Addr,
    pub effective_prefix_len: u32,
    pub effective_output: Vec<Ipv4Net>,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub allow_mapping: bool,
    pub effective_config_sha256: Vec<u8>,
}

impl SubscriptionConfigAck {
    pub fn new(
        revision: u64,
        status: SubscriptionConfigApplyStatus,
        error: String,
        overridden_fields: Vec<String>,
    ) -> Self {
        Self {
            revision,
            status,
            error,
            overridden_fields,
            apply_mode: String::new(),
            changed_fields: Vec::new(),
            effective_device_name: String::new(),
            effective_ip: Ipv4Addr::UNSPECIFIED,
            effective_prefix_len: 0,
            effective_output: Vec::new(),
            allow_ikev2: false,
            allow_wireguard: false,
            allow_mapping: false,
            effective_config_sha256: Vec::new(),
        }
    }

    fn to(self) -> proto::SubscriptionConfigAck {
        proto::SubscriptionConfigAck {
            revision: self.revision,
            status: self.status as i32,
            error: self.error,
            overridden_fields: self.overridden_fields,
            apply_mode: self.apply_mode,
            changed_fields: self.changed_fields,
            effective_device_name: self.effective_device_name,
            effective_ip: self.effective_ip.into(),
            effective_prefix_len: self.effective_prefix_len,
            effective_output: self
                .effective_output
                .into_iter()
                .map(ipv4_subnet_to_proto)
                .collect(),
            allow_ikev2: self.allow_ikev2,
            allow_wireguard: self.allow_wireguard,
            allow_mapping: self.allow_mapping,
            effective_config_sha256: self.effective_config_sha256,
        }
    }

    pub fn encode(self) -> BytesMut {
        self.to().encode_bytes_mut()
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
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    FastReg(FastRegRequestMsg),
    SubscriptionConfig(SubscriptionConfigFetchRequest),
    SubscriptionRegister(SubscriptionRegisterRequest),
    /// 编码路径保留：订阅配置回执的线协议类型。当前的回执流程改为
    /// 注册请求携带 applied_revision，客户端不再主动发送该消息。
    #[allow(dead_code)]
    SubscriptionAck(SubscriptionConfigAck),
    SubscriptionPing(SubscriptionPing),
}
impl RequestMessage {
    pub fn encode(self) -> BytesMut {
        let request_payload = match self {
            RequestMessage::Reg(reg) => RequestPayload::Reg(reg.to()),
            RequestMessage::FastReg(fast_reg) => RequestPayload::FastReg(fast_reg.to()),
            RequestMessage::SubscriptionConfig(request) => {
                RequestPayload::SubscriptionConfig(request.to())
            }
            RequestMessage::SubscriptionRegister(request) => {
                RequestPayload::SubscriptionRegister(request.to())
            }
            RequestMessage::SubscriptionAck(ack) => RequestPayload::SubscriptionAck(ack.to()),
            RequestMessage::SubscriptionPing(ping) => {
                RequestPayload::SubscriptionPing(proto::SubscriptionPing { nonce: ping.nonce })
            }
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
    SubscriptionConfig(SubscriptionConfigEnvelope),
    SubscriptionRegister(SubscriptionConfigEnvelope),
    SubscriptionPush(SubscriptionConfigEnvelope),
    SubscriptionPong(SubscriptionPing),
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
            ResponsePayload::SubscriptionConfig(config) => Ok(ResponseMessage::SubscriptionConfig(
                SubscriptionConfigEnvelope::from(config)?,
            )),
            ResponsePayload::SubscriptionRegister(response) => {
                let config = response.config.ok_or_else(|| {
                    anyhow::anyhow!("subscription registration response is missing config")
                })?;
                Ok(ResponseMessage::SubscriptionRegister(
                    SubscriptionConfigEnvelope::from(config)?,
                ))
            }
            ResponsePayload::SubscriptionPush(config) => Ok(ResponseMessage::SubscriptionPush(
                SubscriptionConfigEnvelope::from(config)?,
            )),
            ResponsePayload::SubscriptionPong(pong) => {
                Ok(ResponseMessage::SubscriptionPong(SubscriptionPing {
                    nonce: pong.nonce,
                }))
            }
        }
    }
    pub fn encode(self) -> BytesMut {
        let response_payload = match self {
            ResponseMessage::Reg(reg) => ResponsePayload::Reg(reg.to()),
            ResponseMessage::Error(e) => ResponsePayload::Error(e.to()),
            ResponseMessage::ConfirmReg(c) => ResponsePayload::ConfirmReg(c.to()),
            ResponseMessage::FastReg(fast_reg) => ResponsePayload::FastReg(fast_reg.to()),
            ResponseMessage::SubscriptionConfig(config) => {
                ResponsePayload::SubscriptionConfig(config.to())
            }
            ResponseMessage::SubscriptionRegister(config) => {
                ResponsePayload::SubscriptionRegister(proto::SubscriptionRegisterResponse {
                    config: Some(config.to()),
                })
            }
            ResponseMessage::SubscriptionPush(config) => {
                ResponsePayload::SubscriptionPush(config.to())
            }
            ResponseMessage::SubscriptionPong(pong) => {
                ResponsePayload::SubscriptionPong(proto::SubscriptionPong { nonce: pong.nonce })
            }
        };
        proto::ResponseMessage {
            response_payload: Some(response_payload),
        }
        .encode_bytes_mut()
    }
}

impl SelectiveBroadcast {
    pub fn new(ips: &[Ipv4Addr], data: Bytes) -> Self {
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
    pub client_type: ClientType,
}
impl ClientSimpleInfo {
    pub fn from(msg: proto::ClientSimpleInfo) -> anyhow::Result<Self> {
        Ok(Self {
            ip: msg.ip.into(),
            online: msg.online,
            client_type: msg.client_type(),
        })
    }
    pub fn to(self) -> proto::ClientSimpleInfo {
        proto::ClientSimpleInfo {
            ip: self.ip.into(),
            online: self.online,
            client_type: self.client_type as i32,
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
    fn subscription_envelope_round_trips_device_table_metadata() {
        let envelope = SubscriptionConfigEnvelope {
            revision: 7,
            toml: "compress = true\n".to_string(),
            managed_ip: Ipv4Addr::new(10, 26, 0, 9),
            managed_prefix_len: 24,
            managed_device_name: "managed-node".to_string(),
            server_proof: SubscriptionServerProof {
                server_nonce: vec![1; 32],
                server_proof: vec![2; 32],
                target_revision: 7,
            },
            network_code: "network".to_string(),
            device_id: "device".to_string(),
            source_server_id: "server".to_string(),
            content_sha256: vec![3; 32],
        };
        let encoded = ResponseMessage::SubscriptionConfig(envelope.clone()).encode();
        let ResponseMessage::SubscriptionConfig(decoded) =
            ResponseMessage::from_slice(encoded.as_ref()).unwrap()
        else {
            panic!("expected subscription config");
        };
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn subscription_control_messages_use_dedicated_variants() {
        let register = SubscriptionRegisterRequest {
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            client_nonce: vec![1; 32],
            client_proof: vec![2; 32],
            instance_id: vec![3; 32],
            applied_revision: 4,
        };
        let encoded = RequestMessage::SubscriptionRegister(register).encode();
        let request = proto::RequestMessage::decode(encoded.as_ref()).unwrap();
        assert!(matches!(
            request.request_payload,
            Some(RequestPayload::SubscriptionRegister(_))
        ));

        let ping = ResponseMessage::SubscriptionPong(SubscriptionPing { nonce: 9 });
        assert_eq!(
            ResponseMessage::from_slice(ping.clone().encode().as_ref()).unwrap(),
            ping
        );
    }

    #[test]
    fn selective_broadcast_keeps_payload_reference_counted() {
        let data = bytes::Bytes::from_static(b"inner packet");
        let original_ptr = data.as_ptr();
        let message = SelectiveBroadcast::new(&[Ipv4Addr::new(10, 0, 0, 2)], data);
        assert_eq!(message.data.as_ptr(), original_ptr);

        let encoded = message.encode_bytes_mut().freeze();
        let start = encoded.as_ptr() as usize;
        let end = start + encoded.len();
        let decoded = SelectiveBroadcast::decode(encoded).unwrap();
        let decoded_ptr = decoded.data.as_ptr() as usize;
        assert!(decoded_ptr >= start && decoded_ptr < end);
        assert_eq!(decoded.data.as_ref(), b"inner packet");
    }

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
            allow_ikev2: false,
            allow_wireguard: false,
            subscription: None,
            client_instance_id: vec![1; 32],
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
            subscription_config_supported: true,
            subscription: None,
            server_instance_id: vec![2; 32],
            multi_link_supported: true,
        })
        .encode();
        let ResponseMessage::Reg(response) = ResponseMessage::from_slice(encoded.as_ref()).unwrap()
        else {
            panic!("expected registration response");
        };
        assert!(response.subnet_sync_supported);
        assert_eq!(response.server_instance_id, vec![2; 32]);
        assert!(response.multi_link_supported);

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

    #[test]
    fn relay_capabilities_and_client_types_round_trip() {
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
            advertised_subnets: Vec::new(),
            allow_ikev2: true,
            allow_wireguard: true,
            subscription: None,
            client_instance_id: vec![1; 32],
        })
        .encode();
        let request = proto::RequestMessage::decode(encoded.as_ref()).unwrap();
        let RequestPayload::Reg(request) = request.request_payload.unwrap() else {
            panic!("expected registration request");
        };
        assert!(request.allow_ikev2);
        assert!(request.allow_wireguard);

        let list = proto::ClientSimpleInfoList {
            data_version: 1,
            list: vec![
                proto::ClientSimpleInfo {
                    ip: Ipv4Addr::new(10, 26, 0, 8).into(),
                    online: true,
                    client_type: proto::ClientType::Ikev2 as i32,
                },
                proto::ClientSimpleInfo {
                    ip: Ipv4Addr::new(10, 26, 0, 9).into(),
                    online: true,
                    client_type: proto::ClientType::Wireguard as i32,
                },
            ],
            is_all: true,
            time: 0,
        }
        .encode_to_vec();
        let decoded = ClientSimpleInfoList::from_slice(&list).unwrap();
        assert_eq!(decoded.list[0].client_type, ClientType::Ikev2);
        assert_eq!(decoded.list[1].client_type, ClientType::Wireguard);
    }
}
