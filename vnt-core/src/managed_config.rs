use crate::protocol::client_message::{NodeIdentityTemplate, SharedNodeIdentity};
use crate::protocol::control_message::{
    RequestMessage, ResponseMessage, SubscriptionConfigEnvelope, SubscriptionConfigFetchRequest,
};
use crate::tls::verifier::CertValidationMode;
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::{
    ConnectRegConfig, ProtocolAddress, SharedRegistrationIp,
};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::str::FromStr;
use std::time::Duration;

pub const SUBSCRIPTION_PREFIX: &str = "vnt2://join/1/";

#[derive(Clone, Serialize, Deserialize)]
struct SubscriptionPayloadV1 {
    v: u8,
    server: String,
    cert_mode: String,
    network_code: String,
    device_id: String,
    credential_key: String,
}

#[derive(Clone)]
pub struct Subscription {
    pub server: String,
    pub cert_mode: String,
    pub network_code: String,
    pub device_id: String,
    credential_key: Vec<u8>,
    instance_id: Vec<u8>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subscription")
            .field("server", &self.server)
            .field("cert_mode", &self.cert_mode)
            .field("network_code", &self.network_code)
            .field("device_id", &self.device_id)
            .field("credential_key", &"[REDACTED]")
            .finish()
    }
}

impl Subscription {
    pub fn set_instance_id(&mut self, instance_id: Vec<u8>) -> anyhow::Result<()> {
        if instance_id.len() != 32 {
            bail!("订阅链接任务实例 ID 长度无效");
        }
        self.instance_id = instance_id;
        Ok(())
    }

    pub fn parse(value: &str) -> anyhow::Result<Self> {
        let encoded = value
            .trim()
            .strip_prefix(SUBSCRIPTION_PREFIX)
            .context("不是受支持的 VNT2 订阅链接")?;
        let payload: SubscriptionPayloadV1 = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .context("订阅链接 Base64URL 载荷无效")?,
        )
        .context("订阅链接 JSON 载荷无效")?;
        if payload.v != 1 {
            bail!("不支持的订阅链接版本 {}", payload.v);
        }
        if payload.server.is_empty() {
            bail!("订阅链接未包含服务端地址");
        }
        let cert_mode =
            CertValidationMode::from_str(&payload.cert_mode).map_err(anyhow::Error::msg)?;
        if matches!(cert_mode, CertValidationMode::InsecureSkipVerification) {
            bail!("订阅链接接入禁止跳过服务端证书校验");
        }
        let credential_key = URL_SAFE_NO_PAD
            .decode(payload.credential_key)
            .context("订阅链接凭据无效")?;
        if credential_key.len() != 32 {
            bail!("订阅链接凭据长度无效");
        }
        if payload.network_code.is_empty() || payload.device_id.is_empty() {
            bail!("订阅链接设备身份无效");
        }
        let address = ProtocolAddress::from_str(&payload.server).map_err(anyhow::Error::msg)?;
        if matches!(
            address.protocol_type,
            crate::tunnel_core::server::transport::config::ProtocolType::Dynamic
        ) {
            bail!("订阅链接不支持 dynamic:// 地址");
        }
        Ok(Self {
            server: payload.server,
            cert_mode: payload.cert_mode,
            network_code: payload.network_code,
            device_id: payload.device_id,
            credential_key,
            instance_id: random_nonce(),
        })
    }

    pub fn registration(&self, revision: u64) -> crate::context::config::ManagedRegistration {
        crate::context::config::ManagedRegistration::new(
            self.credential_key.clone(),
            self.network_code.clone(),
            self.device_id.clone(),
            self.instance_id.clone(),
            revision,
        )
    }

    pub async fn fetch(&self) -> anyhow::Result<SubscriptionConfigEnvelope> {
        let cert_mode =
            CertValidationMode::from_str(&self.cert_mode).map_err(anyhow::Error::msg)?;
        let mut last_error = None;
        for endpoint in std::iter::once(&self.server) {
            let server_addr = ProtocolAddress::from_str(endpoint).map_err(anyhow::Error::msg)?;
            let resolver = ConnectRegConfig {
                server_addr,
                cert_mode: cert_mode.clone(),
                network_code: self.network_code.clone(),
                device_id: self.device_id.clone(),
                identity: SharedNodeIdentity::new(NodeIdentityTemplate {
                    name: self.device_id.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    network_code: self.network_code.clone(),
                    advertised_subnets: Vec::new(),
                }),
                ip: SharedRegistrationIp::new(None),
                key_sign: None,
                ip_variable: true,
                allow_ikev2: false,
                allow_wireguard: false,
                default_interface: None,
                managed: None,
                client_instance_id: std::sync::Arc::new(random_nonce()),
            };
            let configs = match resolver.to_connect_config().await {
                Ok(value) => value,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            for config in configs {
                let mut transport = TransportClient::new();
                let result = async {
                    transport
                        .connect_timeout(&config, Duration::from_secs(10))
                        .await?;
                    let client_nonce = random_nonce();
                    let request =
                        RequestMessage::SubscriptionConfig(SubscriptionConfigFetchRequest {
                            network_code: self.network_code.clone(),
                            device_id: self.device_id.clone(),
                            client_proof: client_proof(&self.credential_key, &client_nonce),
                            client_nonce: client_nonce.clone(),
                            instance_id: self.instance_id.clone(),
                            applied_revision: 0,
                        })
                        .encode();
                    transport.send(request.freeze()).await?;
                    let response = transport.next_timeout(Duration::from_secs(10)).await?;
                    match ResponseMessage::from_slice(&response)? {
                        ResponseMessage::SubscriptionConfig(config) => {
                            let mut hasher = sha2::Sha256::new();
                            hasher.update(config.toml.as_bytes());
                            hasher.update(config.managed_ip.octets());
                            hasher.update([config.managed_prefix_len]);
                            hasher.update(config.managed_device_name.as_bytes());
                            let actual_hash = hasher.finalize();
                            if config.content_sha256.as_slice() != actual_hash.as_slice() {
                                bail!("订阅链接服务端返回的配置内容哈希不匹配");
                            }
                            if config.network_code != self.network_code
                                || config.device_id != self.device_id
                            {
                                bail!("订阅链接服务端返回了不匹配的管理身份");
                            }
                            if !verify_server_proof(
                                &self.credential_key,
                                &client_nonce,
                                &config.server_proof.server_nonce,
                                &config.server_proof.server_proof,
                            ) {
                                bail!("订阅链接服务端凭据校验失败");
                            }
                            Ok(config)
                        }
                        ResponseMessage::Error(error) => {
                            bail!("{} ({})", error.message, error.code)
                        }
                        _ => bail!("服务端不支持订阅链接配置获取协议"),
                    }
                }
                .await;
                transport.graceful_disconnect().await;
                match result {
                    Ok(config) => return Ok(config),
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("没有可用的订阅链接配置服务端")))
    }
}

pub fn random_nonce() -> Vec<u8> {
    let mut nonce = [0_u8; 32];
    rand::rng().fill(&mut nonce);
    nonce.to_vec()
}

pub fn client_proof(credential_key: &[u8], client_nonce: &[u8]) -> Vec<u8> {
    let mut digest = sha2::Sha256::new();
    digest.update(credential_key);
    digest.update([0x01]);
    digest.update(client_nonce);
    digest.finalize().to_vec()
}

pub fn server_proof(credential_key: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut digest = sha2::Sha256::new();
    digest.update(credential_key);
    digest.update([0x02]);
    digest.update(client_nonce);
    digest.update(server_nonce);
    digest.finalize().to_vec()
}

pub fn verify_server_proof(
    credential_key: &[u8],
    client_nonce: &[u8],
    server_nonce: &[u8],
    proof: &[u8],
) -> bool {
    constant_time_eq(
        &server_proof(credential_key, client_nonce, server_nonce),
        proof,
    )
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_separated_proofs_bind_the_server_to_the_client_nonce() {
        let key = [7_u8; 32];
        let client_nonce = [8_u8; 32];
        let other_client_nonce = [9_u8; 32];
        let server_nonce = [10_u8; 32];
        let client = client_proof(&key, &client_nonce);
        let server = server_proof(&key, &client_nonce, &server_nonce);
        assert_ne!(client, server);
        assert!(verify_server_proof(
            &key,
            &client_nonce,
            &server_nonce,
            &server
        ));
        assert!(!verify_server_proof(
            &key,
            &other_client_nonce,
            &server_nonce,
            &server
        ));
    }

    #[test]
    fn rejects_skip_and_wrong_token_length() {
        let payload = SubscriptionPayloadV1 {
            v: 1,
            server: "tcp://127.0.0.1:29872".into(),
            cert_mode: "skip".into(),
            network_code: "net".into(),
            device_id: "dev".into(),
            credential_key: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        };
        let link = format!(
            "{SUBSCRIPTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        assert!(Subscription::parse(&link).is_err());
    }
}
