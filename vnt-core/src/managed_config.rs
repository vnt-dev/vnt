use crate::context::config::{Config, VirtualIp};
use crate::log_manager::InstanceLog;
use crate::protocol::client_message::{NodeIdentityTemplate, SharedNodeIdentity};
use crate::protocol::control_message::{
    RequestMessage, ResponseMessage, SubscriptionConfigAck, SubscriptionConfigApplyStatus,
    SubscriptionConfigEnvelope, SubscriptionConfigFetchRequest, SubscriptionPing,
    SubscriptionRegisterRequest,
};
use crate::tls::verifier::CertValidationMode;
use crate::tunnel_core::server::transport::TransportClient;
use crate::tunnel_core::server::transport::config::{ConnectRegConfig, ProtocolAddress};
use anyhow::{Context, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use parking_lot::Mutex;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

pub const SUBSCRIPTION_PREFIX: &str = "vnt2://join/2/";
/// 订阅链接中 join_id 的长度上限（UUID 规范字符串为 36 字符）
const MAX_JOIN_ID_LEN: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
struct SubscriptionPayloadV2 {
    v: u8,
    server: String,
    cert_mode: String,
    join_id: String,
    credential_key: String,
}

#[derive(Clone)]
pub struct Subscription {
    pub server: String,
    pub cert_mode: String,
    /// 服务端签发的设备唯一订阅接入 ID。身份字段（network_code/device_id）
    /// 不在链接中，认证成功后由服务端信封下发。
    pub join_id: String,
    credential_key: Vec<u8>,
    instance_id: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SubscriptionConnectionStatus {
    Connecting,
    Connected,
    Reconnecting,
    Closed,
}

/// A pull-based listener for one long-lived subscription control connection.
/// It deliberately has no reference to a network instance and never invokes
/// user callbacks. Every authenticated configuration is published directly as
/// the latest `Config`; layering local settings on top is left to callers.
pub(crate) struct SubscriptionListener {
    config_rx: watch::Receiver<Option<EnvelopeConfig>>,
    cancellation: CancellationToken,
    worker: Option<tokio::task::JoinHandle<()>>,
}

impl SubscriptionListener {
    pub(crate) fn new(subscription: Subscription) -> Self {
        let (config_tx, config_rx) = watch::channel(None);
        let cancellation = CancellationToken::new();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::spawn(async move {
            subscription_listener_task(
                subscription,
                config_tx,
                worker_cancellation,
                Arc::new(InstanceLog::new("subscription")),
            )
            .await;
        });
        Self {
            config_rx,
            cancellation,
            worker: Some(worker),
        }
    }

    /// Returns the latest configuration received from the subscription
    /// server, waiting for the first one when it has not arrived yet.
    pub(crate) async fn current_config(&mut self) -> anyhow::Result<EnvelopeConfig> {
        loop {
            if let Some(config) = self.config_rx.borrow().as_ref() {
                return Ok(config.clone());
            }
            self.config_rx
                .changed()
                .await
                .context("subscription source closed before initial config")?;
        }
    }

    /// 非阻塞地读取最新已收到的信封；首份尚未到达时返回 None。
    pub(crate) fn current_config_now(&self) -> Option<EnvelopeConfig> {
        self.config_rx.borrow().clone()
    }

    /// Waits until the subscription server publishes a configuration, then
    /// returns the latest one.
    pub(crate) async fn changed(&mut self) -> anyhow::Result<EnvelopeConfig> {
        loop {
            self.config_rx
                .changed()
                .await
                .context("subscription source closed")?;
            if let Some(config) = self.config_rx.borrow().as_ref() {
                return Ok(config.clone());
            }
        }
    }
}

impl Drop for SubscriptionListener {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Subscription")
            .field("server", &self.server)
            .field("cert_mode", &self.cert_mode)
            .field("join_id", &self.join_id)
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
        let payload: SubscriptionPayloadV2 = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(encoded)
                .context("订阅链接 Base64URL 载荷无效")?,
        )
        .context("订阅链接 JSON 载荷无效")?;
        if payload.v != 2 {
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
        if payload.join_id.is_empty() || payload.join_id.len() > MAX_JOIN_ID_LEN {
            bail!("订阅链接接入 ID 无效");
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
            join_id: payload.join_id,
            credential_key,
            instance_id: random_nonce(),
        })
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
                network_code: self.join_id.clone(),
                device_id: self.join_id.clone(),
                identity: SharedNodeIdentity::new(NodeIdentityTemplate {
                    name: self.join_id.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    network_code: self.join_id.clone(),
                    advertised_subnets: Vec::new(),
                }),
                ip: crate::context::SharedNetworkAddr::default(),
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
                            join_id: self.join_id.clone(),
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

async fn subscription_listener_task(
    subscription: Subscription,
    config_tx: watch::Sender<Option<EnvelopeConfig>>,
    cancellation: CancellationToken,
    log: Arc<InstanceLog>,
) {
    // Last authenticated revision handed to this listener. It is reported to
    // the server on every (re)connect as the applied revision, so the current
    // configuration is not pushed again after a reconnect.
    let acknowledged_revision = Mutex::new(0_u64);
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let result = run_subscription_connection(
            &subscription,
            &acknowledged_revision,
            &config_tx,
            &cancellation,
            &log,
        )
        .await;
        if cancellation.is_cancelled() {
            break;
        }
        if let Err(error) = result {
            log::warn!("subscription control connection closed: {error:#}");
            log.warn(format!("订阅控制连接关闭: {error:#}"));
        }
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

async fn run_subscription_connection(
    subscription: &Subscription,
    acknowledged_revision: &Mutex<u64>,
    config_tx: &watch::Sender<Option<EnvelopeConfig>>,
    cancellation: &CancellationToken,
    log: &InstanceLog,
) -> anyhow::Result<()> {
    let cert_mode =
        CertValidationMode::from_str(&subscription.cert_mode).map_err(anyhow::Error::msg)?;
    let server_addr =
        ProtocolAddress::from_str(&subscription.server).map_err(anyhow::Error::msg)?;
    let resolver = ConnectRegConfig {
        server_addr,
        cert_mode,
        network_code: subscription.join_id.clone(),
        device_id: subscription.join_id.clone(),
        identity: SharedNodeIdentity::new(NodeIdentityTemplate {
            name: subscription.join_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            network_code: subscription.join_id.clone(),
            advertised_subnets: Vec::new(),
        }),
        ip: crate::context::SharedNetworkAddr::default(),
        key_sign: None,
        ip_variable: true,
        allow_ikev2: false,
        allow_wireguard: false,
        default_interface: None,
        managed: None,
        client_instance_id: Arc::new(random_nonce()),
    };
    let configs = resolver.to_connect_config().await?;
    let mut last_error = None;
    for config in configs {
        let mut transport = TransportClient::new();
        // 身份从本连接第一份已认证信封学得，后续信封必须一致
        let mut learned_identity: Option<(String, String)> = None;
        let connection = async {
            transport
                .connect_timeout(&config, Duration::from_secs(10))
                .await?;
            let client_nonce = random_nonce();
            // Wire name retained for protocol compatibility. It now means the
            // last authenticated revision received.
            let applied_revision = *acknowledged_revision.lock();
            transport
                .send(
                    RequestMessage::SubscriptionRegister(SubscriptionRegisterRequest {
                        join_id: subscription.join_id.clone(),
                        client_proof: client_proof(
                            &subscription.credential_key,
                            &client_nonce,
                        ),
                        client_nonce: client_nonce.clone(),
                        instance_id: subscription.instance_id.clone(),
                        applied_revision,
                    })
                    .encode()
                    .freeze(),
                )
                .await?;
            let response = transport.next_timeout(Duration::from_secs(10)).await?;
            let initial = match ResponseMessage::from_slice(&response)? {
                ResponseMessage::SubscriptionRegister(config) => config,
                ResponseMessage::Error(error) => bail!("{} ({})", error.message, error.code),
                _ => bail!("server returned an unexpected subscription registration response"),
            };
            validate_subscription_envelope(
                &subscription.credential_key,
                &client_nonce,
                &initial,
                &mut learned_identity,
            )?;
            if let Some(revision) =
                accept_subscription_update(initial, config_tx, acknowledged_revision)
            {
                ack_subscription_config(&mut transport, revision).await?;
            }
            log.info("订阅连接已建立");

            let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_received = tokio::time::Instant::now();
            let mut nonce = 0_u64;
            loop {
                tokio::select! {
                    _ = cancellation.cancelled() => return Ok(()),
                    _ = heartbeat.tick() => {
                        if last_received.elapsed() > Duration::from_secs(45) {
                            bail!("subscription heartbeat timed out");
                        }
                        nonce = nonce.wrapping_add(1);
                        transport.send(
                            RequestMessage::SubscriptionPing(SubscriptionPing { nonce })
                                .encode().freeze(),
                        ).await?;
                    }
                    incoming = transport.next() => {
                        let incoming = incoming?;
                        last_received = tokio::time::Instant::now();
                        match ResponseMessage::from_slice(&incoming)? {
                            ResponseMessage::SubscriptionPush(update) => {
                                validate_subscription_envelope(
                                    &subscription.credential_key,
                                    &client_nonce,
                                    &update,
                                    &mut learned_identity,
                                )?;
                                if let Some(revision) =
                                    accept_subscription_update(update, config_tx, acknowledged_revision)
                                {
                                    ack_subscription_config(&mut transport, revision).await?;
                                }
                            }
                            ResponseMessage::SubscriptionPong(_) => {}
                            ResponseMessage::Error(error) => bail!("{} ({})", error.message, error.code),
                            _ => bail!("unexpected message on subscription control connection"),
                        }
                    }
                }
            }
        }
        .await;
        transport.graceful_disconnect().await;
        match connection {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no subscription endpoint resolved")))
}

/// Publishes one authenticated envelope as the latest configuration. A
/// revision older than the acknowledged one is dropped, so a stale push can
/// never replace a newer configuration. Returns the accepted revision, or
/// `None` when the update was dropped as stale.
/// 订阅信封的解析结果：信封承载的配置 + 信封 TOML 中实际出现的顶层键。
///
/// 合并时以"出现的键"为准覆盖本地配置：服务端设置了某个字段，该字段就由
/// 服务端说话；信封没提的字段保持客户端本地配置。
#[derive(Clone, Debug, Default)]
pub(crate) struct EnvelopeConfig {
    pub config: Config,
    pub present: HashSet<String>,
}

fn accept_subscription_update(
    update: SubscriptionConfigEnvelope,
    config_tx: &watch::Sender<Option<EnvelopeConfig>>,
    acknowledged_revision: &Mutex<u64>,
) -> Option<u64> {
    {
        let mut acknowledged = acknowledged_revision.lock();
        if update.revision < *acknowledged {
            return None;
        }
        *acknowledged = update.revision;
    }
    let revision = update.revision;
    let envelope = parse_envelope_config(&update);
    config_tx.send_replace(Some(envelope));
    Some(revision)
}

/// 解析信封 TOML 为完整配置 + 出现键集合。身份与受管 IP 来自信封元数据，
/// 其余字段来自信封 TOML：能解析的按值填入，解析失败记警告并留空（合并时
/// 未出现的键不会覆盖本地配置，出现但解析失败的字段等同于未设置）。
fn parse_envelope_config(update: &SubscriptionConfigEnvelope) -> EnvelopeConfig {
    let table = toml::from_str::<toml::Table>(&update.toml).unwrap_or_else(|error| {
        log::warn!("订阅信封配置不是合法 TOML，仅使用其中的身份与 IP 字段: {error}");
        toml::Table::new()
    });
    let present: HashSet<String> = table.keys().cloned().collect();
    let config = Config {
        network_code: update.network_code.clone(),
        device_id: update.device_id.clone(),
        device_name: update.managed_device_name.clone(),
        ip: VirtualIp::new(update.managed_ip, update.managed_prefix_len).ok(),
        // 服务端下发的流量服务器（信封 TOML 的 server 字段）：
        // 管理端可热切换中继服务器，解析失败时退回本地配置
        server_addr: parse_envelope_servers(&table),
        mtu: parse_envelope_u16(&table, "mtu"),
        tun_name: parse_envelope_string(&table, "tun_name").filter(|name| !name.is_empty()),
        // 策略类字段：出现即可由 apply_policy_change 热应用
        compress: parse_envelope_bool(&table, "compress"),
        rtx: parse_envelope_bool(&table, "rtx"),
        fec: parse_envelope_bool(&table, "fec"),
        no_punch: parse_envelope_bool(&table, "no_punch"),
        no_nat: parse_envelope_bool(&table, "no_nat"),
        no_broadcast: parse_envelope_bool(&table, "no_broadcast"),
        auto_sync_subnet: parse_envelope_bool(&table, "auto_sync_subnet"),
        allow_port_mapping: parse_envelope_bool(&table, "allow_port_mapping"),
        allow_ikev2: parse_envelope_bool(&table, "allow_ikev2"),
        allow_wireguard: parse_envelope_bool(&table, "allow_wireguard"),
        peer_address: parse_typed_list(&table, "peer_address"),
        turn: parse_typed_list(&table, "turn"),
        punch_model: parse_typed_list(&table, "punch_model"),
        udp_stun: parse_envelope_string_list(&table, "udp_stun"),
        tcp_stun: parse_envelope_string_list(&table, "tcp_stun"),
        input: parse_typed_list(&table, "input"),
        // 重建类字段：出现即触发实例重建（密码/证书/出口网卡/隧道监听/
        // 设备模式/映射表）。event_script 服务端禁止下发，保持本地配置
        password: parse_envelope_string(&table, "password").filter(|value| !value.is_empty()),
        cert_mode: parse_typed(&table, "cert_mode").unwrap_or_default(),
        outbound_interface: parse_envelope_string(&table, "outbound_interface")
            .filter(|value| !value.is_empty()),
        tunnel_addr: parse_typed_list(&table, "tunnel_addr"),
        tunnel_port: parse_envelope_u16(&table, "tunnel_port"),
        device_mode: parse_typed(&table, "device_mode").unwrap_or_default(),
        port_mapping: parse_typed_list(&table, "port_mapping"),
        subnet_mapping: parse_typed_list(&table, "subnet_mapping"),
        output: parse_typed_list(&table, "output"),
        ..Config::default()
    };
    EnvelopeConfig { config, present }
}

/// 解析信封中的单个枚举/地址类字段，缺失或非法时返回 None。
fn parse_typed<T: std::str::FromStr>(table: &toml::Table, key: &str) -> Option<T> {
    let value = table.get(key).and_then(toml::Value::as_str)?;
    match value.parse() {
        Ok(parsed) => Some(parsed),
        Err(_) => {
            log::warn!("订阅信封中的 {key} '{value}' 无效");
            None
        }
    }
}

/// 解析信封中的字符串数组类字段，逐项 FromStr，跳过非法项。
fn parse_typed_list<T: std::str::FromStr>(table: &toml::Table, key: &str) -> Vec<T> {
    parse_envelope_string_list(table, key)
        .iter()
        .filter_map(|value| match value.parse() {
            Ok(parsed) => Some(parsed),
            Err(_) => {
                log::warn!("订阅信封中的 {key} '{value}' 无效");
                None
            }
        })
        .collect()
}

fn parse_envelope_string(table: &toml::Table, key: &str) -> Option<String> {
    table.get(key).and_then(toml::Value::as_str).map(str::to_string)
}

fn parse_envelope_bool(table: &toml::Table, key: &str) -> bool {
    table.get(key).and_then(toml::Value::as_bool).unwrap_or(false)
}

fn parse_envelope_u16(table: &toml::Table, key: &str) -> Option<u16> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .and_then(|value| u16::try_from(value).ok())
}

fn parse_envelope_string_list(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// 解析订阅信封 TOML 中的流量服务器列表。无法解析或字段缺失时返回空列表
/// （调用方以本地配置兜底）。
fn parse_envelope_servers(table: &toml::Table) -> Vec<ProtocolAddress> {
    let Some(servers) = table.get("server").and_then(toml::Value::as_array) else {
        return Vec::new();
    };
    servers
        .iter()
        .filter_map(|server| {
            let server = server.as_str()?;
            match server.parse() {
                Ok(address) => Some(address),
                Err(error) => {
                    log::warn!("订阅信封中的服务器地址 '{server}' 无效: {error}");
                    None
                }
            }
        })
        .collect()
}

/// 回执一条已接收并发布的配置：服务端据此把设备的同步状态推进到
/// “已应用”。扩展运行时元数据（effective_* 字段）不在监听器职责内，
/// 发送最小回执；发送失败由调用方按连接错误处理，重连时注册请求会
/// 携带 applied_revision 兜底。
async fn ack_subscription_config(
    transport: &mut TransportClient,
    revision: u64,
) -> anyhow::Result<()> {
    let ack = SubscriptionConfigAck::new(
        revision,
        SubscriptionConfigApplyStatus::SubscriptionConfigApplied,
        String::new(),
        Vec::new(),
    );
    transport
        .send(RequestMessage::SubscriptionAck(ack).encode().freeze())
        .await
}

/// 校验一份订阅信封。链接只携带 join_id，身份（network_code/device_id）由
/// 服务端在认证成功后下发：第一份信封学得身份并记录，同一连接上后续信封
/// 必须与学到的身份一致，否则判定为服务端异常并断开。
fn validate_subscription_envelope(
    credential_key: &[u8],
    client_nonce: &[u8],
    config: &SubscriptionConfigEnvelope,
    learned_identity: &mut Option<(String, String)>,
) -> anyhow::Result<()> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(config.toml.as_bytes());
    hasher.update(config.managed_ip.octets());
    hasher.update([config.managed_prefix_len]);
    hasher.update(config.managed_device_name.as_bytes());
    if config.content_sha256.as_slice() != hasher.finalize().as_slice() {
        bail!("subscription server returned a mismatched config hash");
    }
    // 先验证明：未通过认证的信封不透露任何身份信息
    if !verify_server_proof(
        credential_key,
        client_nonce,
        &config.server_proof.server_nonce,
        &config.server_proof.server_proof,
    ) {
        bail!("subscription server proof is invalid");
    }
    match learned_identity {
        Some((network_code, device_id)) => {
            if config.network_code != *network_code || config.device_id != *device_id {
                bail!("subscription server returned a mismatched managed identity");
            }
        }
        None => {
            *learned_identity = Some((config.network_code.clone(), config.device_id.clone()));
        }
    }
    Ok(())
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

    fn envelope(revision: u64) -> SubscriptionConfigEnvelope {
        SubscriptionConfigEnvelope {
            revision,
            toml: "not valid toml = [".to_string(),
            managed_ip: "10.26.0.2".parse().unwrap(),
            managed_prefix_len: 24,
            managed_device_name: "device".to_string(),
            server_proof: crate::protocol::control_message::SubscriptionServerProof {
                server_nonce: Vec::new(),
                server_proof: Vec::new(),
                target_revision: revision,
            },
            network_code: "network".to_string(),
            device_id: "device".to_string(),
            source_server_id: "server".to_string(),
            content_sha256: Vec::new(),
        }
    }

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
        let payload = SubscriptionPayloadV2 {
            v: 2,
            server: "tcp://127.0.0.1:29872".into(),
            cert_mode: "skip".into(),
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            credential_key: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        };
        let link = format!(
            "{SUBSCRIPTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        assert!(Subscription::parse(&link).is_err());
    }

    #[test]
    fn rejects_legacy_v1_link_with_identity_fields() {
        let payload = SubscriptionPayloadV2 {
            v: 1,
            server: "tcp://127.0.0.1:29872".into(),
            cert_mode: "standard".into(),
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            credential_key: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        };
        let link = format!(
            "{SUBSCRIPTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let error = Subscription::parse(&link).unwrap_err();
        assert!(error.to_string().contains("不支持的订阅链接版本"));
    }

    #[test]
    fn parses_v2_link_without_local_identity_fields() {
        let payload = SubscriptionPayloadV2 {
            v: 2,
            server: "tcp://127.0.0.1:29872".into(),
            cert_mode: "standard".into(),
            join_id: "11111111-2222-3333-4444-555555555555".into(),
            credential_key: URL_SAFE_NO_PAD.encode([7_u8; 32]),
        };
        let link = format!(
            "{SUBSCRIPTION_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let subscription = Subscription::parse(&link).unwrap();
        assert_eq!(subscription.join_id, payload.join_id);
        assert_eq!(subscription.server, "tcp://127.0.0.1:29872");
    }

    /// 构造内容哈希与服务端证明都合法的信封。
    fn authenticated_envelope(
        credential_key: &[u8],
        client_nonce: &[u8],
        network_code: &str,
        device_id: &str,
    ) -> SubscriptionConfigEnvelope {
        let mut config = envelope(1);
        config.network_code = network_code.to_string();
        config.device_id = device_id.to_string();
        let mut hasher = sha2::Sha256::new();
        hasher.update(config.toml.as_bytes());
        hasher.update(config.managed_ip.octets());
        hasher.update([config.managed_prefix_len]);
        hasher.update(config.managed_device_name.as_bytes());
        config.content_sha256 = hasher.finalize().to_vec();
        let server_nonce = random_nonce();
        config.server_proof = crate::protocol::control_message::SubscriptionServerProof {
            server_proof: server_proof(credential_key, client_nonce, &server_nonce),
            server_nonce,
            target_revision: 1,
        };
        config
    }

    #[test]
    fn envelope_identity_is_learned_from_the_first_authenticated_config() {
        let key = [7_u8; 32];
        let client_nonce = [8_u8; 32];
        let config = authenticated_envelope(&key, &client_nonce, "managed-net", "managed-dev");
        let mut learned = None;
        validate_subscription_envelope(&key, &client_nonce, &config, &mut learned).unwrap();
        assert_eq!(
            learned,
            Some(("managed-net".to_string(), "managed-dev".to_string()))
        );

        // 同一连接上的后续信封必须与学到的身份一致
        let mut drifted = authenticated_envelope(&key, &client_nonce, "other-net", "managed-dev");
        drifted.revision = 2;
        assert!(validate_subscription_envelope(&key, &client_nonce, &drifted, &mut learned).is_err());
    }

    #[test]
    fn envelope_rejects_forged_server_proof() {
        let key = [7_u8; 32];
        let client_nonce = [8_u8; 32];
        let mut config = authenticated_envelope(&key, &client_nonce, "managed-net", "managed-dev");
        config.server_proof.server_proof[0] ^= 1;
        let mut learned = None;
        assert!(validate_subscription_envelope(&key, &client_nonce, &config, &mut learned).is_err());
        assert!(learned.is_none());
    }

    #[test]
    fn authenticated_config_is_published_as_the_latest_config() {
        let (latest, receiver) = watch::channel(None);
        let acknowledged = Mutex::new(3);

        assert_eq!(
            accept_subscription_update(envelope(4), &latest, &acknowledged),
            Some(4)
        );

        assert_eq!(*acknowledged.lock(), 4);
        let envelope = receiver.borrow().clone().expect("latest config");
        let config = &envelope.config;
        assert_eq!(config.network_code, "network");
        assert_eq!(config.device_id, "device");
        assert_eq!(config.device_name, "device");
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/24");
    }

    #[test]
    fn stale_revision_never_replaces_the_latest_config() {
        let (latest, receiver) = watch::channel(None);
        let acknowledged = Mutex::new(4);

        assert_eq!(
            accept_subscription_update(envelope(3), &latest, &acknowledged),
            None
        );

        assert_eq!(*acknowledged.lock(), 4);
        assert!(receiver.borrow().is_none());
    }
}
