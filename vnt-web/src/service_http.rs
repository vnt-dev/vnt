use crate::defer;
use anyhow::{Context, anyhow, bail};
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    middleware,
    response::Response,
    routing::{delete, get, post},
};
use ipnet::Ipv4Net;
use mime_guess::from_path;
use parking_lot::Mutex;
use rand::RngExt;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(test)]
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};
use vnt_core::api::VntApi;
use vnt_core::context::config::{
    Config as CoreConfig, DeviceMode, PeerAddress, PunchRule, TurnRule, VirtualIp,
};
use vnt_core::core::DEFAULT_MTU;
use vnt_core::log_manager::{LogEntry, LogManager};
use vnt_core::managed_config::Subscription;
use vnt_core::nat::{NetInput, SubnetMapping};
use vnt_core::network_info::{ChangeOutcome, RuntimeChangeManager, RuntimeEvent};
use vnt_core::utils::task_control::TaskGroupManager;
use vnt_core::port_mapping::PortMapping;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;

const CONFIG_DIR: &str = "vnt_config";
const CURRENT_CONFIG_RECORD: &str = "vnt_current_config.txt";

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "lowercase")]
enum VntStatus {
    #[default]
    Stopped,
    Starting,
    Running,
}

#[derive(Clone)]
struct HttpAppState {
    inner: Arc<Mutex<HttpAppStateInner>>,
    /// 按配置文件名管理的实例日志，每个实例保留最近 50 条
    logs: Arc<LogManager>,
}

#[derive(Default)]
struct HttpAppStateInner {
    /// 组网实例表，key = 配置文件名，同一配置最多一个实例
    instances: HashMap<String, InstanceState>,
    /// Stable for this desktop process, including managed in-process restarts.
    subscription_instance_ids: HashMap<String, Vec<u8>>,
    /// 配置管理器：订阅连接与组网实例的生命周期持有者，跨实例重建保留
    runtime_managers: HashMap<String, Arc<tokio::sync::Mutex<RuntimeChangeManager>>>,
}

#[derive(Default)]
struct InstanceState {
    /// Monotonically increasing runtime incarnation for this config file.
    generation: u64,
    vnt: Option<VntHandler>,
    status: VntStatus,
    /// Cancels subscription fetching before the network startup task exists.
    start_cancellation: CancellationToken,
    /// 启动任务句柄，用于在 Starting 状态中断注册重试循环
    start_handle: Option<tokio::task::JoinHandle<()>>,
    /// 启动时解析出的配置快照，用于多实例启动前冲突检测
    start_config: Option<StartConfig>,
    /// 启动时的本地 TOML 快照。订阅配置的有效运行配置包含远端字段，
    /// 不能直接拿它与只保存本地覆盖项的配置文件比较。
    local_config: Option<toml::Value>,
    /// 展示名；Starting 阶段还没有 vnt，用配置里的 config_name 或 file_name 兜底
    config_name: String,
    /// Serializes server pushes and local override changes for this instance.
    config_apply_lock: Arc<tokio::sync::Mutex<()>>,
    /// 当前生效配置的 TOML 文本快照，由启动与监测循环发布。管理器锁在
    /// 等待运行期事件时被监测循环持有，读取方不能直接去锁管理器。
    config_text: Option<String>,
    /// 实例任务组句柄：停止它即可让实例停机，供不能锁管理器的停止流程
    /// 使用（监测循环在 next_event 等待期间持有管理器锁）。
    task_groups: Option<TaskGroupManager>,
}

impl HttpAppState {
    fn runtime_manager(&self, file_name: &str) -> Option<Arc<tokio::sync::Mutex<RuntimeChangeManager>>> {
        self.inner.lock().runtime_managers.get(file_name).cloned()
    }

    fn install_runtime_manager(
        &self,
        file_name: &str,
        manager: Arc<tokio::sync::Mutex<RuntimeChangeManager>>,
    ) {
        self.inner
            .lock()
            .runtime_managers
            .insert(file_name.to_string(), manager);
    }

    fn take_runtime_manager(
        &self,
        file_name: &str,
    ) -> Option<Arc<tokio::sync::Mutex<RuntimeChangeManager>>> {
        self.inner.lock().runtime_managers.remove(file_name)
    }

    fn subscription_instance_id(&self, file_name: &str) -> Vec<u8> {
        self.inner
            .lock()
            .subscription_instance_ids
            .entry(file_name.to_string())
            .or_insert_with(|| {
                let mut value = vec![0_u8; 32];
                rand::rng().fill(value.as_mut_slice());
                value
            })
            .clone()
    }
    fn starting(&self, file_name: &str) -> anyhow::Result<u64> {
        let mut inner = self.inner.lock();
        let inst = inner.instances.entry(file_name.to_string()).or_default();
        if inst.status != VntStatus::Stopped {
            return Err(anyhow!("配置 {} 正在启动或已运行", file_name));
        }
        if inst.vnt.is_some() {
            return Err(anyhow!("配置 {} 已在运行", file_name));
        }
        inst.generation = inst
            .generation
            .checked_add(1)
            .context("实例 generation 已耗尽")?;
        inst.status = VntStatus::Starting;
        // 每次启动重置实例日志，保证日志只反映当前这次运行
        self.logs.instance(file_name).clear();
        inst.start_cancellation = CancellationToken::new();
        inst.start_config = None;
        inst.local_config = None;
        inst.config_name = file_name.to_string();
        Ok(inst.generation)
    }
    fn cleanup_generation(&self, file_name: &str, generation: u64) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.generation != generation {
            return;
        }
        inst.vnt.take();
        // 启动流程会先释放网络资源，再由外层记录具体的失败原因。
        // 此时保持 Starting，避免实例及其启动日志被提前清理。
        if inst.status == VntStatus::Starting {
            return;
        }
        inst.status = VntStatus::Stopped;
        inst.start_config = None;
        inst.local_config = None;
        // 已完成任务的句柄只是残留，不算运行内容
        if inst.start_handle.as_ref().is_some_and(|h| h.is_finished()) {
            inst.start_handle.take();
        }
        // 实例已无任何运行内容时移除条目，避免实例表堆积已停止的配置。
        // 注意 Starting 失败路径走 record_log_and_stopped/starting_to_stopped 保留日志，
        // 不经过这里，不会被误删。管理器已被摘除即代表组网实例与订阅连接
        // 都已结束。
        let removable =
            inst.start_handle.is_none() && !inner.runtime_managers.contains_key(file_name);
        if removable {
            inner.instances.remove(file_name);
        }
    }
    fn starting_to_stopped(&self, file_name: &str, generation: u64) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.generation != generation {
            return;
        }
        if inst.status != VntStatus::Starting {
            return;
        }
        inst.vnt.take();
        inst.status = VntStatus::Stopped;
        self.logs.instance(file_name).warn("启动中断");
    }
    fn starting_to_running(&self, file_name: &str, generation: u64) -> bool {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return false;
        };
        if inst.generation != generation || inst.status != VntStatus::Starting {
            log::error!("starting_to_running VNT is not starting");
            return false;
        }
        inst.status = VntStatus::Running;
        true
    }

    /// Publishes the local display name before an optional subscription fetch completes.
    fn set_starting_config_name(&self, file_name: &str, generation: u64, config_name: String) {
        if config_name.is_empty() {
            return;
        }
        if let Some(instance) = self
            .inner
            .lock()
            .instances
            .get_mut(file_name)
            .filter(|instance| {
                instance.generation == generation && instance.status == VntStatus::Starting
            })
        {
            instance.config_name = config_name;
        }
    }

    fn record_log(&self, file_name: &str, msg: impl Into<String>) {
        self.logs.instance(file_name).info(msg);
    }

    fn start_cancellation(&self, file_name: &str, generation: u64) -> Option<CancellationToken> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .filter(|instance| {
                instance.generation == generation && instance.status == VntStatus::Starting
            })
            .map(|instance| instance.start_cancellation.clone())
    }
    fn record_log_and_stopped(&self, file_name: &str, generation: u64, msg: impl Into<String>) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.generation != generation || inst.status != VntStatus::Starting {
            return;
        }
        self.logs.instance(file_name).error(msg);
        inst.status = VntStatus::Stopped;
    }

    fn status(&self, file_name: &str) -> VntStatus {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .map(|inst| inst.status)
            .unwrap_or(VntStatus::Stopped)
    }

    #[cfg(test)]
    fn current_generation(&self, file_name: &str) -> Option<u64> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .map(|instance| instance.generation)
    }

    fn api(&self, file_name: &str) -> Option<VntApi> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .and_then(|instance| instance.vnt.as_ref())
            .map(|handler| handler.api.clone())
    }

    fn config_apply_lock(&self, file_name: &str) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .map(|instance| instance.config_apply_lock.clone())
    }

    /// 启动解析出配置后写入展示名和配置快照（供实例列表与冲突检测使用）
    /// 发布实例当前生效配置的文本快照（启动与每次应用变更后调用）。
    fn set_instance_config_text(&self, file_name: &str, text: String) {
        if let Some(inst) = self.inner.lock().instances.get_mut(file_name) {
            inst.config_text = Some(text);
        }
    }

    fn instance_config_text(&self, file_name: &str) -> Option<String> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .and_then(|inst| inst.config_text.clone())
    }

    fn set_instance_task_groups(&self, file_name: &str, groups: TaskGroupManager) {
        if let Some(inst) = self.inner.lock().instances.get_mut(file_name) {
            inst.task_groups = Some(groups);
        }
    }

    fn instance_task_groups(&self, file_name: &str) -> Option<TaskGroupManager> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .and_then(|inst| inst.task_groups.clone())
    }

    fn set_starting_config(
        &self,
        file_name: &str,
        generation: u64,
        config_name: String,
        cfg: StartConfig,
        local_config: toml::Value,
    ) {
        if let Some(inst) = self
            .inner
            .lock()
            .instances
            .get_mut(file_name)
            .filter(|instance| instance.generation == generation)
        {
            inst.config_name = config_name;
            inst.start_config = Some(cfg);
            inst.local_config = Some(local_config);
        }
    }

    fn set_start_handle(
        &self,
        file_name: &str,
        generation: u64,
        handle: tokio::task::JoinHandle<()>,
    ) {
        if let Some(inst) = self
            .inner
            .lock()
            .instances
            .get_mut(file_name)
            .filter(|instance| instance.generation == generation)
        {
            inst.start_handle = Some(handle);
        } else {
            handle.abort();
        }
    }

    /// 中断启动任务（如注册重试循环）。任务已完成时为空操作。
    fn abort_start_task(&self, file_name: &str) {
        let handle = self
            .inner
            .lock()
            .instances
            .get_mut(file_name)
            .and_then(|inst| {
                inst.start_cancellation.cancel();
                inst.start_handle.take()
            });
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    fn abort_start_task_if_generation(&self, file_name: &str, generation: u64) -> bool {
        let handle = {
            let mut inner = self.inner.lock();
            let Some(instance) = inner.instances.get_mut(file_name) else {
                return false;
            };
            if instance.generation != generation {
                return false;
            }
            instance.start_cancellation.cancel();
            instance.start_handle.take()
        };
        if let Some(handle) = handle {
            handle.abort();
        }
        true
    }
}

struct VntHandler {
    api: VntApi,
    config_name: String,
    config_file_name: String,
    /// 启动时的配置快照，用于多实例冲突检测
    start_config: StartConfig,
}

#[derive(Serialize)]
struct ApiResponse<T> {
    code: i32,
    msg: String,
    data: Option<T>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            code: 0,
            msg: "success".to_string(),
            data: Some(data),
        }
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            code: -1,
            msg: msg.into(),
            data: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StartConfig {
    pub config_name: Option<String>,
    /// Optional remote configuration source. The value remains in the user's
    /// TOML; remote configuration is merged in memory and never materialized
    /// back into this file.
    pub subscription: Option<String>,
    #[serde(default)]
    pub server: Vec<String>,
    #[serde(default)]
    pub peer_address: Vec<String>,
    #[serde(default)]
    pub turn: Vec<String>,
    #[serde(default)]
    pub punch_model: Vec<String>,
    pub cert_mode: Option<String>,
    pub network_code: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_name: Option<String>,
    pub outbound_interface: Option<String>,
    pub ip: Option<VirtualIp>,
    pub password: Option<String>,
    #[serde(default)]
    pub no_punch: bool,
    #[serde(default)]
    pub no_broadcast: bool,
    #[serde(default)]
    pub allow_ikev2: bool,
    #[serde(default)]
    pub allow_wireguard: bool,
    #[serde(default)]
    pub compress: bool,
    #[serde(default)]
    pub rtx: bool,
    #[serde(default)]
    pub fec: bool,
    #[serde(default)]
    pub input: Vec<NetInput>,
    #[serde(default)]
    pub subnet_mapping: Vec<SubnetMapping>,
    #[serde(default)]
    pub output: Vec<Ipv4Net>,
    #[serde(default)]
    pub auto_sync_subnet: bool,
    #[serde(default)]
    pub no_nat: bool,
    #[serde(default)]
    pub device_mode: DeviceMode,
    #[serde(default, rename = "no_tun", skip_serializing)]
    pub legacy_no_tun: Option<bool>,
    pub mtu: Option<u16>,
    #[serde(default)]
    pub port_mapping: Vec<String>,
    #[serde(default)]
    pub allow_mapping: bool,
    #[serde(default)]
    pub udp_stun: Vec<String>,
    #[serde(default)]
    pub tcp_stun: Vec<String>,
    #[serde(default)]
    pub tunnel_addr: Vec<SocketAddr>,
    pub tunnel_port: Option<u16>,
    #[serde(default)]
    pub event_script: Option<String>,
}

impl StartConfig {
    /// 本地配置的基础校验：与是否配置服务器无关的部分。
    fn validate_local(&self) -> anyhow::Result<()> {
        if self.legacy_no_tun == Some(true) {
            bail!("configuration key 'no_tun' was removed; use device_mode = \"no|tun|tap\"")
        }
        validate_tunnel_binding(&self.tunnel_addr, self.tunnel_port)?;
        Ok(())
    }

    fn validate(&self) -> anyhow::Result<()> {
        self.validate_local()?;
        if self.server.is_empty() && self.ip.is_none() {
            bail!("未配置服务器时必须指定虚拟 IP")
        }
        if self.server.len() > 1 && self.ip.is_none() {
            bail!("配置多个服务器时必须指定虚拟 IP")
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct SubscriptionStateFile {
    version: u8,
    remote_toml: String,
    target_revision: u64,
    #[serde(default)]
    acknowledged_revision: u64,
    applied_revision: u64,
    last_good_toml: Option<String>,
    #[serde(default)]
    last_good_config: Option<StartConfig>,
    #[serde(default)]
    last_good_content_sha256: Option<Vec<u8>>,
    failed_revision: Option<u64>,
    last_error: Option<String>,
}

impl Default for SubscriptionStateFile {
    fn default() -> Self {
        Self {
            version: 1,
            remote_toml: String::new(),
            target_revision: 0,
            acknowledged_revision: 0,
            applied_revision: 0,
            last_good_toml: None,
            last_good_config: None,
            last_good_content_sha256: None,
            failed_revision: None,
            last_error: None,
        }
    }
}

fn subscription_state_path(file_name: &str) -> PathBuf {
    Path::new(CONFIG_DIR)
        .join(".managed")
        .join(format!("{file_name}.json"))
}

fn load_subscription_state(file_name: &str) -> SubscriptionStateFile {
    let mut state: SubscriptionStateFile = std::fs::read(subscription_state_path(file_name))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    state.acknowledged_revision = state.acknowledged_revision.max(state.applied_revision);
    state
}

/// 订阅身份（network_code, device_id）来自运行中管理器持有的最新订阅信封：
/// 订阅链接只携带服务端签发的 join_id，身份由服务端认证成功后下发。
/// 管理器不存在或首份信封尚未到达时返回空串。
async fn subscription_identity(state: &HttpAppState, file_name: &str) -> (String, String) {
    let Some(manager) = state.runtime_manager(file_name) else {
        return (String::new(), String::new());
    };
    manager.lock().await.managed_identity().unwrap_or_default()
}

/// 解析本地配置并创建配置管理器（订阅模式在此等待服务端首份配置并启动
/// 首个组网实例）。管理器存入实例表，跨组网实例重建保留。
async fn resolve_subscription_config_with_retry(
    state: &HttpAppState,
    file_name: &str,
    local_content: &str,
    cancellation: &CancellationToken,
) -> anyhow::Result<StartConfig> {
    let local: toml::Value = toml::from_str(local_content).context("本地配置 TOML 无效")?;
    let local_table = local.as_table().context("本地配置 TOML 根节点必须是表")?;
    let start_config: StartConfig = toml::from_str(local_content)?;
    let local_core = convert_config(start_config.clone())?;

    // 旧的配置管理器先摘除（Drop 会停止组网实例并断开订阅控制连接）
    if let Some(old) = state.take_runtime_manager(file_name) {
        drop(old);
    }

    let subscription = match local_table.get("subscription") {
        None => None,
        Some(link_value) => {
            let mut link = Subscription::parse(
                link_value
                    .as_str()
                    .context("subscription 必须是字符串")?,
            )?;
            // 稳定的订阅实例 ID：跨进程重启保持服务端视角的身份一致
            link.set_instance_id(state.subscription_instance_id(file_name))?;
            Some(link)
        }
    };

    // 管理器创建即启动首个组网实例；订阅模式内部等待服务端首份配置，
    // 等待期间可取消
    let manager = tokio::select! {
        _ = cancellation.cancelled() => return Err(anyhow!("启动已取消")),
        result = RuntimeChangeManager::new(
            local_core,
            subscription,
            state.logs.instance(file_name),
        ) => result?,
    };
    state.install_runtime_manager(file_name, Arc::new(tokio::sync::Mutex::new(manager)));
    Ok(start_config)
}

#[cfg(test)]
async fn fetch_subscription_until_cancelled<T, Fetch, FetchFuture, Report>(
    cancellation: &CancellationToken,
    retry_delay: Duration,
    mut fetch: Fetch,
    mut report_failure: Report,
) -> anyhow::Result<T>
where
    Fetch: FnMut() -> FetchFuture,
    FetchFuture: Future<Output = anyhow::Result<T>>,
    Report: FnMut(u64, &anyhow::Error),
{
    let mut attempts = 0_u64;
    loop {
        if cancellation.is_cancelled() {
            return Err(anyhow!("启动已取消"));
        }
        let result = tokio::select! {
            _ = cancellation.cancelled() => return Err(anyhow!("启动已取消")),
            result = fetch() => result,
        };
        match result {
            Ok(value) => return Ok(value),
            Err(error) => {
                attempts += 1;
                report_failure(attempts, &error);
                tokio::select! {
                    _ = cancellation.cancelled() => return Err(anyhow!("启动已取消")),
                    _ = tokio::time::sleep(retry_delay) => {},
                }
            }
        }
    }
}

struct ResolvedManagedConfig {
    effective_toml: String,
    config: StartConfig,
    #[cfg_attr(not(test), allow(dead_code))]
    overridden_fields: Vec<String>,
}

fn resolve_effective_managed_config(
    remote_content: &str,
    local_content: &str,
    network_code: &str,
    device_id: &str,
    managed_ip: VirtualIp,
    managed_device_name: String,
) -> anyhow::Result<ResolvedManagedConfig> {
    let mut remote: toml::Value = toml::from_str(remote_content).context("服务端配置 TOML 无效")?;
    let remote_table = remote
        .as_table_mut()
        .context("服务端配置 TOML 根节点必须是表")?;
    for ignored in [
        "network_code",
        "device_id",
        "subscription",
        "event_script",
        "config_name",
        "device_name",
    ] {
        remote_table.remove(ignored);
    }
    let local: toml::Value = toml::from_str(local_content).context("本地配置 TOML 无效")?;
    let local_table = local.as_table().context("本地配置 TOML 根节点必须是表")?;
    for (key, value) in local_table {
        if matches!(
            key.as_str(),
            "subscription" | "network_code" | "device_id" | "ip" | "device_name"
        ) {
            continue;
        }
        remote_table.insert(key.clone(), value.clone());
    }
    remote_table.insert(
        "network_code".to_string(),
        toml::Value::String(network_code.to_string()),
    );
    remote_table.insert(
        "device_id".to_string(),
        toml::Value::String(device_id.to_string()),
    );
    let effective_toml = toml::to_string_pretty(&remote)?;
    let mut config: StartConfig = toml::from_str(&effective_toml)?;
    // Server-owned identity and address are revisioned envelope metadata,
    // never TOML and never local overrides.
    config.ip = Some(managed_ip);
    config.device_name = Some(managed_device_name);
    config.validate()?;
    let overridden_fields = local_override_fields(remote_content, local_content)?;
    Ok(ResolvedManagedConfig {
        effective_toml,
        config,
        overridden_fields,
    })
}

fn local_override_fields(remote_content: &str, local_content: &str) -> anyhow::Result<Vec<String>> {
    let remote: toml::Value = toml::from_str(remote_content)?;
    let local: toml::Value = toml::from_str(local_content)?;
    let remote = remote
        .as_table()
        .context("服务端配置 TOML 根节点必须是表")?;
    let local = local.as_table().context("本地配置 TOML 根节点必须是表")?;
    Ok(local
        .iter()
        .filter(|(key, value)| {
            !matches!(
                key.as_str(),
                "subscription" | "network_code" | "device_id" | "ip" | "device_name"
            ) && remote.get(*key) != Some(*value)
        })
        .map(|(key, _)| key.clone())
        .collect())
}

fn validate_tunnel_binding(addrs: &[SocketAddr], legacy_port: Option<u16>) -> anyhow::Result<()> {
    if !addrs.is_empty() && legacy_port.is_some() {
        bail!("tunnel_addr and tunnel_port cannot be configured together")
    }
    let mut ipv4 = false;
    let mut ipv6 = false;
    let mut port = None;
    for addr in addrs {
        let seen = match addr {
            SocketAddr::V4(_) => &mut ipv4,
            SocketAddr::V6(_) => &mut ipv6,
        };
        if *seen {
            bail!("tunnel_addr supports at most one address per IP family")
        }
        *seen = true;
        if let Some(expected) = port
            && expected != addr.port()
        {
            bail!("all tunnel_addr entries must use the same port")
        }
        port = Some(addr.port());
    }
    Ok(())
}

#[derive(Deserialize)]
struct SaveConfigReq {
    file_name: Option<String>,
    config: String,
}

#[derive(Deserialize)]
struct FileReq {
    file_name: String,
}

#[derive(Serialize)]
struct ConfigSummary {
    file_name: String,
    config_name: String,
}

#[derive(Serialize, Default)]
struct HttpAppInfo {
    name: String,
    version: String,
    ip: Option<Ipv4Addr>,
    prefix_len: Option<u8>,
    gateway: Option<Ipv4Addr>,
    device_id: String,
    status: VntStatus,
    current_config_name: Option<String>,
    current_config_file: Option<String>,
    online_client_num: usize,
    offline_client_num: usize,
    direct_client_num: usize,
    server_info: Vec<HttpServerInfo>,
    nat_type: Option<String>,
    public_ipv6: Option<Ipv6Addr>,
    public_ipv4s: Vec<Ipv4Addr>,
    network_code: Option<String>,
    mtu: Option<u16>,
    fec: Option<bool>,
    compress: Option<bool>,
    encrypt: Option<bool>,
    rtx: Option<bool>,
    allow_ikev2: bool,
    allow_wireguard: bool,
    tunnel_listen_addrs: Vec<HttpTunnelListenAddr>,
    input: Vec<NetInput>,
    output: Vec<Ipv4Net>,
    automatic_input: Vec<NetInput>,
    /// 启动后配置文件是否发生过变化(与启动时的配置快照对比)
    config_changed: bool,
}

#[derive(Serialize)]
struct HttpServerInfo {
    server: String,
    connected: bool,
    server_rtt: Option<u32>,
    server_version: Option<String>,
}

#[derive(Serialize)]
struct HttpTunnelListenAddr {
    protocol: String,
    address: SocketAddr,
}

#[derive(Serialize)]
struct HttpClientItem {
    ip: Ipv4Addr,
    name: Option<String>,
    online: bool,
    route: Option<HttpRouteDetail>,
    version: String,
    client_type: String,
    last_connected_time: i64,
    key_equal: i32,
    nat_info: Option<HttpClientNatInfo>,
    packet_loss: Option<HttpPacketLoss>,
    traffic: Option<HttpTraffic>,
    advertised_subnets: Vec<Ipv4Net>,
}

#[derive(Serialize)]
struct HttpClientNatInfo {
    nat_type: String,
    public_ips: Vec<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
}

#[derive(Serialize)]
struct HttpPacketLoss {
    sent: u64,
    received: u64,
    loss_rate: f64,
}

#[derive(Serialize)]
struct HttpTraffic {
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Serialize)]
struct HttpRouteItem {
    ip: Ipv4Addr,
    routes: Vec<HttpRouteDetail>,
}

#[derive(Serialize, Clone)]
struct HttpRouteDetail {
    addr: String,
    protocol: String,
    metric: u8,
    rtt: u32,
    loss_rate: u16,
}

#[derive(Serialize)]
struct StartStatusResponse {
    status: VntStatus,
}

#[derive(Serialize)]
struct InstanceSummary {
    file_name: String,
    config_name: String,
    status: VntStatus,
}

async fn get_start_status(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<StartStatusResponse>> {
    let lock = state.inner.lock();
    // 实例不存在（从未启动或已停止并清理）时返回 Stopped，
    // 前端轮询已停止实例时自然终止
    let resp = match lock.instances.get(&req.file_name) {
        Some(inst) => StartStatusResponse {
            status: inst.status,
        },
        None => StartStatusResponse {
            status: VntStatus::Stopped,
        },
    };
    Json(ApiResponse::success(resp))
}

/// 获取实例最近日志（每个实例保留最后 50 条，停止后仍可查询）
async fn get_instance_logs(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<Vec<LogEntry>>> {
    Json(ApiResponse::success(state.logs.logs(&req.file_name)))
}

/// 运行中实例当前生效的配置（本地配置与服务端下发合并后的结果），以 TOML
/// 文本返回，仅供查看。
///
/// 读快照而非实时锁管理器：监测循环在等待运行期事件时持有管理器锁，
/// 直接去锁会阻塞到下一次事件。
async fn get_instance_config(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<String>> {
    match state.instance_config_text(&req.file_name) {
        Some(text) => Json(ApiResponse::success(text)),
        None => Json(ApiResponse::error("实例未运行或配置尚未就绪")),
    }
}

async fn get_instances(
    State(state): State<HttpAppState>,
) -> Json<ApiResponse<Vec<InstanceSummary>>> {
    let lock = state.inner.lock();
    let mut list: Vec<InstanceSummary> = lock
        .instances
        .iter()
        .map(|(file_name, inst)| {
            let config_name = inst
                .vnt
                .as_ref()
                .map(|v| v.config_name.clone())
                .unwrap_or_else(|| {
                    if inst.config_name.is_empty() {
                        file_name.clone()
                    } else {
                        inst.config_name.clone()
                    }
                });
            InstanceSummary {
                file_name: file_name.clone(),
                config_name,
                status: inst.status,
            }
        })
        .collect();
    list.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    Json(ApiResponse::success(list))
}

async fn logging_middleware(req: Request, next: axum::middleware::Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();
    let response = next.run(req).await;
    log::info!(
        "Request: {} {} | Status: {} | Took: {:?}",
        method,
        uri,
        response.status(),
        start.elapsed()
    );
    response
}

#[derive(RustEmbed)]
#[folder = "static/"]
struct Asset;

/// VNT 业务服务。独立 Web 程序与需要进程内嵌入的调用方共用同一组 handler。
#[derive(Clone)]
pub struct VntService {
    router: Router,
}

#[derive(Clone, Copy)]
enum ServiceRuntime {
    StandaloneWeb,
    DesktopWeb,
}

impl ServiceRuntime {
    fn as_str(self) -> &'static str {
        match self {
            Self::StandaloneWeb => "standalone_web",
            Self::DesktopWeb => "desktop_web",
        }
    }
}

impl VntService {
    pub async fn new(start_config_file_name: Option<PathBuf>) -> anyhow::Result<Self> {
        Self::new_with_runtime(start_config_file_name, ServiceRuntime::StandaloneWeb).await
    }

    /// 保留给需要进程内嵌入 VNT Web handler 的调用方。
    pub async fn new_desktop(start_config_file_name: Option<PathBuf>) -> anyhow::Result<Self> {
        Self::new_with_runtime(start_config_file_name, ServiceRuntime::DesktopWeb).await
    }

    async fn new_with_runtime(
        start_config_file_name: Option<PathBuf>,
        runtime: ServiceRuntime,
    ) -> anyhow::Result<Self> {
        fs::create_dir_all(CONFIG_DIR)
            .await
            .context("Failed to create config directory")?;

        let state = HttpAppState {
            inner: Arc::new(Default::default()),
            logs: Arc::new(LogManager::new()),
        };

        for (file_name, path) in determine_auto_start_files(start_config_file_name).await {
            log::info!("Auto starting VNT with config: {:?}", path);
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) = start_vnt_internal(&state_clone, file_name, path).await {
                    log::error!("Auto start failed: {:?}", e);
                }
            });
        }

        Ok(Self {
            router: api_router(state, runtime),
        })
    }

    /// 由 Tauri command 调用，不经过 TCP/HTTP 监听端口。
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        let method = Method::from_bytes(method.as_bytes()).context("Invalid request method")?;
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.unwrap_or_default()))?;
        let response = self.router.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024).await?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("Invalid service response ({status})"))?;
        Ok(value)
    }

    /// 在当前进程中按需开放带令牌鉴权的 Web 服务。
    pub async fn start_http(
        &self,
        addr: SocketAddr,
        token: String,
        cancellation: CancellationToken,
    ) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;
        let app = http_router(self.router.clone(), token);
        log::info!("HTTP API Listening on http://{}", actual_addr);
        Ok(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(cancellation.cancelled_owned())
                .await?;
            Ok(())
        }))
    }
}

pub fn generate_access_token() -> String {
    let mut bytes = [0_u8; 24];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn api_router(state: HttpAppState, runtime: ServiceRuntime) -> Router {
    let get_runtime =
        move || async move { Json(ApiResponse::success(runtime.as_str().to_string())) };
    Router::new()
        .route("/api/version", get(get_version))
        .route("/api/runtime", get(get_runtime))
        .route("/api/info", get(get_info))
        .route("/api/peers", get(get_peers))
        .route("/api/routes", get(get_routes))
        .route("/api/start/status", get(get_start_status))
        .route("/api/instance/logs", get(get_instance_logs))
        .route("/api/instance/config", get(get_instance_config))
        .route("/api/instances", get(get_instances))
        .route("/api/instance", delete(dismiss_instance_handler))
        .route("/api/start", post(start_vnt_handler))
        .route("/api/stop", post(stop_vnt_handler))
        .route("/api/restart", post(restart_vnt_handler))
        .route("/api/config/list", get(list_configs))
        .route(
            "/api/config",
            get(get_config).post(save_config).delete(delete_config),
        )
        .route("/api/subscription/preview", post(preview_subscription))
        .route("/api/subscription/status", get(get_subscription_status))
        .route(
            "/api/subscription/overrides/clear",
            post(clear_subscription_overrides),
        )
        .route("/api/subscription/detach", post(detach_subscription))
        .with_state(state)
}

async fn token_auth_middleware(
    State(token): State<String>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|provided| provided == token);
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::<()>::error("访问令牌无效或已过期")),
        )
            .into_response();
    }
    next.run(req).await
}

fn http_router(api: Router, token: String) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    Router::new()
        .merge(api.layer(middleware::from_fn_with_state(token, token_auth_middleware)))
        .fallback(static_handler)
        .layer(cors)
        .layer(middleware::from_fn(logging_middleware))
}

pub async fn run_http_server(
    addr: SocketAddr,
    start_config_file_name: Option<PathBuf>,
    token: String,
) -> anyhow::Result<()> {
    let service = VntService::new(start_config_file_name).await?;
    let cancellation = CancellationToken::new();
    let handle = service
        .start_http(addr, token, cancellation.clone())
        .await?;
    let shutdown_result = shutdown_signal().await;
    cancellation.cancel();
    handle.await??;
    shutdown_result?;
    Ok(())
}

/// 确定自动启动的配置文件列表。
/// --conf 显式指定时只返回那一个；否则读自启记录文件（每行一个 file_name），过滤存在的文件。
async fn determine_auto_start_files(
    start_config_file_name: Option<PathBuf>,
) -> Vec<(String, PathBuf)> {
    let mut result = Vec::new();

    let paths: Vec<PathBuf> = if let Some(name) = start_config_file_name {
        vec![name]
    } else if Path::new(CURRENT_CONFIG_RECORD).exists() {
        match fs::read_to_string(CURRENT_CONFIG_RECORD).await {
            Ok(content) => content
                .lines()
                .map(|line| line.trim())
                .filter(|line| !line.is_empty())
                .map(|line| Path::new(CONFIG_DIR).join(line))
                .collect(),
            Err(e) => {
                log::warn!("Failed to read auto start record: {}", e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    for p in paths {
        let Some(file_name) = p
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
        else {
            continue;
        };
        if result.iter().any(|(name, _)| *name == file_name) {
            continue;
        }
        if p.exists() {
            result.push((file_name, p));
        } else {
            log::warn!("Auto start config file not found: {:?}", p);
        }
    }
    result
}

/// 读取自启记录文件（每行一个 file_name，去空白、去重）
async fn read_running_records() -> Vec<String> {
    let Ok(content) = fs::read_to_string(CURRENT_CONFIG_RECORD).await else {
        return Vec::new();
    };
    let mut names: Vec<String> = Vec::new();
    for line in content.lines() {
        let name = line.trim();
        if !name.is_empty() && !names.iter().any(|n| n == name) {
            names.push(name.to_string());
        }
    }
    names
}

async fn write_running_records(names: &[String]) {
    if let Err(e) = fs::write(CURRENT_CONFIG_RECORD, names.join("\n")).await {
        log::warn!("Failed to record running configs: {}", e);
    }
}

/// 启动成功后把 file_name 加入自启记录
async fn record_add_running(file_name: &str) {
    let mut names = read_running_records().await;
    if !names.iter().any(|n| n == file_name) {
        names.push(file_name.to_string());
    }
    write_running_records(&names).await;
}

/// 实例停止后把 file_name 从自启记录移除
async fn record_remove_running(file_name: &str) {
    let mut names = read_running_records().await;
    names.retain(|n| n != file_name);
    write_running_records(&names).await;
}

fn build_headers_for_path(path: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let is_gz = path.ends_with(".gz");

    let mime = if is_gz {
        let original = path.trim_end_matches(".gz");
        from_path(original).first_or_octet_stream()
    } else {
        from_path(path).first_or_octet_stream()
    };
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(mime.as_ref())
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );

    if is_gz {
        headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    // Vite 会为 JS/CSS 等静态资源生成带内容哈希的文件名，可以长期缓存。
    // 但 index.html 是资源清单的入口；若将它标记为 immutable，浏览器会在
    // 程序升级后继续使用旧入口，进而加载旧的前端代码或引用已经不存在的资源。
    headers.insert(
        header::CACHE_CONTROL,
        if path.trim_end_matches(".gz") == "index.html" {
            HeaderValue::from_static("no-cache")
        } else {
            HeaderValue::from_static("public, max-age=31536000, immutable")
        },
    );
    headers
}
/// 将请求路径安全地映射到 static 目录内。
/// 逐组件校验，拒绝 `..`、根路径、盘符等任何可能逃逸出 static 的路径。
fn resolve_static_path(path: &str) -> Option<PathBuf> {
    let mut local_path = PathBuf::from("static");
    for component in Path::new(path).components() {
        match component {
            std::path::Component::Normal(part) => local_path.push(part),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(local_path)
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    // 先尝试从本地文件读取
    let Some(local_path) = resolve_static_path(path) else {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    };
    if local_path.is_file()
        && let Ok(content) = tokio::fs::read(&local_path).await
    {
        log::debug!("Serving file from local filesystem: {:?}", local_path);
        // 开发/本地静态目录与发布时内嵌资源必须使用同一缓存策略，避免
        // 两种运行方式的刷新行为不一致。
        let headers = build_headers_for_path(path);
        return (headers, Body::from(content)).into_response();
    }

    // 从内嵌数据中读取
    if let Some(content) = Asset::get(path) {
        log::debug!("Serving file from embedded assets: {}", path);
        let headers = build_headers_for_path(path);
        return (headers, Body::from(content.data)).into_response();
    }

    (StatusCode::NOT_FOUND, "404 Not Found").into_response()
}

/// 启动前冲突检测：新配置与所有 Starting/Running 实例的配置比对。
/// 纯函数，便于单元测试。
fn check_config_conflict(new: &StartConfig, running: &[&StartConfig]) -> Result<(), String> {
    for cfg in running {
        // device_id 的唯一性只在"同一服务器 + 同一组网编号"范围内成立：
        // 不同服务器或不同 network_code 的实例互不影响
        let same_network = new.network_code == cfg.network_code;
        let server_overlap = (new.server.is_empty() && cfg.server.is_empty())
            || new.server.iter().any(|s| cfg.server.contains(s));
        // 两者都为 None 也算冲突：缺省 device_id 使用同一 machine_uid
        if same_network && server_overlap && new.device_id == cfg.device_id {
            return Err(match &new.device_id {
                Some(id) => format!(
                    "启动冲突：device_id \"{}\" 已被同服务器同组网的运行中实例使用",
                    id
                ),
                None => {
                    "启动冲突：与同服务器同组网的实例都未指定 device_id，缺省会使用相同的本机标识"
                        .to_string()
                }
            });
        }
        if tunnel_bindings_conflict(new, cfg) {
            return Err("启动冲突：P2P 隧道监听地址与其他运行中的实例冲突".to_string());
        }
    }
    Ok(())
}

fn effective_tunnel_addrs(config: &StartConfig) -> Vec<SocketAddr> {
    let (mut addrs, port) = if let Some(addr) = config.tunnel_addr.first() {
        (config.tunnel_addr.clone(), addr.port())
    } else if let Some(port) = config.tunnel_port {
        (Vec::new(), port)
    } else {
        return Vec::new();
    };
    if port == 0 {
        return Vec::new();
    }
    if !addrs.iter().any(SocketAddr::is_ipv4) {
        addrs.push(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
    }
    if !addrs.iter().any(SocketAddr::is_ipv6) {
        addrs.push(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
    }
    addrs
}

fn tunnel_bindings_conflict(a: &StartConfig, b: &StartConfig) -> bool {
    effective_tunnel_addrs(a).iter().any(|left| {
        effective_tunnel_addrs(b).iter().any(|right| {
            left.port() == right.port()
                && left.is_ipv4() == right.is_ipv4()
                && (left.ip().is_unspecified()
                    || right.ip().is_unspecified()
                    || left.ip() == right.ip())
        })
    })
}

/// 启动 VNT 服务的入口函数
async fn start_vnt_internal(
    state: &HttpAppState,
    file_name: String,
    file_path: PathBuf,
) -> anyhow::Result<()> {
    let generation = begin_vnt_start(state, &file_name)?;
    start_vnt_internal_reserved(state, file_name, file_path, generation).await
}

/// 在把启动任务放入后台前先公布 Starting 状态和当次日志。
///
/// HTTP 启动接口会在返回后被前端立即轮询；如果在 spawn 的任务里才
/// 切换状态，轮询可能暂时读到上一轮的 Stopped 和旧日志。
fn begin_vnt_start(state: &HttpAppState, file_name: &str) -> anyhow::Result<u64> {
    log::info!("Starting VNT service: {}", file_name);
    let generation = state.starting(file_name)?;
    state.record_log(file_name, format!("启动配置: {}", file_name));
    state.record_log(file_name, "读取配置文件");
    Ok(generation)
}

async fn start_vnt_internal_reserved(
    state: &HttpAppState,
    file_name: String,
    file_path: PathBuf,
    generation: u64,
) -> anyhow::Result<()> {
    let start_cancellation = state
        .start_cancellation(&file_name, generation)
        .context("启动实例取消信号缺失")?;

    let state_for_error = state.clone();
    let file_name_for_error = file_name.clone();
    let on_error_guard = defer(move || {
        state_for_error.starting_to_stopped(&file_name_for_error, generation);
    });

    // 读取并解析配置
    let local_content = fs::read_to_string(&file_path)
        .await
        .with_context(|| format!("Config file not found: {:?}", file_path))?;
    let local_display_config: toml::Value =
        toml::from_str(&local_content).context("本地配置 TOML 无效")?;
    if let Some(config_name) = local_display_config
        .as_table()
        .and_then(|table| table.get("config_name"))
        .and_then(toml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        state.set_starting_config_name(&file_name, generation, config_name.to_string());
    }

    let cfg = resolve_subscription_config_with_retry(
        state,
        &file_name,
        &local_content,
        &start_cancellation,
    )
    .await?;

    state.record_log(&file_name, "解析配置文件内容");
    // 订阅模式下服务器与虚拟 IP 由服务端首份配置下发（管理器内部等待并
    // 合并），本地配置只做与服务器无关的基础校验，与 cli 的解析流程一致
    if cfg.subscription.is_some() {
        cfg.validate_local()?;
    } else {
        cfg.validate()?;
    }

    let config_display_name = cfg.config_name.clone().unwrap_or_else(|| file_name.clone());

    // 启动前冲突检测：与所有 Starting/Running 实例的配置比对
    {
        let inner = state.inner.lock();
        let running: Vec<&StartConfig> = inner
            .instances
            .iter()
            .filter(|(name, inst)| name.as_str() != file_name && inst.status != VntStatus::Stopped)
            .filter_map(|(_, inst)| {
                inst.vnt
                    .as_ref()
                    .map(|v| &v.start_config)
                    .or(inst.start_config.as_ref())
            })
            .collect();
        if let Err(msg) = check_config_conflict(&cfg, &running) {
            bail!(msg);
        }
    }

    let local_config = toml::from_str(&local_content).context("本地配置 TOML 无效")?;
    state.set_starting_config(
        &file_name,
        generation,
        config_display_name.clone(),
        cfg.clone(),
        local_config,
    );

    let start_config = cfg.clone();

    let state_clone = state.clone();
    let file_name_clone = file_name.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let start_handle = tokio::spawn(async move {
        let result = start_vnt_network(StartNetworkContext {
            state: state_clone.clone(),
            file_name: file_name_clone.clone(),
            generation,
            config_display_name,
            start_config,
        })
        .await;

        if let Err(e) = result {
            log::error!("Failed to start VNT network: {:?}", e);
            let error_message = e.to_string();
            state_clone.record_log_and_stopped(
                &file_name_clone,
                generation,
                format!("启动失败: {e:?}"),
            );
            drop(on_error_guard);
            let _ = ready_tx.send(Err(error_message));
            return;
        }
        let _ = ready_tx.send(Ok(()));
        drop(on_error_guard);
    });
    state.set_start_handle(&file_name, generation, start_handle);
    match tokio::time::timeout(Duration::from_secs(30), ready_rx).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(anyhow!(error)),
        Ok(Err(_)) => Err(anyhow!("启动任务在返回结果前退出")),
        Err(_) => {
            state.abort_start_task_if_generation(&file_name, generation);
            // 中止启动任务会丢弃其中持有的管理器；兜底再摘除并停止一次
            if let Some(manager) = state.take_runtime_manager(&file_name)
                && let Ok(mut guard) = tokio::time::timeout(
                    Duration::from_secs(10),
                    manager.lock(),
                )
                .await
            {
                guard.stop().await;
            }
            let error = "启动网络实例超时";
            state.record_log_and_stopped(&file_name, generation, error);
            Err(anyhow!(error))
        }
    }
}

struct StartNetworkContext {
    state: HttpAppState,
    file_name: String,
    generation: u64,
    config_display_name: String,
    start_config: StartConfig,
}

/// 执行实际的网络启动操作（组网实例已由配置管理器创建）
async fn start_vnt_network(context: StartNetworkContext) -> anyhow::Result<()> {
    let StartNetworkContext {
        state,
        file_name,
        generation,
        config_display_name,
        start_config,
    } = context;
    let manager = state
        .runtime_manager(&file_name)
        .context("配置管理器不可用")?;

    // 启动虚拟网卡（管理器内部等待注册完成）
    let (device_mode, vnt_api) = {
        let mut guard = manager.lock().await;
        let network_addr = match guard.start_device().await {
            Ok(network_addr) => network_addr,
            Err(e) => {
                log::error!("Register failed: {:?}", e);
                state.record_log(&file_name, format!("注册失败:{}", e));
                bail!("注册失败：{}", e)
            }
        };
        let device_mode = guard.device_mode();
        let vnt_api = guard.api().context("配置管理器 API 不可用")?;
        let task_groups = guard.task_groups();
        drop(guard);
        state.set_instance_task_groups(&file_name, task_groups);
        state.record_log(
            &file_name,
            format!("注册成功 {}/{}", network_addr.ip, network_addr.prefix_len),
        );
        log::info!(
            "Network Started: {}/{}",
            network_addr.ip,
            network_addr.prefix_len
        );
        (device_mode, vnt_api)
    };
    if device_mode.has_device() {
        state.record_log(&file_name, format!("创建并应用 {} 虚拟网卡成功", device_mode));
    } else {
        state.record_log(&file_name, "device_mode=no，不创建虚拟网卡");
    }

    {
        let mut lock = state.inner.lock();
        let Some(inst) = lock.instances.get_mut(&file_name) else {
            return Err(anyhow!("Instance not found: {}", file_name));
        };
        if inst.generation != generation {
            bail!("实例已被新的 generation 替代");
        }
        if inst.vnt.is_some() {
            return Err(anyhow!("VNT is already running"));
        }
        inst.vnt = Some(VntHandler {
            api: vnt_api,
            config_name: config_display_name,
            config_file_name: file_name.clone(),
            start_config: start_config.clone(),
        });
    }

    let state_for_vnt_cleanup = state.clone();
    let file_name_for_cleanup = file_name.clone();
    let vnt_cleanup_guard = defer(move || {
        state_for_vnt_cleanup.cleanup_generation(&file_name_for_cleanup, generation);
    });

    if !state.starting_to_running(&file_name, generation) {
        bail!("实例启动完成时 generation 已失效");
    }

    // 发布初始生效配置文本（本地配置与服务端下发的合并结果）
    let config_text = {
        let mut guard = manager.lock().await;
        guard
            .current_config()
            .await
            .ok()
            .map(|config| config.to_toml_string())
    };
    if let Some(text) = config_text {
        state.set_instance_config_text(&file_name, text);
    }

    // 启动成功后记录到自启列表
    record_add_running(&file_name).await;

    // 启动运行期事件循环。管理器持有订阅连接与组网实例，事件循环只通过
    // 它获取/应用变化；组网实例重建（apply_change 内部）不经过这里。
    let file_name_for_wait = file_name.clone();
    tokio::spawn(async move {
        loop {
            let event = {
                let mut guard = manager.lock().await;
                guard.next_event().await
            };
            match event {
                Ok(RuntimeEvent::InstanceStopped) => break,
                Ok(RuntimeEvent::Changed(change)) => {
                    let outcome = {
                        let mut guard = manager.lock().await;
                        guard.apply_change(&change).await
                    };
                    match outcome {
                        Ok(ChangeOutcome::Applied) => {
                            state.record_log(
                                &file_name_for_wait,
                                format!("已应用运行期变化（入栈路由 {} 条）", change.routes.len()),
                            );
                            // 刷新生效配置文本快照
                            let config_text = {
                                let mut guard = manager.lock().await;
                                guard
                                    .current_config()
                                    .await
                                    .ok()
                                    .map(|config| config.to_toml_string())
                            };
                            if let Some(text) = config_text {
                                state.set_instance_config_text(&file_name_for_wait, text);
                            }
                        }
                        // 桌面平台的 rebuild/need_fd 均由 apply_change 内部处理
                        Ok(ChangeOutcome::Rebuild) | Ok(ChangeOutcome::NeedFd(_)) => {}
                        Err(error) => {
                            log::warn!("应用运行期变化失败: {error:#}");
                            state.record_log(
                                &file_name_for_wait,
                                format!("应用运行期变化失败: {error:#}"),
                            );
                        }
                    }
                }
                Err(error) => {
                    log::warn!("运行期变化监听结束: {error:#}");
                    break;
                }
            }
        }
        // 事件循环结束：摘除管理器（停止组网实例并断开订阅连接）
        drop(state.take_runtime_manager(&file_name_for_wait));
        drop(manager);
        drop(vnt_cleanup_guard);
        record_remove_running(&file_name_for_wait).await;
        log::info!("Network manager stopped.");
    });

    Ok(())
}

fn is_valid_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && !file_name.contains("..")
        && !file_name.contains('/')
        && !file_name.contains('\\')
}

/// 规范化配置文件名：无扩展名时补 .toml；扩展名不是 .toml 则拒绝。
/// list_configs 只列出 *.toml，不强制后缀会保存出列表中不可见的文件
fn normalize_config_file_name(file_name: String) -> Result<String, &'static str> {
    match Path::new(&file_name).extension() {
        None => Ok(format!("{file_name}.toml")),
        Some(ext) if ext == "toml" => Ok(file_name),
        Some(_) => Err("Config file name must end with .toml"),
    }
}

async fn start_vnt_handler(
    State(state): State<HttpAppState>,
    Json(req): Json<FileReq>,
) -> Json<ApiResponse<()>> {
    if !is_valid_file_name(&req.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }

    let path = Path::new(CONFIG_DIR).join(&req.file_name);
    if !path.exists() {
        return Json(ApiResponse::error("Config file not found"));
    }
    let file_name = req.file_name;
    // 必须在返回 HTTP 响应前公布 Starting 并清理旧日志，
    // 否则前端的首次轮询会把旧的 Stopped 误当成本次启动结果。
    let generation = match begin_vnt_start(&state, &file_name) {
        Ok(generation) => generation,
        Err(error) => return Json(ApiResponse::error(error.to_string())),
    };
    let start_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) =
            start_vnt_internal_reserved(&start_state, file_name.clone(), path, generation).await
        {
            log::error!("启动 VNT 实例 {file_name} 失败: {error:#}");
        }
    });
    Json(ApiResponse::success(()))
}

/// 停止运行中的实例。
///
/// 不能直接锁管理器再 `stop()`：监测循环在 `next_event` 等待期间持有
/// 管理器锁，停止流程去锁会死锁到超时（且管理器已被摘除，实例失控）。
/// 改为停止实例任务组——监测循环的 `wait_all_stopped` 随即唤醒，由其
/// 清理路径摘除管理器并把状态置为 Stopped。
async fn stop_running_instance(state: &HttpAppState, file_name: &str) -> anyhow::Result<()> {
    if let Some(groups) = state.instance_task_groups(file_name) {
        if tokio::time::timeout(Duration::from_secs(10), groups.stop_and_wait())
            .await
            .is_err()
        {
            anyhow::bail!("停止网络实例超时");
        }
    } else if let Some(manager) = state.runtime_manager(file_name) {
        // 启动早期还没有任务组句柄：退回直接停止管理器
        if tokio::time::timeout(
            Duration::from_secs(10),
            async {
                manager.lock().await.stop().await;
            },
        )
        .await
        .is_err()
        {
            anyhow::bail!("停止网络实例超时");
        }
    }
    // 兜底摘除：监测循环通常已自行摘除
    drop(state.take_runtime_manager(file_name));
    // 等待状态落到 Stopped（监测循环清理或启动 guard 触发）
    for _ in 0..100 {
        if state.status(file_name) == VntStatus::Stopped {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

async fn stop_vnt_handler(
    State(state): State<HttpAppState>,
    Json(req): Json<FileReq>,
) -> Json<ApiResponse<()>> {
    if state.status(&req.file_name) == VntStatus::Stopped {
        // 摘除管理器（停止组网实例并断开订阅控制连接）
        drop(state.take_runtime_manager(&req.file_name));
        return Json(ApiResponse::error("Vnt stopped"));
    }
    // 先中断可能处于注册重试循环中的启动任务，再停止实例
    let apply_lock = state.config_apply_lock(&req.file_name);
    let _apply_guard = if let Some(lock) = apply_lock.as_ref() {
        Some(lock.lock().await)
    } else {
        None
    };
    state.abort_start_task(&req.file_name);
    if state.runtime_manager(&req.file_name).is_none() && state.status(&req.file_name) != VntStatus::Starting {
        return Json(ApiResponse::error("实例不存在"));
    }
    if let Err(error) = stop_running_instance(&state, &req.file_name).await {
        return Json(ApiResponse::error(error.to_string()));
    }

    record_remove_running(&req.file_name).await;
    Json(ApiResponse::success(()))
}

/// 移除已停止的实例条目（清理启动失败的残留卡片）
async fn dismiss_instance_handler(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<()>> {
    if state.status(&req.file_name) == VntStatus::Stopped {
        // Drop 停止组网实例并断开订阅控制连接
        drop(state.take_runtime_manager(&req.file_name));
    }
    let mut lock = state.inner.lock();
    match lock.instances.get(&req.file_name) {
        None => Json(ApiResponse::error("实例不存在")),
        Some(inst) if inst.status != VntStatus::Stopped => {
            Json(ApiResponse::error("实例正在运行，不能移除"))
        }
        Some(_) => {
            lock.instances.remove(&req.file_name);
            state.logs.remove(&req.file_name);
            Json(ApiResponse::success(()))
        }
    }
}

async fn restart_vnt_handler(
    State(state): State<HttpAppState>,
    Json(req): Json<FileReq>,
) -> Json<ApiResponse<()>> {
    if !is_valid_file_name(&req.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }

    let path = Path::new(CONFIG_DIR).join(&req.file_name);
    if !path.exists() {
        return Json(ApiResponse::error("Config file not found"));
    }

    // 先停止（如果正在运行则停止，否则忽略）
    if state.status(&req.file_name) != VntStatus::Stopped {
        let apply_lock = state.config_apply_lock(&req.file_name);
        let _apply_guard = if let Some(lock) = apply_lock.as_ref() {
            Some(lock.lock().await)
        } else {
            None
        };
        state.abort_start_task(&req.file_name);
        if let Err(error) = stop_running_instance(&state, &req.file_name).await {
            return Json(ApiResponse::error(format!("停止旧网络实例失败: {error}")));
        }
    }

    // 再启动；订阅拉取可能长期重试，不能让 HTTP 请求的超时取消后台启动。
    let file_name = req.file_name;
    let generation = match begin_vnt_start(&state, &file_name) {
        Ok(generation) => generation,
        Err(error) => return Json(ApiResponse::error(error.to_string())),
    };
    let start_state = state.clone();
    tokio::spawn(async move {
        if let Err(error) =
            start_vnt_internal_reserved(&start_state, file_name.clone(), path, generation).await
        {
            log::error!("重启 VNT 实例 {file_name} 失败: {error:#}");
        }
    });
    Json(ApiResponse::success(()))
}

/// 客户端版本号,与组网状态无关,任何时刻都可获取
async fn get_version() -> Json<ApiResponse<String>> {
    Json(ApiResponse::success(env!("CARGO_PKG_VERSION").to_string()))
}

async fn get_info(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<HttpAppInfo>> {
    // 先读当前配置文件(异步),避免持锁跨 await
    let current_config: Option<toml::Value> =
        match fs::read_to_string(Path::new(CONFIG_DIR).join(&req.file_name)).await {
            Ok(content) => toml::from_str(&content).ok(),
            Err(_) => None,
        };

    let lock = state.inner.lock();
    let Some(inst) = lock.instances.get(&req.file_name) else {
        return Json(ApiResponse::error("实例不存在"));
    };
    let status = inst.status;

    // 与启动时的配置快照对比:文件缺失或解析失败也视为已变化
    let config_changed = status != VntStatus::Stopped
        && match (&inst.local_config, &current_config) {
            (Some(base), Some(current)) => base != current,
            (Some(_), None) => true,
            (None, _) => false,
        };

    let info = if let Some(handler) = inst.vnt.as_ref() {
        let api = &handler.api;
        let config = api.get_config();
        let ips = api.client_ips();
        let server_node_list = api.server_node_list();
        let nat_info = api.nat_info();
        let network = api.network();

        HttpAppInfo {
            name: config
                .as_ref()
                .map(|v| v.device_name.clone())
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ip: network.map(|v| v.ip),
            prefix_len: network.map(|v| v.prefix_len),
            gateway: network.and_then(|v| v.gateway),
            device_id: config
                .as_ref()
                .map(|v| v.device_id.clone())
                .unwrap_or_default(),
            status,
            current_config_name: Some(handler.config_name.clone()),
            current_config_file: Some(handler.config_file_name.clone()),
            online_client_num: ips.iter().filter(|v| v.online).count(),
            offline_client_num: ips.iter().filter(|v| !v.online).count(),
            direct_client_num: ips.iter().filter(|ip| api.is_direct(&ip.ip)).count(),
            server_info: server_node_list
                .into_iter()
                .map(|v| HttpServerInfo {
                    server: v.server_addr.to_string(),
                    connected: v.connected,
                    server_rtt: v.rtt,
                    server_version: v.server_version,
                })
                .collect(),
            nat_type: nat_info.as_ref().map(|v| format!("{:?}", v.nat_type)),
            public_ipv4s: nat_info
                .as_ref()
                .map(|v| v.public_ips.clone())
                .unwrap_or_default(),
            public_ipv6: nat_info.as_ref().and_then(|v| v.ipv6),
            network_code: config.as_ref().map(|v| v.network_code.clone()),
            mtu: config.as_ref().map(|v| v.mtu.unwrap_or(DEFAULT_MTU)),
            fec: config.as_ref().map(|v| v.fec),
            compress: config.as_ref().map(|v| v.compress),
            encrypt: config.as_ref().map(|v| v.password.is_some()),
            rtx: config.as_ref().map(|v| v.rtx),
            allow_ikev2: config.as_ref().is_some_and(|v| v.allow_ikev2),
            allow_wireguard: config.as_ref().is_some_and(|v| v.allow_wireguard),
            tunnel_listen_addrs: api
                .p2p_listen_addrs()
                .into_iter()
                .map(|v| HttpTunnelListenAddr {
                    protocol: v.protocol.to_string(),
                    address: v.addr,
                })
                .collect(),
            input: config.as_ref().map(|v| v.input.clone()).unwrap_or_default(),
            output: config
                .as_ref()
                .map(|v| v.output.clone())
                .unwrap_or_default(),
            automatic_input: api.automatic_subnet_routes(),
            config_changed,
        }
    } else {
        HttpAppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status,
            config_changed,
            ..Default::default()
        }
    };

    Json(ApiResponse::success(info))
}

async fn list_configs() -> Json<ApiResponse<Vec<ConfigSummary>>> {
    let mut result = Vec::new();

    let Ok(mut entries) = fs::read_dir(CONFIG_DIR).await else {
        return Json(ApiResponse::success(result));
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();

        if path.extension().is_none_or(|ext| ext != "toml") {
            continue;
        }

        let Ok(content) = fs::read_to_string(&path).await else {
            continue;
        };

        match toml::from_str::<toml::Value>(&content) {
            Ok(value) => {
                let file_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();

                result.push(ConfigSummary {
                    file_name,
                    config_name: value
                        .as_table()
                        .and_then(|table| table.get("config_name"))
                        .and_then(toml::Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| entry.file_name().to_string_lossy().to_string()),
                });
            }
            Err(e) => {
                log::warn!("Failed to parse configuration file {:?}: {:?}", path, e);
            }
        }
    }

    result.sort_by(|a, b| b.file_name.cmp(&a.file_name));
    Json(ApiResponse::success(result))
}

#[derive(Deserialize)]
struct SubscriptionPreviewRequest {
    subscription: String,
}

#[derive(Deserialize)]
struct SubscriptionClearOverridesRequest {
    file_name: String,
    fields: Option<Vec<String>>,
}

#[derive(Serialize)]
struct SubscriptionPreviewResponse {
    server: Vec<String>,
    cert_mode: String,
    network_code: String,
    device_id: String,
    revision: u64,
    device_name: Option<String>,
    ip: Option<String>,
    config: String,
}

#[derive(Serialize)]
struct SubscriptionStatusResponse {
    file_name: String,
    network_code: String,
    device_id: String,
    target_revision: u64,
    acknowledged_revision: u64,
    applied_revision: u64,
    local_overrides: Vec<String>,
    failed_revision: Option<u64>,
    last_error: Option<String>,
    config_sync_verified: bool,
}

fn write_config_atomic(path: &Path, content: &str) -> anyhow::Result<()> {
    let parent = path.parent().context("配置路径缺少父目录")?;
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("toml.{}.tmp", std::process::id()));
    std::fs::write(&temporary, content)?;
    if path.exists() {
        let backup = path.with_extension("toml.managed-backup");
        let _ = std::fs::remove_file(&backup);
        std::fs::rename(path, &backup)?;
        if let Err(error) = std::fs::rename(&temporary, path) {
            let _ = std::fs::rename(&backup, path);
            return Err(error.into());
        }
        let _ = std::fs::remove_file(backup);
    } else {
        std::fs::rename(temporary, path)?;
    }
    Ok(())
}

async fn preview_subscription(
    Json(request): Json<SubscriptionPreviewRequest>,
) -> Json<ApiResponse<SubscriptionPreviewResponse>> {
    let result = async {
        let join = Subscription::parse(&request.subscription)?;
        let envelope = join.fetch().await?;
        let effective = resolve_effective_managed_config(
            &envelope.toml,
            "",
            &envelope.network_code,
            &envelope.device_id,
            VirtualIp::new(envelope.managed_ip, envelope.managed_prefix_len)?,
            envelope.managed_device_name,
        )?;
        Ok::<_, anyhow::Error>(SubscriptionPreviewResponse {
            server: vec![join.server],
            cert_mode: join.cert_mode,
            network_code: envelope.network_code,
            device_id: envelope.device_id,
            revision: envelope.revision,
            device_name: effective.config.device_name,
            ip: effective.config.ip.map(|ip| ip.to_string()),
            config: effective.effective_toml,
        })
    }
    .await;
    Json(match result {
        Ok(value) => ApiResponse::success(value),
        Err(error) => ApiResponse::error(error.to_string()),
    })
}

async fn get_subscription_status(
    State(state): State<HttpAppState>,
    Query(request): Query<FileReq>,
) -> Json<ApiResponse<SubscriptionStatusResponse>> {
    if !is_valid_file_name(&request.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }
    let result = async {
        let content = fs::read_to_string(Path::new(CONFIG_DIR).join(&request.file_name)).await?;
        let local: toml::Value = toml::from_str(&content)?;
        let link_value = local
            .as_table()
            .and_then(|table| table.get("subscription"))
            .and_then(toml::Value::as_str)
            .context("该配置没有订阅链接")?;
        let _link = Subscription::parse(link_value)?;
        let sync_state = load_subscription_state(&request.file_name);
        // 身份由运行中管理器持有的最新订阅信封提供（链接只携带 join_id）；
        // 管理器不存在或首份信封未达时返回空串
        let (network_code, device_id) =
            subscription_identity(&state, &request.file_name).await;
        let local_overrides = if sync_state.remote_toml.is_empty() {
            local
                .as_table()
                .into_iter()
                .flat_map(|table| table.keys())
                .filter(|field| {
                    !matches!(
                        field.as_str(),
                        "subscription" | "network_code" | "device_id" | "ip" | "device_name"
                    )
                })
                .cloned()
                .collect()
        } else {
            local_override_fields(&sync_state.remote_toml, &content)?
        };
        Ok::<_, anyhow::Error>(SubscriptionStatusResponse {
            file_name: request.file_name.clone(),
            network_code,
            device_id,
            target_revision: sync_state.target_revision,
            acknowledged_revision: sync_state.acknowledged_revision,
            applied_revision: sync_state.applied_revision,
            local_overrides,
            failed_revision: sync_state.failed_revision,
            last_error: sync_state.last_error,
            config_sync_verified: state
                .api(&request.file_name)
                .is_some_and(|api| api.has_verified_config_server()),
        })
    }
    .await;
    Json(match result {
        Ok(status) => ApiResponse::success(status),
        Err(error) => ApiResponse::error(error.to_string()),
    })
}

async fn clear_subscription_overrides(
    State(state): State<HttpAppState>,
    Json(request): Json<SubscriptionClearOverridesRequest>,
) -> Json<ApiResponse<SubscriptionStatusResponse>> {
    let result = async {
        if !is_valid_file_name(&request.file_name) {
            bail!("Invalid file name");
        }
        let apply_lock = state.config_apply_lock(&request.file_name);
        let _apply_guard = if let Some(lock) = apply_lock.as_ref() {
            Some(lock.lock().await)
        } else {
            None
        };
        let path = Path::new(CONFIG_DIR).join(&request.file_name);
        let content = fs::read_to_string(&path).await?;
        let mut value: toml::Value = toml::from_str(&content)?;
        let link_value = {
            let table = value
                .as_table_mut()
                .context("本地配置 TOML 根节点必须是表")?;
            match request.fields.as_deref() {
                Some(fields) => {
                    for field in fields {
                        if field != "subscription" {
                            table.remove(field);
                        }
                    }
                }
                None => table.retain(|key, _| {
                    matches!(key, "subscription" | "config_name" | "event_script")
                }),
            }
            table
                .get("subscription")
                .and_then(toml::Value::as_str)
                .context("该配置没有订阅链接")?
                .to_string()
        };
        let local = toml::to_string_pretty(&value)?;
        write_config_atomic(&path, &local)?;

        // Clearing a local override is deliberately local-only. It does not
        // fetch or apply a remote revision: the next server push (or a later
        // start) establishes the new effective runtime configuration.
        let _link = Subscription::parse(&link_value)?;
        let sync_state = load_subscription_state(&request.file_name);
        // 身份由运行中管理器持有的最新订阅信封提供（链接只携带 join_id）
        let (network_code, device_id) =
            subscription_identity(&state, &request.file_name).await;
        let local_overrides = if sync_state.remote_toml.is_empty() {
            value
                .as_table()
                .into_iter()
                .flat_map(|table| table.keys())
                .filter(|field| {
                    !matches!(
                        field.as_str(),
                        "subscription" | "network_code" | "device_id" | "ip" | "device_name"
                    )
                })
                .cloned()
                .collect()
        } else {
            local_override_fields(&sync_state.remote_toml, &local)?
        };
        Ok::<_, anyhow::Error>(SubscriptionStatusResponse {
            file_name: request.file_name.clone(),
            network_code,
            device_id,
            target_revision: sync_state.target_revision,
            acknowledged_revision: sync_state.acknowledged_revision,
            applied_revision: sync_state.applied_revision,
            local_overrides,
            failed_revision: sync_state.failed_revision,
            last_error: sync_state.last_error,
            config_sync_verified: state
                .api(&request.file_name)
                .is_some_and(|api| api.has_verified_config_server()),
        })
    }
    .await;
    Json(match result {
        Ok(value) => ApiResponse::success(value),
        Err(error) => ApiResponse::error(error.to_string()),
    })
}

async fn detach_subscription(Json(request): Json<FileReq>) -> Json<ApiResponse<()>> {
    if !is_valid_file_name(&request.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }
    let result = async {
        let path = Path::new(CONFIG_DIR).join(&request.file_name);
        let local = fs::read_to_string(&path).await?;
        let local_value: toml::Value = toml::from_str(&local)?;
        if local_value
            .as_table()
            .and_then(|table| table.get("subscription"))
            .is_none()
        {
            bail!("配置没有订阅链接");
        }
        // Detaching is not a synchronization operation. Use the last
        // successfully applied effective TOML so it cannot unexpectedly pull
        // and apply a newer server revision while the user is detaching.
        let sync_state = load_subscription_state(&request.file_name);
        let effective = sync_state.last_good_toml.context(
            "尚未有可保留的已应用配置；请先成功启动一次，或手动改为普通配置后再解除服务端管理",
        )?;
        let detached = sync_state
            .last_good_config
            .map(|config| toml::to_string_pretty(&config))
            .transpose()?
            .unwrap_or(effective);
        let mut value: toml::Value = toml::from_str(&detached)?;
        value
            .as_table_mut()
            .context("配置 TOML 根节点必须是表")?
            .remove("subscription");
        write_config_atomic(&path, &toml::to_string_pretty(&value)?)?;
        let state_path = subscription_state_path(&request.file_name);
        let _ = std::fs::remove_file(state_path);
        Ok::<_, anyhow::Error>(())
    }
    .await;
    Json(match result {
        Ok(()) => ApiResponse::success(()),
        Err(error) => ApiResponse::error(error.to_string()),
    })
}

async fn save_config(Json(req): Json<SaveConfigReq>) -> Json<ApiResponse<()>> {
    // 订阅配置在保存时只校验 TOML 和订阅链接本身，不连接远端。
    // 完整的远端拉取、合并和运行配置校验统一放在启动流程中执行。
    let value = match toml::from_str::<toml::Value>(&req.config) {
        Ok(value) => value,
        Err(error) => {
            log::warn!("Failed to parse configuration: {:?}", error);
            return Json(ApiResponse::error(format!(
                "Invalid TOML format: {}",
                error
            )));
        }
    };
    let Some(table) = value.as_table() else {
        return Json(ApiResponse::error(
            "Invalid TOML format: root must be a table",
        ));
    };
    let subscription = match table.get("subscription") {
        Some(value) => match value.as_str() {
            Some(value) if !value.trim().is_empty() => {
                if let Err(error) = Subscription::parse(value) {
                    return Json(ApiResponse::error(error.to_string()));
                }
                Some(value.to_string())
            }
            Some(_) => return Json(ApiResponse::error("subscription 不能为空")),
            None => return Json(ApiResponse::error("subscription 必须是字符串")),
        },
        None => None,
    };

    if subscription.is_none() {
        let parsed = toml::from_str::<StartConfig>(&req.config).and_then(|config| {
            config
                .validate()
                .map(|_| config)
                .map_err(serde::de::Error::custom)
        });
        if let Err(error) = parsed {
            log::warn!("Failed to validate configuration: {:?}", error);
            return Json(ApiResponse::error(format!(
                "Invalid TOML format: {}",
                error
            )));
        }
    }

    let file_name = req
        .file_name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            format!("{}.toml", now)
        });

    if !is_valid_file_name(&file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }

    let file_name = match normalize_config_file_name(file_name) {
        Ok(name) => name,
        Err(msg) => return Json(ApiResponse::error(msg)),
    };

    let target_path = Path::new(CONFIG_DIR).join(&file_name);
    let previous_subscription = match fs::read_to_string(&target_path).await {
        Ok(content) => toml::from_str::<toml::Value>(&content)
            .ok()
            .and_then(|value| {
                value
                    .as_table()
                    .and_then(|table| table.get("subscription"))
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            }),
        Err(_) => None,
    };

    match fs::write(&target_path, &req.config).await {
        Ok(_) => {
            if previous_subscription != subscription {
                let _ = fs::remove_file(subscription_state_path(&file_name)).await;
            }
            Json(ApiResponse::success(()))
        }
        Err(e) => Json(ApiResponse::error(format!("Write config failed: {}", e))),
    }
}

async fn get_config(Query(req): Query<FileReq>) -> Json<ApiResponse<String>> {
    if !is_valid_file_name(&req.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }

    let path = Path::new(CONFIG_DIR).join(&req.file_name);

    if !path.exists() {
        return Json(ApiResponse::error("Config file not found"));
    }

    match fs::read_to_string(&path).await {
        Ok(content) => Json(ApiResponse::success(content)),
        Err(e) => Json(ApiResponse::error(format!("Read file failed: {}", e))),
    }
}

async fn delete_config(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<()>> {
    if !is_valid_file_name(&req.file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }
    {
        let lock = state.inner.lock();
        // 实例存在且有运行内容（已运行或非 Stopped）即视为占用
        if let Some(inst) = lock.instances.get(&req.file_name)
            && (inst.vnt.is_some() || inst.status != VntStatus::Stopped)
        {
            return Json(ApiResponse::error("此配置已被使用，不能删除"));
        }
    }

    let path = Path::new(CONFIG_DIR).join(&req.file_name);

    if !path.exists() {
        return Json(ApiResponse::error("Config file not found"));
    }

    match fs::remove_file(&path).await {
        Ok(_) => {
            let _ = fs::remove_file(subscription_state_path(&req.file_name)).await;
            state.logs.remove(&req.file_name);
            Json(ApiResponse::success(()))
        }
        Err(e) => Json(ApiResponse::error(format!("Delete failed: {}", e))),
    }
}

fn convert_config(cfg: StartConfig) -> anyhow::Result<CoreConfig> {
    // 只做基础校验：服务器/虚拟 IP 的要求由调用方按订阅与否决定
    // （订阅模式下二者来自服务端首份配置），最终以合并后配置的
    // Config::check 为准
    cfg.validate_local()?;
    let server_addrs: Vec<ProtocolAddress> = cfg
        .server
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow!("invalid server address '{}': {}", s, e))
        })
        .collect::<anyhow::Result<_>>()?;

    let peer_address: Vec<PeerAddress> = cfg
        .peer_address
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow!("invalid peer address '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let turn: Vec<TurnRule> = cfg
        .turn
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow!("invalid turn rule '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let punch_model: Vec<PunchRule> = cfg
        .punch_model
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow!("invalid punch_model rule '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let port_mapping: Vec<PortMapping> = cfg
        .port_mapping
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow!("invalid port_mapping '{}': {}", s, e))
        })
        .collect::<anyhow::Result<_>>()?;

    let cert_mode = match cfg.cert_mode.as_deref() {
        Some(s) => s
            .parse()
            .map_err(|e| anyhow!("invalid cert_mode '{}': {}", s, e))?,
        None => CertValidationMode::InsecureSkipVerification,
    };

    let device_id = match cfg.device_id {
        Some(id) => id,
        None => vnt_core::utils::device_id::get_device_id()
            .map_err(|e| anyhow!("failed to get device_id: {}", e))?,
    };

    let device_name = cfg.device_name.unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|v| v.into_string().ok())
            .unwrap_or_default()
    });
    let mut udp_stun = cfg.udp_stun;
    for x in udp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }
    let mut tcp_stun = cfg.tcp_stun;
    for x in tcp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }
    Ok(CoreConfig {
        server_addr: server_addrs,
        peer_address,
        turn,
        punch_model,
        network_code: cfg.network_code,
        ip: cfg.ip,
        no_punch: cfg.no_punch,
        no_broadcast: cfg.no_broadcast,
        allow_ikev2: cfg.allow_ikev2,
        allow_wireguard: cfg.allow_wireguard,
        rtx: cfg.rtx,
        compress: cfg.compress,
        device_id,
        device_name,
        tun_name: cfg.tun_name,
        outbound_interface: cfg.outbound_interface,
        password: cfg.password,
        cert_mode,
        input: cfg.input,
        subnet_mapping: cfg.subnet_mapping,
        output: cfg.output,
        auto_sync_subnet: cfg.auto_sync_subnet,
        no_nat: cfg.no_nat,
        device_mode: cfg.device_mode,
        mtu: cfg.mtu,
        port_mapping,
        allow_port_mapping: cfg.allow_mapping,
        udp_stun,
        tcp_stun,
        fec: cfg.fec,
        tunnel_addr: cfg.tunnel_addr,
        tunnel_port: cfg.tunnel_port,
        event_script: cfg.event_script,
        managed: None,
    })
}

async fn shutdown_signal() -> anyhow::Result<()> {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .context("failed to install Ctrl+C handler")
    };

    #[cfg(unix)]
    let terminate = async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to install terminate signal handler")?;
        signal.recv().await;
        Ok::<(), anyhow::Error>(())
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<anyhow::Result<()>>();

    tokio::select! {
        result = ctrl_c => result?,
        result = terminate => result?,
    }
    Ok(())
}

async fn get_peers(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<Vec<HttpClientItem>>> {
    let api = state
        .inner
        .lock()
        .instances
        .get(&req.file_name)
        .and_then(|inst| inst.vnt.as_ref())
        .map(|v| v.api.clone());

    let Some(api) = api else {
        return Json(ApiResponse::error("VNT not running"));
    };

    let key_sign = api.get_config().and_then(|config| config.key_sign());

    let calc_key_equal = |peer_key_sign: &Option<String>| -> i32 {
        match (&key_sign, peer_key_sign) {
            (None, None) => 2,
            (Some(k1), Some(k2)) if k1 == k2 => 1,
            (Some(_), Some(_)) => 5,
            (Some(_), None) => 3,
            (None, Some(_)) => 4,
        }
    };

    let build_nat_info = |ip: &Ipv4Addr| -> Option<HttpClientNatInfo> {
        api.peer_nat_info(ip).map(|v| HttpClientNatInfo {
            nat_type: format!("{:?}", v.nat_type),
            public_ips: v.public_ips,
            ipv6: v.ipv6,
        })
    };

    let build_packet_loss = |ip: &Ipv4Addr| -> Option<HttpPacketLoss> {
        api.packet_loss_info(ip).map(|v| HttpPacketLoss {
            sent: v.sent,
            received: v.received,
            loss_rate: v.loss_rate,
        })
    };

    let build_traffic = |ip: &Ipv4Addr| -> Option<HttpTraffic> {
        api.traffic_info(ip).map(|v| HttpTraffic {
            tx_bytes: v.tx_bytes,
            rx_bytes: v.rx_bytes,
        })
    };

    let build_route = |ip: &Ipv4Addr| -> Option<HttpRouteDetail> {
        api.find_route(ip).map(|route| HttpRouteDetail {
            addr: route.route_key().to_string(),
            protocol: route.route_key().protocol().to_string(),
            metric: route.metric(),
            rtt: route.rtt(),
            loss_rate: route.loss_rate(),
        })
    };

    // 先从本地获取基础数据
    let mut merged: HashMap<Ipv4Addr, HttpClientItem> = api
        .client_ips()
        .into_iter()
        .map(|v| {
            let ip = v.ip;
            let route = build_route(&ip);
            // 如果有路由，说明设备在线（可以直接通信）
            let has_route = route.is_some();
            (
                ip,
                HttpClientItem {
                    ip,
                    name: None,
                    online: v.online || has_route,
                    route,
                    version: String::new(),
                    client_type: match v.client_type {
                        vnt_core::protocol::control_message::ClientType::Ikev2 => "IKEV2",
                        vnt_core::protocol::control_message::ClientType::Wireguard => "WIREGUARD",
                        vnt_core::protocol::control_message::ClientType::Vnt => "VNT",
                    }
                    .to_string(),
                    last_connected_time: 0,
                    key_equal: 0,
                    nat_info: build_nat_info(&ip),
                    packet_loss: build_packet_loss(&ip),
                    traffic: build_traffic(&ip),
                    advertised_subnets: Vec::new(),
                },
            )
        })
        .collect();

    for node in api.gossip_node_list() {
        let ip = node.ip;
        let route = build_route(&ip);
        merged
            .entry(ip)
            .and_modify(|item| {
                item.name = Some(node.name.clone());
                item.version = node.version.clone();
                item.online = true;
                item.route = route.clone();
                item.advertised_subnets = node.advertised_subnets.clone();
            })
            .or_insert_with(|| HttpClientItem {
                ip,
                name: Some(node.name),
                online: true,
                route,
                version: node.version,
                client_type: "VNT".to_string(),
                last_connected_time: 0,
                key_equal: 0,
                nat_info: build_nat_info(&ip),
                packet_loss: build_packet_loss(&ip),
                traffic: build_traffic(&ip),
                advertised_subnets: node.advertised_subnets,
            });
    }

    // 从服务器获取更详细的信息；纯去中心化模式不创建无意义的 RPC，
    // 避免设备列表轮询持续产生“未连接服务器”告警。
    let server_response = if api
        .get_config()
        .is_some_and(|config| !config.server_addr.is_empty())
    {
        Some(api.server_rpc().client_list().await)
    } else {
        None
    };
    match server_response {
        Some(Ok(resp)) => {
            for v in resp.list {
                let ip = Ipv4Addr::from(v.ip);
                let route = build_route(&ip);
                // 如果有路由，说明设备在线（可以直接通信）
                let has_route = route.is_some();
                let learned = merged.get(&ip);
                let learned_name = learned.and_then(|item| item.name.clone());
                let learned_version = learned.map(|item| item.version.clone());
                let advertised_subnets = learned
                    .map(|item| item.advertised_subnets.clone())
                    .unwrap_or_default();
                let client_type = match v.client_type {
                    1 => "IKEV2",
                    2 => "WIREGUARD",
                    _ => "VNT",
                };
                merged.insert(
                    ip,
                    HttpClientItem {
                        ip,
                        name: if v.name.is_empty() {
                            learned_name
                        } else {
                            Some(v.name)
                        },
                        online: v.online || has_route,
                        route,
                        version: if v.version.is_empty() {
                            learned_version.unwrap_or_default()
                        } else {
                            v.version
                        },
                        client_type: client_type.to_string(),
                        last_connected_time: v.last_connected_time,
                        key_equal: if v.client_type != 0 {
                            0
                        } else {
                            calc_key_equal(&v.key_sign)
                        },
                        nat_info: build_nat_info(&ip),
                        packet_loss: build_packet_loss(&ip),
                        traffic: build_traffic(&ip),
                        advertised_subnets,
                    },
                );
            }
        }
        Some(Err(error)) => log::warn!("Failed to get client list from server: {error}"),
        None => {}
    }

    let mut items: Vec<HttpClientItem> = merged.into_values().collect();
    items.sort_by_key(|it| it.ip);

    Json(ApiResponse::success(items))
}

async fn get_routes(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<Vec<HttpRouteItem>>> {
    let lock = state.inner.lock();

    let Some(handler) = lock
        .instances
        .get(&req.file_name)
        .and_then(|inst| inst.vnt.as_ref())
    else {
        return Json(ApiResponse::error("VNT not running"));
    };

    let table = handler.api.route_table();
    let items: Vec<HttpRouteItem> = table
        .into_iter()
        .map(|(ip, route_list)| HttpRouteItem {
            ip,
            routes: route_list
                .into_iter()
                .map(|v| HttpRouteDetail {
                    addr: v.route_key().to_string(),
                    protocol: v.route_key().protocol().to_string(),
                    metric: v.metric(),
                    rtt: v.rtt(),
                    loss_rate: v.loss_rate(),
                })
                .collect(),
        })
        .collect();

    Json(ApiResponse::success(items))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_fetch_retries_and_reports_each_failure() {
        let cancellation = CancellationToken::new();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reports = std::sync::Arc::new(Mutex::new(Vec::new()));
        let fetch_calls = calls.clone();
        let failure_reports = reports.clone();

        let value = fetch_subscription_until_cancelled(
            &cancellation,
            Duration::ZERO,
            move || {
                let calls = fetch_calls.clone();
                async move {
                    let attempt = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if attempt == 0 {
                        Err(anyhow!("temporary subscription failure"))
                    } else {
                        Ok("fetched")
                    }
                }
            },
            move |attempt, error| failure_reports.lock().push((attempt, error.to_string())),
        )
        .await
        .unwrap();

        assert_eq!(value, "fetched");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            reports.lock().as_slice(),
            &[(1, "temporary subscription failure".to_string())]
        );
    }

    #[tokio::test]
    async fn cancelled_subscription_fetch_never_starts_an_attempt() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetch_calls = calls.clone();

        let error = fetch_subscription_until_cancelled(
            &cancellation,
            Duration::ZERO,
            move || {
                let calls = fetch_calls.clone();
                async move {
                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, anyhow::Error>("unexpected")
                }
            },
            |_attempt, _error| {},
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("启动已取消"));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn managed_merge_always_uses_subscription_identity() {
        // 身份来自服务端信封元数据，本地两层配置的同类值一律被忽略
        let merged = resolve_effective_managed_config(
            r#"network_code = "remote-forged"
device_id = "remote-forged"
device_name = "remote-name"
compress = true
server = ["tcp://example.com:443"]
cert_mode = "standard"
ip = "10.26.0.2/24"
"#,
            r#"network_code = "local-forged"
device_id = "local-forged"
subscription = "vnt2://join/secret"
device_name = "local-name"
event_script = "local-script"
config_name = "local-label"
"#,
            "trusted-net",
            "trusted-device",
            VirtualIp::new("10.26.0.2".parse().unwrap(), 24).unwrap(),
            "managed-name".to_string(),
        )
        .unwrap();
        let value: toml::Value = toml::from_str(&merged.effective_toml).unwrap();
        let table = value.as_table().unwrap();
        assert_eq!(table["network_code"].as_str(), Some("trusted-net"));
        assert_eq!(table["device_id"].as_str(), Some("trusted-device"));
        assert!(!table.contains_key("device_name"));
        assert_eq!(table["event_script"].as_str(), Some("local-script"));
        assert_eq!(table["config_name"].as_str(), Some("local-label"));
        assert!(!table.contains_key("subscription"));
        assert_eq!(merged.config.device_name.as_deref(), Some("managed-name"));
        assert!(merged.config.subscription.is_none());
        assert_eq!(
            merged.config.ip.unwrap().ip(),
            "10.26.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );

        let overrides = merged.overridden_fields;
        assert!(!overrides.iter().any(|field| field == "network_code"));
        assert!(!overrides.iter().any(|field| field == "device_id"));
        assert!(!overrides.iter().any(|field| field == "device_name"));
    }

    #[tokio::test]
    async fn test_ipc_request_uses_in_process_router() {
        let service = VntService {
            router: api_router(new_test_state(), ServiceRuntime::StandaloneWeb),
        };
        let response = service.request("GET", "/api/version", None).await.unwrap();
        assert_eq!(response["code"], 0);
        assert!(
            response["data"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );

        let response = service.request("GET", "/api/runtime", None).await.unwrap();
        assert_eq!(response["code"], 0);
        assert_eq!(response["data"], "standalone_web");

        let desktop_service = VntService {
            router: api_router(new_test_state(), ServiceRuntime::DesktopWeb),
        };
        let response = desktop_service
            .request("GET", "/api/runtime", None)
            .await
            .unwrap();
        assert_eq!(response["code"], 0);
        assert_eq!(response["data"], "desktop_web");
    }

    #[tokio::test]
    async fn test_http_api_requires_bearer_token() {
        let token = "test-token-with-enough-entropy".to_string();
        let app = http_router(
            api_router(new_test_state(), ServiceRuntime::StandaloneWeb),
            token.clone(),
        );
        let unauthorized = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/version")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn subscription_sync_route_is_not_exposed() {
        let response = api_router(new_test_state(), ServiceRuntime::StandaloneWeb)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/subscription/sync")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_normalize_config_file_name() {
        // 无扩展名补 .toml
        assert_eq!(
            normalize_config_file_name("myconfig".to_string()).unwrap(),
            "myconfig.toml"
        );
        // 已是 .toml 保持不变
        assert_eq!(
            normalize_config_file_name("a.toml".to_string()).unwrap(),
            "a.toml"
        );
        // 其他扩展名拒绝（list_configs 只列 *.toml，保存了也不可见）
        assert!(normalize_config_file_name("a.txt".to_string()).is_err());
        assert!(normalize_config_file_name("a.json".to_string()).is_err());
    }

    #[test]
    fn test_resolve_static_path_allows_normal_paths() {
        assert_eq!(
            resolve_static_path("index.html"),
            Some(PathBuf::from("static").join("index.html"))
        );
        assert_eq!(
            resolve_static_path("css/style.css"),
            Some(PathBuf::from("static").join("css").join("style.css"))
        );
        assert_eq!(
            resolve_static_path("./index.html"),
            Some(PathBuf::from("static").join("index.html"))
        );
    }

    #[test]
    fn test_resolve_static_path_rejects_traversal() {
        assert!(resolve_static_path("../Cargo.toml").is_none());
        assert!(resolve_static_path("a/../../Cargo.toml").is_none());
        assert!(resolve_static_path("/etc/passwd").is_none());
        assert!(resolve_static_path("..").is_none());
        // Windows 下反斜杠也是路径分隔符
        #[cfg(windows)]
        {
            assert!(resolve_static_path("..\\..\\Cargo.toml").is_none());
            assert!(resolve_static_path("C:/Windows/win.ini").is_none());
        }
    }

    fn new_test_state() -> HttpAppState {
        HttpAppState {
            inner: Arc::new(Mutex::new(HttpAppStateInner::default())),
            logs: Arc::new(LogManager::new()),
        }
    }

    fn new_test_config() -> StartConfig {
        StartConfig {
            config_name: None,
            subscription: None,
            server: Vec::new(),
            peer_address: Vec::new(),
            turn: Vec::new(),
            punch_model: Vec::new(),
            cert_mode: None,
            network_code: "test".to_string(),
            device_id: Some("device-a".to_string()),
            device_name: None,
            tun_name: None,
            outbound_interface: None,
            ip: Some("10.26.0.2/24".parse().unwrap()),
            password: None,
            no_punch: false,
            no_broadcast: false,
            allow_ikev2: false,
            allow_wireguard: false,
            compress: false,
            rtx: false,
            fec: false,
            input: Vec::new(),
            subnet_mapping: Vec::new(),
            output: Vec::new(),
            auto_sync_subnet: false,
            no_nat: false,
            // 默认无网卡，避免无关用例意外触发 tun_name 冲突
            device_mode: DeviceMode::No,
            legacy_no_tun: None,
            mtu: None,
            port_mapping: Vec::new(),
            allow_mapping: false,
            udp_stun: Vec::new(),
            tcp_stun: Vec::new(),
            tunnel_addr: Vec::new(),
            tunnel_port: None,
            event_script: None,
        }
    }

    #[test]
    fn test_device_mode_config_and_legacy_rejection() {
        let base = r#"server = ["quic://127.0.0.1:29872"]
network_code = "test"
"#;
        let default_cfg: StartConfig = toml::from_str(base).unwrap();
        assert_eq!(default_cfg.device_mode, DeviceMode::Tun);

        let tap_cfg: StartConfig =
            toml::from_str(&format!("{base}device_mode = \"tap\"\n")).unwrap();
        assert_eq!(tap_cfg.device_mode, DeviceMode::Tap);

        let legacy: StartConfig = toml::from_str(&format!("{base}no_tun = true\n")).unwrap();
        assert!(legacy.validate().is_err());

        let legacy_false: StartConfig = toml::from_str(&format!("{base}no_tun = false\n")).unwrap();
        assert!(legacy_false.validate().is_ok());
    }

    #[test]
    fn index_html_must_revalidate_but_hashed_assets_can_be_immutable() {
        let index_headers = build_headers_for_path("index.html");
        assert_eq!(
            index_headers.get(header::CACHE_CONTROL).unwrap(),
            "no-cache"
        );

        let compressed_index_headers = build_headers_for_path("index.html.gz");
        assert_eq!(
            compressed_index_headers.get(header::CACHE_CONTROL).unwrap(),
            "no-cache"
        );

        let asset_headers = build_headers_for_path("assets/index-abc123.js");
        assert_eq!(
            asset_headers.get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn test_serverless_config_requires_and_preserves_cidr() {
        let config: StartConfig = toml::from_str(
            r#"network_code = "test"
ip = "10.26.0.2/20"
"#,
        )
        .unwrap();
        assert!(config.validate().is_ok());
        let core = convert_config(config).unwrap();
        assert_eq!(core.ip.unwrap().to_string(), "10.26.0.2/20");

        let missing_ip: StartConfig = toml::from_str(r#"network_code = "test""#).unwrap();
        assert!(missing_ip.validate().is_err());
    }

    #[test]
    fn test_plain_virtual_ip_defaults_to_24() {
        let config: StartConfig = toml::from_str(
            r#"network_code = "test"
ip = "10.26.0.2"
"#,
        )
        .unwrap();
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/24");
    }

    #[test]
    fn test_convert_config_keeps_peer_addresses() {
        let mut config = new_test_config();
        config.server = vec!["quic://127.0.0.1:29872".to_string()];
        config.peer_address = vec![
            "127.0.0.1:30001".to_string(),
            "tcp://127.0.0.1:30002".to_string(),
            "dynamic://peers.example.com".to_string(),
        ];
        let core = convert_config(config).unwrap();
        assert_eq!(core.peer_address.len(), 3);
        assert_eq!(core.peer_address[0].to_string(), "127.0.0.1:30001");
        assert_eq!(core.peer_address[1].to_string(), "tcp://127.0.0.1:30002");
        assert_eq!(
            core.peer_address[2].to_string(),
            "dynamic://peers.example.com"
        );
    }

    #[test]
    fn test_convert_config_keeps_turn_rules() {
        let mut config = new_test_config();
        config.turn = vec![
            "10.26.0.0/16,10.26.0.2".to_string(),
            "10.26.1.9,10.26.0.3".to_string(),
        ];
        let core = convert_config(config).unwrap();
        assert_eq!(core.turn.len(), 2);
        assert_eq!(core.turn[0].to_string(), "10.26.0.0/16,10.26.0.2");
        assert_eq!(core.turn[1].to_string(), "10.26.1.9,10.26.0.3");
    }

    #[test]
    fn test_convert_config_keeps_punch_model_rules() {
        let mut config = new_test_config();
        config.punch_model = vec![
            "10.26.0.2,IPv4Udp".to_string(),
            "10.26.1.0/24,IPv4Tcp,IPv6Udp".to_string(),
        ];
        let core = convert_config(config).unwrap();
        assert_eq!(core.punch_model.len(), 2);
        assert_eq!(core.punch_model[0].to_string(), "10.26.0.2,IPv4Udp");
        assert_eq!(
            core.punch_model[1].to_string(),
            "10.26.1.0/24,IPv4Tcp,IPv6Udp"
        );
    }

    #[test]
    fn test_convert_config_keeps_exit_subnet_mapping() {
        let mut config = new_test_config();
        config.subnet_mapping = vec!["192.168.2.2/32,192.168.1.3/32".parse().unwrap()];
        config.output = vec!["192.168.1.0/24".parse().unwrap()];
        config.auto_sync_subnet = true;
        let mut core = convert_config(config).unwrap();
        assert_eq!(
            core.subnet_mapping[0].to_string(),
            "192.168.2.2/32,192.168.1.3/32"
        );
        assert!(core.auto_sync_subnet);
        core.normalize().unwrap();
    }

    #[test]
    fn test_convert_config_keeps_broadcast_and_relay_switches() {
        let mut config = new_test_config();
        config.no_broadcast = true;
        config.allow_ikev2 = true;
        config.allow_wireguard = true;
        let core = convert_config(config).unwrap();
        assert!(core.no_broadcast);
        assert!(core.allow_ikev2);
        assert!(core.allow_wireguard);
    }

    /// 两个实例同时处于 Starting 互不影响
    #[test]
    fn test_two_instances_starting_independent() {
        let state = new_test_state();
        let a_generation = state.starting("a.toml").unwrap();
        state.starting("b.toml").unwrap();
        state.record_log("a.toml", "a 的日志");
        state.record_log("b.toml", "b 的日志");

        assert_eq!(state.status("a.toml"), VntStatus::Starting);
        assert_eq!(state.status("b.toml"), VntStatus::Starting);

        // a 启动失败停止，b 的状态和日志不受影响
        state.record_log_and_stopped("a.toml", a_generation, "启动失败");
        assert_eq!(state.status("a.toml"), VntStatus::Stopped);
        assert_eq!(state.status("b.toml"), VntStatus::Starting);

        let a_logs = state.logs.logs("a.toml");
        assert!(a_logs.iter().any(|log| log.message.contains("启动失败")));
        let b_logs = state.logs.logs("b.toml");
        assert_eq!(b_logs.len(), 1);
        assert!(b_logs[0].message.contains("b 的日志"));
    }

    #[test]
    fn starting_instance_uses_local_config_name_before_subscription_resolves() {
        let state = new_test_state();
        let generation = state.starting("opaque-file.toml").unwrap();

        state.set_starting_config_name("opaque-file.toml", generation, "公司网络".to_string());

        let lock = state.inner.lock();
        assert_eq!(lock.instances["opaque-file.toml"].config_name, "公司网络");
    }

    /// 网卡创建等启动步骤失败时，网络资源清理发生在错误日志写入之前。
    /// 清理阶段必须保留 Starting 实例，外层才能把具体错误返回给前端日志。
    #[test]
    fn test_starting_cleanup_preserves_failure_log() {
        let state = new_test_state();
        let generation = state.starting("a.toml").unwrap();
        state.record_log("a.toml", "正在创建 tun 虚拟网卡");

        state.cleanup_generation("a.toml", generation);
        assert_eq!(state.status("a.toml"), VntStatus::Starting);

        state.record_log_and_stopped("a.toml", generation, "启动失败: 创建 tun 虚拟网卡失败");

        let lock = state.inner.lock();
        let instance = lock.instances.get("a.toml").unwrap();
        assert_eq!(instance.status, VntStatus::Stopped);
        drop(lock);
        assert!(
            state
                .logs
                .logs("a.toml")
                .iter()
                .any(|log| log.message.contains("创建 tun 虚拟网卡失败"))
        );
    }

    /// 移除已停止实例：Stopped 可移除，Starting 拒绝
    #[tokio::test]
    async fn test_dismiss_instance() {
        let state = new_test_state();
        let generation = state.starting("a.toml").unwrap();
        state.record_log_and_stopped("a.toml", generation, "启动失败");
        state.starting("b.toml").unwrap();

        // Starting 中的实例不能移除
        let resp = dismiss_instance_handler(
            State(state.clone()),
            Query(FileReq {
                file_name: "b.toml".to_string(),
            }),
        )
        .await;
        assert_eq!(resp.code, -1);
        assert!(state.inner.lock().instances.contains_key("b.toml"));

        // 已停止（启动失败残留）的实例可以移除
        let resp = dismiss_instance_handler(
            State(state.clone()),
            Query(FileReq {
                file_name: "a.toml".to_string(),
            }),
        )
        .await;
        assert_eq!(resp.code, 0);
        assert!(!state.inner.lock().instances.contains_key("a.toml"));
        // 移除实例时同步清理其实例日志
        assert!(state.logs.logs("a.toml").is_empty());

        // 不存在的实例报错
        let resp = dismiss_instance_handler(
            State(state.clone()),
            Query(FileReq {
                file_name: "nope.toml".to_string(),
            }),
        )
        .await;
        assert_eq!(resp.code, -1);
    }

    /// 实例日志端点：按实例返回最近日志，未知实例返回空列表
    #[tokio::test]
    async fn test_instance_logs_endpoint() {
        let state = new_test_state();
        let generation = state.starting("a.toml").unwrap();
        state.record_log("a.toml", "连接服务器，执行注册");
        state.record_log_and_stopped("a.toml", generation, "启动失败: 连接超时");

        let resp = get_instance_logs(
            State(state.clone()),
            Query(FileReq {
                file_name: "a.toml".to_string(),
            }),
        )
        .await;
        let Json(resp) = resp;
        assert_eq!(resp.code, 0);
        let logs = resp.data.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].message, "连接服务器，执行注册");
        assert_eq!(logs[0].level, vnt_core::log_manager::LogLevel::Info);
        assert_eq!(logs[1].level, vnt_core::log_manager::LogLevel::Error);
        assert!(logs[1].message.contains("连接超时"));

        // 未知实例返回空列表
        let resp = get_instance_logs(
            State(state.clone()),
            Query(FileReq {
                file_name: "missing.toml".to_string(),
            }),
        )
        .await;
        let Json(resp) = resp;
        assert_eq!(resp.code, 0);
        assert!(resp.data.unwrap().is_empty());
    }

    /// 同一 file_name 重复 starting 报错
    #[test]
    fn test_duplicate_starting_same_file() {
        let state = new_test_state();
        state.starting("a.toml").unwrap();
        assert!(state.starting("a.toml").is_err());
        // 不同 file_name 不受影响
        state.starting("b.toml").unwrap();
    }

    /// HTTP 处理器返回前必须让首次轮询看到本次启动，而不是上次的日志。
    #[test]
    fn begin_start_publishes_current_attempt_before_worker_runs() {
        let state = new_test_state();
        let old_generation = state.starting("a.toml").unwrap();
        state.record_log_and_stopped("a.toml", old_generation, "上次启动失败");

        let generation = begin_vnt_start(&state, "a.toml").unwrap();

        assert!(generation > old_generation);
        assert_eq!(state.status("a.toml"), VntStatus::Starting);
        let logs = state.logs.logs("a.toml");
        assert_eq!(logs.len(), 2);
        assert!(logs[0].message.contains("启动配置"));
        assert_eq!(logs[1].message, "读取配置文件");
        assert!(logs.iter().all(|log| !log.message.contains("上次")));
    }

    #[test]
    fn stale_generation_cannot_cleanup_or_stop_replacement() {
        let state = new_test_state();
        let old_generation = state.starting("a.toml").unwrap();
        state.record_log_and_stopped("a.toml", old_generation, "旧实例已停止");
        let new_generation = state.starting("a.toml").unwrap();
        assert!(new_generation > old_generation);

        state.cleanup_generation("a.toml", old_generation);
        state.starting_to_stopped("a.toml", old_generation);
        assert_eq!(state.current_generation("a.toml"), Some(new_generation));
        assert_eq!(state.status("a.toml"), VntStatus::Starting);
    }

    /// device_id 相同（含双方都为 None）且同服务器同组网时冲突；
    /// 不同服务器或不同 network_code 时允许相同 device_id
    #[test]
    fn test_conflict_same_device_id() {
        let running = new_test_config();
        // 相同 device_id（双方 server 均为空，视为同范围）
        let new = new_test_config();
        assert!(check_config_conflict(&new, &[&running]).is_err());
        // 双方都不指定 device_id（缺省会用同一 machine_uid）也算冲突
        let mut a = new_test_config();
        a.device_id = None;
        let mut b = new_test_config();
        b.device_id = None;
        assert!(check_config_conflict(&b, &[&a]).is_err());
        // 不同 device_id 不冲突
        let mut c = new_test_config();
        c.device_id = Some("device-c".to_string());
        assert!(check_config_conflict(&c, &[&running]).is_ok());
        // 相同 device_id 但 network_code 不同 → 不冲突
        let mut d = new_test_config();
        d.network_code = "other-net".to_string();
        assert!(check_config_conflict(&d, &[&running]).is_ok());
        // 相同 device_id 相同 network_code 但服务器不同 → 不冲突
        let mut e_running = new_test_config();
        e_running.server = vec!["server1:29870".to_string()];
        let mut e = new_test_config();
        e.server = vec!["server2:29870".to_string()];
        assert!(check_config_conflict(&e, &[&e_running]).is_ok());
        // 相同 device_id 相同 network_code 且服务器有交集 → 冲突
        let mut f = new_test_config();
        f.server = vec!["server1:29870".to_string(), "server3:29870".to_string()];
        assert!(check_config_conflict(&f, &[&e_running]).is_err());
    }

    /// 旧版 tunnel_port 都为固定同端口时冲突。
    #[test]
    fn test_conflict_same_tunnel_port() {
        let mut running = new_test_config();
        running.device_id = Some("d1".to_string());
        running.tunnel_port = Some(12345);
        let mut new = new_test_config();
        new.device_id = Some("d2".to_string());
        new.tunnel_port = Some(12345);
        assert!(check_config_conflict(&new, &[&running]).is_err());
        // 一方未指定不冲突
        let mut new_none = new_test_config();
        new_none.device_id = Some("d2".to_string());
        assert!(check_config_conflict(&new_none, &[&running]).is_ok());
        // 端口不同不冲突
        let mut new_other = new_test_config();
        new_other.device_id = Some("d2".to_string());
        new_other.tunnel_port = Some(23456);
        assert!(check_config_conflict(&new_other, &[&running]).is_ok());

        let mut automatic = new_test_config();
        automatic.device_id = Some("d2".to_string());
        automatic.tunnel_port = Some(0);
        assert!(check_config_conflict(&automatic, &[&running]).is_ok());
    }

    #[test]
    fn test_tunnel_addr_validation_and_conflicts() {
        let mut running = new_test_config();
        running.device_id = Some("d1".to_string());
        running.tunnel_addr = vec![
            "192.168.1.10:12345".parse().unwrap(),
            "[2001:db8::10]:12345".parse().unwrap(),
        ];
        assert!(running.validate().is_ok());

        let mut distinct = new_test_config();
        distinct.device_id = Some("d2".to_string());
        distinct.tunnel_addr = vec![
            "192.168.1.11:12345".parse().unwrap(),
            "[2001:db8::11]:12345".parse().unwrap(),
        ];
        assert!(!tunnel_bindings_conflict(&distinct, &running));

        distinct.tunnel_addr = vec!["192.168.1.11:12345".parse().unwrap()];
        assert!(tunnel_bindings_conflict(&distinct, &running));

        distinct.tunnel_addr = vec!["0.0.0.0:0".parse().unwrap()];
        assert!(!tunnel_bindings_conflict(&distinct, &running));

        distinct.tunnel_addr = vec![
            "192.168.1.11:12345".parse().unwrap(),
            "[2001:db8::11]:12346".parse().unwrap(),
        ];
        assert!(distinct.validate().is_err());
    }

    /// Starting 状态下执行停止：必须中断注册重试循环并迁移到 Stopped。
    /// 复现 bug 场景——服务器不可达时启动任务陷在无限重试里，
    /// 不中断启动任务则状态永远卡在 Starting。
    #[tokio::test]
    async fn test_stop_during_starting() {
        let state = new_test_state();
        let file_name = "a.toml";
        let generation = state.starting(file_name).unwrap();

        // 模拟启动任务：注册一直失败、5 秒重试的无限循环
        let state_clone = state.clone();
        let file_name_owned = file_name.to_string();
        let on_error_guard = defer(move || {
            state_clone.starting_to_stopped(&file_name_owned, generation);
        });
        let handle = tokio::spawn(async move {
            let _on_error_guard = on_error_guard;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        state.set_start_handle(file_name, generation, handle);

        assert_eq!(state.status(file_name), VntStatus::Starting);
        state.abort_start_task(file_name);

        // abort 生效后 defer 触发，状态应迁移到 Stopped
        for _ in 0..100 {
            if state.status(file_name) == VntStatus::Stopped {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(state.status(file_name), VntStatus::Stopped);
    }

    #[test]
    fn subscription_only_config_skips_server_requirements() {
        let cfg: StartConfig = toml::from_str(
            r#"
config_name = "sub-only"
network_code = "net"
subscription = "vnt2://join/2/eyJ2IjoyfQ"
"#,
        )
        .unwrap();
        assert!(cfg.subscription.is_some());
        assert!(cfg.server.is_empty());
        // 订阅模式下本地配置只做基础校验（服务器/IP 由服务端首份配置下发）
        cfg.validate_local().unwrap();
        // 完整校验仍然要求服务器或 IP
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn subscription_state_never_contains_link_credentials() {
        let state = SubscriptionStateFile {
            remote_toml: "mtu = 1400".to_string(),
            target_revision: 3,
            applied_revision: 2,
            last_good_toml: Some("mtu = 1380".to_string()),
            failed_revision: Some(3),
            last_error: Some("invalid mtu".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        assert!(!json.contains("credential"));
        assert!(!json.contains("subscription"));
    }
}
