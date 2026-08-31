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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, macros::format_description};
use tokio::fs;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tower_http::cors::{Any, CorsLayer};
use vnt_core::api::VntApi;
use vnt_core::context::config::{Config as CoreConfig, DeviceMode, PeerAddress, TurnRule};
use vnt_core::core::{DEFAULT_MTU, NetworkManager, RegisterResponse};
use vnt_core::nat::NetInput;
use vnt_core::port_mapping::PortMapping;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_core::utils::task_control::TaskGroupManager;

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
}

#[derive(Default)]
struct HttpAppStateInner {
    /// 组网实例表，key = 配置文件名，同一配置最多一个实例
    instances: HashMap<String, InstanceState>,
}

#[derive(Default)]
struct InstanceState {
    vnt: Option<VntHandler>,
    status: VntStatus,
    start_logs: Vec<String>,
    /// 启动任务句柄，用于在 Starting 状态中断注册重试循环
    start_handle: Option<tokio::task::JoinHandle<()>>,
    /// 每个实例持有自己的任务组管理器（TaskGroupManager 是单槽的，不能共享）
    task_group_manager: TaskGroupManager,
    /// 启动时解析出的配置快照，用于多实例启动前冲突检测
    start_config: Option<StartConfig>,
    /// 展示名；Starting 阶段还没有 vnt，用配置里的 config_name 或 file_name 兜底
    config_name: String,
}

impl HttpAppState {
    fn starting(&self, file_name: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock();
        let inst = inner.instances.entry(file_name.to_string()).or_default();
        if inst.status != VntStatus::Stopped {
            return Err(anyhow!("配置 {} 正在启动或已运行", file_name));
        }
        if inst.vnt.is_some() {
            return Err(anyhow!("配置 {} 已在运行", file_name));
        }
        inst.status = VntStatus::Starting;
        inst.start_logs.clear();
        inst.start_config = None;
        inst.config_name = file_name.to_string();
        Ok(())
    }
    fn stopped(&self, file_name: &str) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        inst.vnt.take();
        // 启动流程会先释放网络资源，再由外层记录具体的失败原因。
        // 此时保持 Starting，避免实例及其启动日志被提前清理。
        if inst.status == VntStatus::Starting {
            return;
        }
        inst.status = VntStatus::Stopped;
        inst.start_config = None;
        // 已完成任务的句柄只是残留，不算运行内容
        if inst.start_handle.as_ref().is_some_and(|h| h.is_finished()) {
            inst.start_handle.take();
        }
        // 实例已无任何运行内容时移除条目，避免实例表堆积已停止的配置。
        // 注意 Starting 失败路径走 record_log_and_stopped/starting_to_stopped 保留日志，
        // 不经过这里，不会被误删。
        let removable = inst.start_handle.is_none() && inst.task_group_manager.is_stopped();
        if removable {
            inner.instances.remove(file_name);
        }
    }
    fn starting_to_stopped(&self, file_name: &str) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.status != VntStatus::Starting {
            return;
        }
        inst.vnt.take();
        inst.status = VntStatus::Stopped;
        inst.start_logs
            .push(format!("[{}] 启动中断", HttpAppState::timestamp()));
    }
    fn starting_to_running(&self, file_name: &str) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.status != VntStatus::Starting {
            log::error!("starting_to_running VNT is not starting");
            return;
        }
        inst.status = VntStatus::Running;
        inst.start_logs.clear();
    }

    fn record_log(&self, file_name: &str, msg: impl Into<String>) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.status != VntStatus::Starting {
            return;
        }
        inst.start_logs
            .push(format!("[{}] {}", Self::timestamp(), msg.into()));
    }
    fn record_log_and_stopped(&self, file_name: &str, msg: impl Into<String>) {
        let mut inner = self.inner.lock();
        let Some(inst) = inner.instances.get_mut(file_name) else {
            return;
        };
        if inst.status != VntStatus::Starting {
            return;
        }
        inst.start_logs
            .push(format!("[{}] {}", Self::timestamp(), msg.into()));
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

    fn task_group_manager(&self, file_name: &str) -> Option<TaskGroupManager> {
        self.inner
            .lock()
            .instances
            .get(file_name)
            .map(|inst| inst.task_group_manager.clone())
    }

    /// 启动解析出配置后写入展示名和配置快照（供实例列表与冲突检测使用）
    fn set_starting_config(&self, file_name: &str, config_name: String, cfg: StartConfig) {
        if let Some(inst) = self.inner.lock().instances.get_mut(file_name) {
            inst.config_name = config_name;
            inst.start_config = Some(cfg);
        }
    }

    fn set_start_handle(&self, file_name: &str, handle: tokio::task::JoinHandle<()>) {
        if let Some(inst) = self.inner.lock().instances.get_mut(file_name) {
            inst.start_handle = Some(handle);
        }
    }

    /// 中断启动任务（如注册重试循环）。任务已完成时为空操作。
    fn abort_start_task(&self, file_name: &str) {
        let handle = self
            .inner
            .lock()
            .instances
            .get_mut(file_name)
            .and_then(|inst| inst.start_handle.take());
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    fn timestamp() -> String {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let format = format_description!("[hour]:[minute]:[second]");
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
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
    pub server: Vec<String>,
    #[serde(default)]
    pub peer_address: Vec<String>,
    #[serde(default)]
    pub turn: Vec<String>,
    pub cert_mode: Option<String>,
    pub network_code: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_name: Option<String>,
    pub outbound_interface: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub password: Option<String>,
    #[serde(default)]
    pub no_punch: bool,
    #[serde(default)]
    pub no_broadcast: bool,
    #[serde(default)]
    pub compress: bool,
    #[serde(default)]
    pub rtx: bool,
    #[serde(default)]
    pub fec: bool,
    #[serde(default)]
    pub input: Vec<NetInput>,
    #[serde(default)]
    pub output: Vec<Ipv4Net>,
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
    pub tunnel_port: Option<u16>,
    #[serde(default)]
    pub event_script: Option<String>,
}

impl StartConfig {
    fn reject_legacy_no_tun(&self) -> anyhow::Result<()> {
        if self.legacy_no_tun == Some(true) {
            bail!("configuration key 'no_tun' was removed; use device_mode = \"no|tun|tap\"")
        }
        Ok(())
    }
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
struct HttpClientItem {
    ip: Ipv4Addr,
    name: Option<String>,
    online: bool,
    route: Option<HttpRouteDetail>,
    version: String,
    last_connected_time: i64,
    key_equal: i32,
    nat_info: Option<HttpClientNatInfo>,
    packet_loss: Option<HttpPacketLoss>,
    traffic: Option<HttpTraffic>,
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

#[derive(Serialize)]
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
    logs: Vec<String>,
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
    // 实例不存在（从未启动或已停止并清理）时返回 Stopped + 空日志，
    // 前端轮询已停止实例时自然终止
    let resp = match lock.instances.get(&req.file_name) {
        Some(inst) => StartStatusResponse {
            status: inst.status,
            logs: inst.start_logs.clone(),
        },
        None => StartStatusResponse {
            status: VntStatus::Stopped,
            logs: Vec::new(),
        },
    };
    Json(ApiResponse::success(resp))
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
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
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
        let mime = from_path(&local_path).first_or_octet_stream();
        return ([(header::CONTENT_TYPE, mime.as_ref())], content).into_response();
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
        if let (Some(a), Some(b)) = (new.tunnel_port, cfg.tunnel_port)
            && a == b
        {
            return Err(format!(
                "启动冲突：tunnel_port {} 已被其他运行中的实例使用",
                a
            ));
        }
    }
    Ok(())
}

/// 启动 VNT 服务的入口函数
async fn start_vnt_internal(
    state: &HttpAppState,
    file_name: String,
    file_path: PathBuf,
) -> anyhow::Result<()> {
    log::info!("Starting VNT service: {}", file_name);
    state.starting(&file_name)?;

    let state_for_error = state.clone();
    let file_name_for_error = file_name.clone();
    let on_error_guard = defer(move || {
        state_for_error.starting_to_stopped(&file_name_for_error);
    });

    state.record_log(&file_name, format!("启动配置: {}", file_name));
    state.record_log(&file_name, "读取配置文件");

    // 读取并解析配置
    let content = fs::read_to_string(&file_path)
        .await
        .with_context(|| format!("Config file not found: {:?}", file_path))?;

    state.record_log(&file_name, "解析配置文件内容");
    let cfg: StartConfig = toml::from_str(&content).context("Failed to parse TOML config")?;

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

    state.set_starting_config(&file_name, config_display_name.clone(), cfg.clone());

    let start_config = cfg.clone();
    let core_config = convert_config(cfg)?;

    state.record_log(&file_name, "创建异步任务组");
    let task_group_manager = state
        .task_group_manager(&file_name)
        .context("Instance not found")?;
    let (task_group, task_group_guard) = task_group_manager
        .create_task()
        .context("Create task failed")?;

    state.record_log(&file_name, "创建组网管理器");

    let state_clone = state.clone();
    let file_name_clone = file_name.clone();
    let start_handle = tokio::spawn(async move {
        let result = start_vnt_network(
            state_clone.clone(),
            file_name_clone.clone(),
            config_display_name,
            start_config,
            core_config,
            task_group,
            task_group_guard,
        )
        .await;

        if let Err(e) = result {
            log::error!("Failed to start VNT network: {:?}", e);
            state_clone.record_log_and_stopped(&file_name_clone, format!("启动失败: {:?}", e));
        }
        drop(on_error_guard);
    });
    state.set_start_handle(&file_name, start_handle);

    Ok(())
}

/// 执行实际的网络启动操作
async fn start_vnt_network(
    state: HttpAppState,
    file_name: String,
    config_display_name: String,
    start_config: StartConfig,
    core_config: CoreConfig,
    task_group: vnt_core::utils::task_control::TaskGroup,
    task_group_guard: vnt_core::utils::task_control::TaskGroupGuard,
) -> anyhow::Result<()> {
    let sub_input = core_config.input.clone();
    let mut network_manager =
        NetworkManager::create_network(Box::new(core_config), task_group.clone())
            .await
            .map_err(|e| anyhow!("Create network failed: {:?}", e))?;

    let vnt_api = network_manager.vnt_api();

    {
        let mut lock = state.inner.lock();
        let Some(inst) = lock.instances.get_mut(&file_name) else {
            return Err(anyhow!("Instance not found: {}", file_name));
        };
        if inst.vnt.is_some() {
            return Err(anyhow!("VNT is already running"));
        }
        inst.vnt = Some(VntHandler {
            api: vnt_api,
            config_name: config_display_name,
            config_file_name: file_name.clone(),
            start_config,
        });
    }

    let state_for_vnt_cleanup = state.clone();
    let file_name_for_cleanup = file_name.clone();
    let vnt_cleanup_guard = defer(move || {
        state_for_vnt_cleanup.stopped(&file_name_for_cleanup);
    });

    state.record_log(&file_name, "连接服务器，执行注册");
    log::info!("Registering with server");

    let reg_msg = loop {
        let reg_msg = match network_manager.register().await {
            Ok(rs) => rs,
            Err(e) => {
                log::error!("Register failed: {:?}", e);
                state.record_log(&file_name, format!("注册失败:{},5秒后重试", e));
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };
        match reg_msg {
            RegisterResponse::Success(reg_msg) => {
                break reg_msg;
            }
            RegisterResponse::Failed(e) => {
                log::error!("Register failed: {:?}", e);
                bail!("注册失败：{}", e.message)
            }
        }
    };
    state.record_log(
        &file_name,
        format!("注册成功 {}/{}", reg_msg.ip, reg_msg.prefix_len),
    );
    log::info!("Network Started: {}/{}", reg_msg.ip, reg_msg.prefix_len);
    if network_manager.device_mode().has_device() {
        let mode = network_manager.device_mode();
        state.record_log(&file_name, format!("正在创建 {} 虚拟网卡", mode));
        network_manager
            .start_device()
            .await
            .with_context(|| format!("创建 {} 虚拟网卡失败", mode))?;

        state.record_log(&file_name, format!("创建 {} 虚拟网卡成功，设置 IP", mode));
        network_manager
            .set_device_network_ip(reg_msg.ip, reg_msg.prefix_len)
            .await
            .with_context(|| format!("设置 {} 虚拟网卡 IP 失败", mode))?;
        state.record_log(&file_name, "设置 IP 成功");

        // 配置子网路由
        if !sub_input.is_empty()
            && let Ok(if_index) = network_manager.device_if_index().await
            && let Ok(mut route_manager) = route_manager::RouteManager::new()
        {
            state.record_log(&file_name, "配置子网路由");
            for input in &sub_input {
                let route =
                    route_manager::Route::new(input.net.network().into(), input.net.prefix_len())
                        .with_gateway(input.target_ip.into())
                        .with_if_index(if_index);

                if let Err(e) = route_manager.add(&route) {
                    log::error!("add route [{route}] error: {e:?}");
                } else {
                    log::info!("add route [{route}] successful");
                }
            }
        }
    } else {
        state.record_log(&file_name, "device_mode=no，不创建虚拟网卡");
    }

    state.starting_to_running(&file_name);

    // 启动成功后记录到自启列表
    record_add_running(&file_name).await;

    // 启动网络管理任务。
    // 注意必须在任务组外等待：等待目标就是这个 task_group，
    // 若 spawn 进组内会形成自引用等待，网络自行停止时永不返回
    let file_name_for_wait = file_name.clone();
    tokio::spawn(async move {
        network_manager.wait_all_stopped().await;
        drop(task_group_guard);
        drop(network_manager);
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

    match start_vnt_internal(&state, req.file_name, path).await {
        Ok(_) => Json(ApiResponse::success(())),
        Err(e) => Json(ApiResponse::error(format!("Start failed: {:?}", e))),
    }
}

async fn stop_vnt_handler(
    State(state): State<HttpAppState>,
    Json(req): Json<FileReq>,
) -> Json<ApiResponse<()>> {
    let Some(task_group_manager) = state.task_group_manager(&req.file_name) else {
        return Json(ApiResponse::error("实例不存在"));
    };
    if state.status(&req.file_name) == VntStatus::Stopped {
        return Json(ApiResponse::error("Vnt stopped"));
    }
    // 先中断可能处于注册重试循环中的启动任务，再停止任务组
    state.abort_start_task(&req.file_name);
    task_group_manager.stop();

    record_remove_running(&req.file_name).await;
    Json(ApiResponse::success(()))
}

/// 移除已停止的实例条目（清理启动失败的残留卡片）
async fn dismiss_instance_handler(
    State(state): State<HttpAppState>,
    Query(req): Query<FileReq>,
) -> Json<ApiResponse<()>> {
    let mut lock = state.inner.lock();
    match lock.instances.get(&req.file_name) {
        None => Json(ApiResponse::error("实例不存在")),
        Some(inst) if inst.status != VntStatus::Stopped => {
            Json(ApiResponse::error("实例正在运行，不能移除"))
        }
        Some(_) => {
            lock.instances.remove(&req.file_name);
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
        state.abort_start_task(&req.file_name);
        if let Some(task_group_manager) = state.task_group_manager(&req.file_name) {
            task_group_manager.stop();
        }
        // 等待停止完成
        for _ in 0..50 {
            if state.status(&req.file_name) == VntStatus::Stopped {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // 再启动
    match start_vnt_internal(&state, req.file_name, path).await {
        Ok(_) => Json(ApiResponse::success(())),
        Err(e) => Json(ApiResponse::error(format!("Restart failed: {:?}", e))),
    }
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
    let current_config: Option<StartConfig> =
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
        && match (&inst.start_config, &current_config) {
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
            gateway: network.map(|v| v.gateway),
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

        match toml::from_str::<StartConfig>(&content) {
            Ok(cfg) => {
                let file_name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();

                result.push(ConfigSummary {
                    file_name,
                    config_name: cfg
                        .config_name
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

async fn save_config(Json(req): Json<SaveConfigReq>) -> Json<ApiResponse<()>> {
    // 验证配置格式
    let parsed = toml::from_str::<StartConfig>(&req.config).and_then(|config| {
        config
            .reject_legacy_no_tun()
            .map(|_| config)
            .map_err(serde::de::Error::custom)
    });
    if let Err(e) = parsed {
        log::warn!("Failed to parse configuration: {:?}", e);
        return Json(ApiResponse::error(format!("Invalid TOML format: {}", e)));
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

    match fs::write(&target_path, &req.config).await {
        Ok(_) => Json(ApiResponse::success(())),
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
        Ok(_) => Json(ApiResponse::success(())),
        Err(e) => Json(ApiResponse::error(format!("Delete failed: {}", e))),
    }
}

fn convert_config(cfg: StartConfig) -> anyhow::Result<CoreConfig> {
    cfg.reject_legacy_no_tun()?;
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
        network_code: cfg.network_code,
        ip: cfg.ip,
        no_punch: cfg.no_punch,
        no_broadcast: cfg.no_broadcast,
        rtx: cfg.rtx,
        compress: cfg.compress,
        device_id,
        device_name,
        tun_name: cfg.tun_name,
        outbound_interface: cfg.outbound_interface,
        password: cfg.password,
        cert_mode,
        input: cfg.input,
        output: cfg.output,
        no_nat: cfg.no_nat,
        device_mode: cfg.device_mode,
        mtu: cfg.mtu,
        port_mapping,
        allow_port_mapping: cfg.allow_mapping,
        udp_stun,
        tcp_stun,
        fec: cfg.fec,
        tunnel_port: cfg.tunnel_port,
        event_script: cfg.event_script,
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
                    last_connected_time: 0,
                    key_equal: 0,
                    nat_info: build_nat_info(&ip),
                    packet_loss: build_packet_loss(&ip),
                    traffic: build_traffic(&ip),
                },
            )
        })
        .collect();

    // 从服务器获取更详细的信息
    if let Ok(resp) = api.server_rpc().client_list().await {
        for v in resp.list {
            let ip = Ipv4Addr::from(v.ip);
            let route = build_route(&ip);
            // 如果有路由，说明设备在线（可以直接通信）
            let has_route = route.is_some();
            merged.insert(
                ip,
                HttpClientItem {
                    ip,
                    name: Some(v.name),
                    online: v.online || has_route,
                    route,
                    version: v.version,
                    last_connected_time: v.last_connected_time,
                    key_equal: calc_key_equal(&v.key_sign),
                    nat_info: build_nat_info(&ip),
                    packet_loss: build_packet_loss(&ip),
                    traffic: build_traffic(&ip),
                },
            );
        }
    } else {
        log::warn!("Failed to get client list from server");
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
        }
    }

    fn new_test_config() -> StartConfig {
        StartConfig {
            config_name: None,
            server: Vec::new(),
            peer_address: Vec::new(),
            turn: Vec::new(),
            cert_mode: None,
            network_code: "test".to_string(),
            device_id: Some("device-a".to_string()),
            device_name: None,
            tun_name: None,
            outbound_interface: None,
            ip: None,
            password: None,
            no_punch: false,
            no_broadcast: false,
            compress: false,
            rtx: false,
            fec: false,
            input: Vec::new(),
            output: Vec::new(),
            no_nat: false,
            // 默认无网卡，避免无关用例意外触发 tun_name 冲突
            device_mode: DeviceMode::No,
            legacy_no_tun: None,
            mtu: None,
            port_mapping: Vec::new(),
            allow_mapping: false,
            udp_stun: Vec::new(),
            tcp_stun: Vec::new(),
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
        assert!(legacy.reject_legacy_no_tun().is_err());

        let legacy_false: StartConfig = toml::from_str(&format!("{base}no_tun = false\n")).unwrap();
        assert!(legacy_false.reject_legacy_no_tun().is_ok());
    }

    #[test]
    fn test_convert_config_keeps_peer_addresses() {
        let mut config = new_test_config();
        config.server = vec!["quic://127.0.0.1:29872".to_string()];
        config.peer_address = vec![
            "127.0.0.1:30001".to_string(),
            "tcp://127.0.0.1:30002".to_string(),
        ];
        let core = convert_config(config).unwrap();
        assert_eq!(core.peer_address.len(), 2);
        assert_eq!(core.peer_address[0].to_string(), "127.0.0.1:30001");
        assert_eq!(core.peer_address[1].to_string(), "tcp://127.0.0.1:30002");
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
    fn test_convert_config_keeps_broadcast_switch() {
        let mut config = new_test_config();
        config.no_broadcast = true;
        let core = convert_config(config).unwrap();
        assert!(core.no_broadcast);
    }

    /// 两个实例同时处于 Starting 互不影响
    #[test]
    fn test_two_instances_starting_independent() {
        let state = new_test_state();
        state.starting("a.toml").unwrap();
        state.starting("b.toml").unwrap();
        state.record_log("a.toml", "a 的日志");
        state.record_log("b.toml", "b 的日志");

        assert_eq!(state.status("a.toml"), VntStatus::Starting);
        assert_eq!(state.status("b.toml"), VntStatus::Starting);

        // a 启动失败停止，b 的状态和日志不受影响
        state.record_log_and_stopped("a.toml", "启动失败");
        assert_eq!(state.status("a.toml"), VntStatus::Stopped);
        assert_eq!(state.status("b.toml"), VntStatus::Starting);

        let lock = state.inner.lock();
        let a = lock.instances.get("a.toml").unwrap();
        assert!(a.start_logs.iter().any(|l| l.contains("启动失败")));
        let b = lock.instances.get("b.toml").unwrap();
        assert_eq!(b.start_logs.len(), 1);
        assert!(b.start_logs[0].contains("b 的日志"));
    }

    /// 网卡创建等启动步骤失败时，网络资源清理发生在错误日志写入之前。
    /// 清理阶段必须保留 Starting 实例，外层才能把具体错误返回给前端日志。
    #[test]
    fn test_starting_cleanup_preserves_failure_log() {
        let state = new_test_state();
        state.starting("a.toml").unwrap();
        state.record_log("a.toml", "正在创建 tun 虚拟网卡");

        state.stopped("a.toml");
        assert_eq!(state.status("a.toml"), VntStatus::Starting);

        state.record_log_and_stopped("a.toml", "启动失败: 创建 tun 虚拟网卡失败");

        let lock = state.inner.lock();
        let instance = lock.instances.get("a.toml").unwrap();
        assert_eq!(instance.status, VntStatus::Stopped);
        assert!(
            instance
                .start_logs
                .iter()
                .any(|log| log.contains("创建 tun 虚拟网卡失败"))
        );
    }

    /// 移除已停止实例：Stopped 可移除，Starting 拒绝
    #[tokio::test]
    async fn test_dismiss_instance() {
        let state = new_test_state();
        state.starting("a.toml").unwrap();
        state.record_log_and_stopped("a.toml", "启动失败");
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

    /// 同一 file_name 重复 starting 报错
    #[test]
    fn test_duplicate_starting_same_file() {
        let state = new_test_state();
        state.starting("a.toml").unwrap();
        assert!(state.starting("a.toml").is_err());
        // 不同 file_name 不受影响
        state.starting("b.toml").unwrap();
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

    /// tunnel_port 都为 Some 且相等时冲突
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
    }

    /// Starting 状态下执行停止：必须中断注册重试循环并迁移到 Stopped。
    /// 复现 bug 场景——服务器不可达时启动任务陷在无限重试里，
    /// 不中断启动任务则状态永远卡在 Starting。
    #[tokio::test]
    async fn test_stop_during_starting() {
        let state = new_test_state();
        let file_name = "a.toml";
        state.starting(file_name).unwrap();

        // 模拟启动任务：注册一直失败、5 秒重试的无限循环
        let state_clone = state.clone();
        let file_name_owned = file_name.to_string();
        let on_error_guard = defer(move || {
            state_clone.starting_to_stopped(&file_name_owned);
        });
        let handle = tokio::spawn(async move {
            let _on_error_guard = on_error_guard;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
        state.set_start_handle(file_name, handle);

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
}
