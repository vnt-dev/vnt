use crate::defer;
use anyhow::{Context, anyhow, bail};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::IntoResponse;
use axum::{
    Json, Router,
    extract::{Query, Request, State},
    middleware,
    response::Response,
    routing::{get, post},
};
use ipnet::Ipv4Net;
use mime_guess::from_path;
use parking_lot::Mutex;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::{OffsetDateTime, format_description};
use tokio::fs;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use vnt_core::api::VntApi;
use vnt_core::context::config::Config as CoreConfig;
use vnt_core::core::{DEFAULT_MTU, NetworkManager, RegisterResponse};
use vnt_core::nat::NetInput;
use vnt_core::port_mapping::PortMapping;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_core::utils::task_control::TaskGroupManager;

const CONFIG_DIR: &str = "vnt_config";
const CURRENT_CONFIG_RECORD: &str = "vnt_current_config.txt";

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
enum VntStatus {
    #[default]
    Stopped,
    Starting,
    Running,
}

#[derive(Clone)]
struct HttpAppState {
    task_group_manager: TaskGroupManager,
    inner: Arc<Mutex<HttpAppStateInner>>,
}

#[derive(Default)]
struct HttpAppStateInner {
    vnt: Option<VntHandler>,
    status: VntStatus,
    start_logs: Vec<String>,
}

impl HttpAppState {
    fn starting(&self) -> anyhow::Result<()> {
        let mut inner = self.inner.lock();
        if inner.status != VntStatus::Stopped {
            return Err(anyhow!("VNT is already starting or running"));
        }
        if inner.vnt.is_some() {
            return Err(anyhow!("VNT is already running"));
        }
        inner.status = VntStatus::Starting;
        inner.start_logs.clear();
        Ok(())
    }
    fn stopped(&self) {
        let mut inner = self.inner.lock();
        inner.vnt.take();
        inner.status = VntStatus::Stopped;
    }
    fn starting_to_stopped(&self) {
        let mut inner = self.inner.lock();
        if inner.status != VntStatus::Starting {
            return;
        }
        inner.vnt.take();
        inner.status = VntStatus::Stopped;
        inner
            .start_logs
            .push(format!("[{}] 启动中断", HttpAppState::timestamp()));
    }
    fn starting_to_running(&self) {
        let mut inner = self.inner.lock();
        if inner.status != VntStatus::Starting {
            log::error!("starting_to_running VNT is not starting");
            return;
        }
        inner.status = VntStatus::Running;
        inner.start_logs.clear();
    }

    fn record_log(&self, msg: impl Into<String>) {
        let mut inner = self.inner.lock();
        if inner.status != VntStatus::Starting {
            return;
        }
        inner
            .start_logs
            .push(format!("[{}] {}", Self::timestamp(), msg.into()));
    }
    fn record_log_and_stopped(&self, msg: impl Into<String>) {
        let mut inner = self.inner.lock();
        if inner.status != VntStatus::Starting {
            return;
        }
        inner
            .start_logs
            .push(format!("[{}] {}", Self::timestamp(), msg.into()));
        inner.status = VntStatus::Stopped;
    }
    fn status(&self) -> VntStatus {
        self.inner.lock().status
    }

    fn timestamp() -> String {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let format = format_description::parse("[hour]:[minute]:[second]").unwrap();
        now.format(&format)
            .unwrap_or_else(|_| "00:00:00".to_string())
    }
}

struct VntHandler {
    api: VntApi,
    config_name: String,
    config_file_name: String,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StartConfig {
    pub config_name: Option<String>,
    pub server: Vec<String>,
    pub cert_mode: Option<String>,
    pub network_code: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_name: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub password: Option<String>,
    #[serde(default)]
    pub no_punch: bool,
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
    pub no_tun: bool,
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

async fn get_start_status(
    State(state): State<HttpAppState>,
) -> Json<ApiResponse<StartStatusResponse>> {
    let lock = state.inner.lock();
    Json(ApiResponse::success(StartStatusResponse {
        status: lock.status,
        logs: lock.start_logs.clone(),
    }))
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

pub async fn run_http_server(
    addr: SocketAddr,
    start_config_file_name: Option<PathBuf>,
) -> anyhow::Result<()> {
    fs::create_dir_all(CONFIG_DIR)
        .await
        .context("Failed to create config directory")?;

    let state = HttpAppState {
        task_group_manager: TaskGroupManager::new(),
        inner: Arc::new(Default::default()),
    };

    // 自动启动逻辑
    let auto_start_file = determine_auto_start_file(start_config_file_name).await;

    if let Some((file_name, path)) = auto_start_file {
        log::info!("Auto starting VNT with config: {:?}", path);
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = start_vnt_internal(&state_clone, file_name, path).await {
                log::error!("Auto start failed: {:?}", e);
            }
        });
    }

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/api/info", get(get_info))
        .route("/api/peers", get(get_peers))
        .route("/api/routes", get(get_routes))
        .route("/api/start/status", get(get_start_status))
        .route("/api/start", post(start_vnt_handler))
        .route("/api/stop", post(stop_vnt_handler))
        .route("/api/restart", post(restart_vnt_handler))
        .route("/api/config/list", get(list_configs))
        .route(
            "/api/config",
            get(get_config).post(save_config).delete(delete_config),
        )
        .layer(cors)
        .layer(middleware::from_fn(logging_middleware))
        .with_state(state)
        .fallback(static_handler);

    log::info!("HTTP API Listening on http://{}", addr);
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

/// 确定自动启动的配置文件
async fn determine_auto_start_file(
    start_config_file_name: Option<PathBuf>,
) -> Option<(String, PathBuf)> {
    let path = if let Some(name) = start_config_file_name {
        Some(name)
    } else if Path::new(CURRENT_CONFIG_RECORD).exists() {
        fs::read_to_string(CURRENT_CONFIG_RECORD)
            .await
            .ok()
            .filter(|content| !content.trim().is_empty())
            .map(|content| Path::new(CONFIG_DIR).join(content.trim()))
    } else {
        None
    };

    path.and_then(|p| {
        let file_name = p.file_name()?.to_str()?.to_string();
        if p.exists() {
            Some((file_name, p))
        } else {
            log::warn!("Auto start config file not found: {:?}", p);
            None
        }
    })
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
        HeaderValue::from_str(mime.as_ref()).unwrap(),
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
async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    // 先尝试从本地文件读取
    let local_path = Path::new("static").join(path);
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

/// 启动 VNT 服务的入口函数
async fn start_vnt_internal(
    state: &HttpAppState,
    file_name: String,
    file_path: PathBuf,
) -> anyhow::Result<()> {
    log::info!("Starting VNT service: {}", file_name);
    state.starting()?;

    let state_for_error = state.clone();
    let on_error_guard = defer(move || {
        state_for_error.starting_to_stopped();
    });

    state.record_log(format!("启动配置: {}", file_name));
    state.record_log("读取配置文件");

    // 读取并解析配置
    let content = fs::read_to_string(&file_path)
        .await
        .with_context(|| format!("Config file not found: {:?}", file_path))?;

    state.record_log("解析配置文件内容");
    let cfg: StartConfig = toml::from_str(&content).context("Failed to parse TOML config")?;

    let config_display_name = cfg.config_name.clone().unwrap_or_else(|| file_name.clone());
    let core_config = convert_config(cfg)?;
    let sub_input = core_config.input.clone();

    state.record_log("创建异步任务组");
    let (task_group, task_group_guard) = state
        .task_group_manager
        .create_task()
        .context("Create task failed")?;

    state.record_log("创建组网管理器");

    let state_clone = state.clone();
    tokio::spawn(async move {
        let result = start_vnt_network(
            state_clone.clone(),
            file_name,
            config_display_name,
            core_config,
            sub_input,
            task_group,
            task_group_guard,
        )
        .await;

        if let Err(e) = result {
            log::error!("Failed to start VNT network: {:?}", e);
            state_clone.record_log_and_stopped(format!("启动失败: {}", e));
        }
        drop(on_error_guard);
    });

    Ok(())
}

/// 执行实际的网络启动操作
async fn start_vnt_network(
    state: HttpAppState,
    file_name: String,
    config_display_name: String,
    core_config: CoreConfig,
    sub_input: Vec<NetInput>,
    task_group: vnt_core::utils::task_control::TaskGroup,
    task_group_guard: vnt_core::utils::task_control::TaskGroupGuard,
) -> anyhow::Result<()> {
    let mut network_manager =
        NetworkManager::create_network(Box::new(core_config), task_group.clone())
            .await
            .map_err(|e| anyhow!("Create network failed: {:?}", e))?;

    let vnt_api = network_manager.vnt_api();

    {
        let mut lock = state.inner.lock();
        if lock.vnt.is_some() {
            return Err(anyhow!("VNT is already running"));
        }
        lock.vnt = Some(VntHandler {
            api: vnt_api,
            config_name: config_display_name,
            config_file_name: file_name.clone(),
        });
    }

    let state_for_vnt_cleanup = state.clone();
    let vnt_cleanup_guard = defer(move || {
        state_for_vnt_cleanup.stopped();
    });

    state.record_log("连接服务器，执行注册");
    log::info!("Registering with server");

    let reg_msg = loop {
        let reg_msg = match network_manager.register().await {
            Ok(rs) => rs,
            Err(e) => {
                log::error!("Register failed: {:?}", e);
                state.record_log(format!("注册失败:{},5秒后重试", e));
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
    state.record_log(format!("注册成功 {}/{}", reg_msg.ip, reg_msg.prefix_len));
    log::info!("Network Started: {}/{}", reg_msg.ip, reg_msg.prefix_len);
    if !network_manager.is_no_tun() {
        state.record_log("正在创建 TUN 虚拟网卡");
        network_manager.start_tun().await?;

        state.record_log("创建 TUN 虚拟网卡成功，设置 IP");
        network_manager
            .set_tun_network_ip(reg_msg.ip, reg_msg.prefix_len)
            .await?;
        state.record_log("设置 IP 成功");

        // 配置子网路由
        if !sub_input.is_empty()
            && let Ok(if_index) = network_manager.tun_if_index().await
            && let Ok(mut route_manager) = route_manager::RouteManager::new()
        {
            state.record_log("配置子网路由");
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
    }

    state.starting_to_running();

    // 启动网络管理任务
    task_group.spawn(async move {
        network_manager.wait_all_stopped().await;
        drop(task_group_guard);
        drop(network_manager);
        drop(vnt_cleanup_guard);
        log::info!("Network manager stopped.");
    });

    // 记录当前配置
    if let Err(e) = fs::write(CURRENT_CONFIG_RECORD, &file_name).await {
        log::warn!("Failed to record current config: {}", e);
    }
    Ok(())
}

fn is_valid_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && !file_name.contains("..")
        && !file_name.contains('/')
        && !file_name.contains('\\')
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

async fn stop_vnt_handler(State(state): State<HttpAppState>) -> Json<ApiResponse<()>> {
    if state.status() == VntStatus::Stopped {
        return Json(ApiResponse::error("Vnt stopped"));
    }
    state.task_group_manager.stop();

    let _ = fs::write(CURRENT_CONFIG_RECORD, "").await;
    Json(ApiResponse::success(()))
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
    if state.status() != VntStatus::Stopped {
        state.task_group_manager.stop();
        // 等待停止完成
        for _ in 0..50 {
            if state.status() == VntStatus::Stopped {
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

async fn get_info(State(state): State<HttpAppState>) -> Json<ApiResponse<HttpAppInfo>> {
    let lock = state.inner.lock();
    let status = lock.status;

    let info = if let Some(handler) = lock.vnt.as_ref() {
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
        }
    } else {
        HttpAppInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            status,
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
    if let Err(e) = toml::from_str::<StartConfig>(&req.config) {
        log::warn!("Failed to parse configuration: {:?}", e);
        return Json(ApiResponse::error(format!("Invalid TOML format: {}", e)));
    }

    let file_name = req
        .file_name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            format!("{}.toml", now)
        });

    if !is_valid_file_name(&file_name) {
        return Json(ApiResponse::error("Invalid file name"));
    }

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
        if let Some(vnt) = &state.inner.lock().vnt
            && vnt.config_file_name == req.file_name
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
    let server_addrs: Vec<ProtocolAddress> = cfg
        .server
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow!("invalid server address '{}': {}", s, e))
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
        network_code: cfg.network_code,
        ip: cfg.ip,
        no_punch: cfg.no_punch,
        rtx: cfg.rtx,
        compress: cfg.compress,
        device_id,
        device_name,
        tun_name: cfg.tun_name,
        password: cfg.password,
        cert_mode,
        input: cfg.input,
        output: cfg.output,
        no_nat: cfg.no_nat,
        no_tun: cfg.no_tun,
        mtu: cfg.mtu,
        port_mapping,
        allow_port_mapping: cfg.allow_mapping,
        udp_stun,
        tcp_stun,
        fec: cfg.fec,
        tunnel_port: cfg.tunnel_port,
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

async fn get_peers(State(state): State<HttpAppState>) -> Json<ApiResponse<Vec<HttpClientItem>>> {
    let api = state.inner.lock().vnt.as_ref().map(|v| v.api.clone());

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

async fn get_routes(State(state): State<HttpAppState>) -> Json<ApiResponse<Vec<HttpRouteItem>>> {
    let lock = state.inner.lock();

    let Some(handler) = lock.vnt.as_ref() else {
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
