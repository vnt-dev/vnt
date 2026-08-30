use anyhow::{Context, bail};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_opener::OpenerExt;

#[cfg(windows)]
mod service_control;

static EXITING: AtomicBool = AtomicBool::new(false);
const KERNEL_CONFIG_FILE: &str = "web_access.toml";
const SIDECAR_STEM: &str = "vnt2-web";
#[cfg(windows)]
const SERVICE_CONTROL_FLAG: &str = "--vnt-service-control";
#[cfg(windows)]
const DESKTOP_CONFIG_FLAG: &str = "--desktop-config";

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
struct KernelConfig {
    listen_address: String,
    port: u16,
    token: String,
    auto_start: bool,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1".to_string(),
            port: 19099,
            token: generate_token(),
            auto_start: false,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct LegacyKernelConfig {
    listen_address: Option<String>,
    port: u16,
    token: String,
    auto_start: bool,
    global: bool,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KernelConfigInput {
    listen_address: String,
    port: u16,
    token: String,
    auto_start: bool,
}

impl From<KernelConfigInput> for KernelConfig {
    fn from(value: KernelConfigInput) -> Self {
        Self {
            listen_address: value.listen_address,
            port: value.port,
            token: value.token,
            auto_start: value.auto_start,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KernelStatus {
    running: bool,
    port: u16,
    listen_address: String,
    listen_endpoint: String,
    token: String,
    url: String,
    mode: &'static str,
    service_supported: bool,
    service_installed: bool,
    service_running: bool,
    auto_start: bool,
}

struct KernelRuntime {
    config: KernelConfig,
    child: Option<Child>,
}

impl Drop for KernelRuntime {
    fn drop(&mut self) {
        stop_child(self);
    }
}

struct DesktopState {
    kernel: tokio::sync::Mutex<KernelRuntime>,
    config_path: PathBuf,
    data_dir: PathBuf,
    executable_path: PathBuf,
    client: reqwest::Client,
}

#[cfg(not(windows))]
#[derive(Clone, Copy, Default)]
struct ServiceSnapshot {
    installed: bool,
    running: bool,
    auto_start: bool,
}

#[cfg(windows)]
use service_control::Snapshot as ServiceSnapshot;

fn generate_token() -> String {
    let mut bytes = [0_u8; 24];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn load_kernel_config(path: &Path) -> KernelConfig {
    let raw: LegacyKernelConfig = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default();
    let mut config = KernelConfig {
        listen_address: raw.listen_address.unwrap_or_else(|| {
            if raw.global {
                "0.0.0.0".to_string()
            } else {
                "127.0.0.1".to_string()
            }
        }),
        port: raw.port,
        token: raw.token,
        auto_start: raw.auto_start,
    };
    if validate_kernel_config(&config).is_err() {
        let defaults = KernelConfig::default();
        if config.listen_address.parse::<IpAddr>().is_err() {
            config.listen_address = defaults.listen_address;
        }
        if config.port == 0 {
            config.port = defaults.port;
        }
        if config.token.len() < 16 {
            config.token = defaults.token;
        }
    }
    config
}

fn save_kernel_config(path: &Path, config: &KernelConfig) -> anyhow::Result<()> {
    std::fs::write(path, toml::to_string_pretty(config)?)
        .with_context(|| format!("写入内核设置失败：{}", path.display()))?;
    Ok(())
}

fn validate_kernel_config(config: &KernelConfig) -> anyhow::Result<IpAddr> {
    let address: IpAddr = config
        .listen_address
        .parse()
        .context("监听地址必须是有效的 IPv4 或 IPv6 地址")?;
    if config.port == 0 {
        bail!("监听端口必须在 1-65535 之间");
    }
    if config.token.trim().len() < 16 {
        bail!("访问令牌至少需要 16 个字符");
    }
    Ok(address)
}

fn listen_endpoint(config: &KernelConfig) -> anyhow::Result<SocketAddr> {
    Ok(SocketAddr::new(
        validate_kernel_config(config)?,
        config.port,
    ))
}

fn client_endpoint(config: &KernelConfig) -> anyhow::Result<SocketAddr> {
    let listen = listen_endpoint(config)?;
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    Ok(SocketAddr::new(ip, listen.port()))
}

fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn access_endpoint(config: &KernelConfig) -> anyhow::Result<SocketAddr> {
    let listen = listen_endpoint(config)?;
    let ip = if listen.ip().is_unspecified() {
        lan_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    } else {
        listen.ip()
    };
    Ok(SocketAddr::new(ip, listen.port()))
}

fn access_url(config: &KernelConfig) -> anyhow::Result<String> {
    let mut url = reqwest::Url::parse(&format!("http://{}/", access_endpoint(config)?))?;
    url.query_pairs_mut().append_pair("token", &config.token);
    Ok(url.to_string())
}

fn api_url(config: &KernelConfig, path: &str) -> anyhow::Result<reqwest::Url> {
    Ok(reqwest::Url::parse(&format!(
        "http://{}{}",
        client_endpoint(config)?,
        path
    ))?)
}

fn sidecar_filename(target_suffix: bool) -> String {
    let extension = std::env::consts::EXE_EXTENSION;
    let suffix = if target_suffix {
        format!("-{}", env!("VNT_SIDECAR_TARGET"))
    } else {
        String::new()
    };
    if extension.is_empty() {
        format!("{SIDECAR_STEM}{suffix}")
    } else {
        format!("{SIDECAR_STEM}{suffix}.{extension}")
    }
}

#[cfg(windows)]
struct ServiceControlRequest {
    action: service_control::Action,
    config_path: PathBuf,
}

#[cfg(windows)]
fn parse_service_control_args<I>(args: I) -> anyhow::Result<Option<ServiceControlRequest>>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut args = args.into_iter();
    let Some(flag) = args.next() else {
        return Ok(None);
    };
    if flag != std::ffi::OsStr::new(SERVICE_CONTROL_FLAG) {
        return Ok(None);
    }
    let action = args
        .next()
        .context("缺少 VNT Web 服务操作")
        .and_then(|value| service_control::Action::parse(&value))?;
    let config_flag = args.next().context("缺少 --desktop-config 参数")?;
    if config_flag != std::ffi::OsStr::new(DESKTOP_CONFIG_FLAG) {
        bail!("VNT Web 服务操作只接受 --desktop-config 参数");
    }
    let config_path = PathBuf::from(args.next().context("缺少桌面端内核设置路径")?);
    if !config_path.is_absolute() {
        bail!("桌面端内核设置路径必须是绝对路径");
    }
    if args.next().is_some() {
        bail!("VNT Web 服务操作包含多余参数");
    }
    Ok(Some(ServiceControlRequest {
        action,
        config_path,
    }))
}

/// 在 Tauri 初始化前处理需要管理员权限的 Windows 服务控制子命令。
pub fn run_service_control_from_args() -> anyhow::Result<bool> {
    #[cfg(windows)]
    {
        let Some(request) = parse_service_control_args(std::env::args_os().skip(1))? else {
            return Ok(false);
        };
        let current_exe = std::env::current_exe().context("读取桌面程序路径失败")?;
        let sidecar_path = current_exe
            .parent()
            .context("桌面程序路径缺少父目录")?
            .join(sidecar_filename(false));
        service_control::execute(request.action, &sidecar_path, &request.config_path)?;
        Ok(true)
    }

    #[cfg(not(windows))]
    Ok(false)
}

fn resolve_sidecar_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("VNT_WEB_EXECUTABLE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }
    let current_exe = std::env::current_exe().context("读取桌面程序路径失败")?;
    let mut candidates = Vec::new();
    if let Some(dir) = current_exe.parent() {
        candidates.push(dir.join(sidecar_filename(false)));
        candidates.push(dir.join(if cfg!(windows) {
            "vnt2_web.exe"
        } else {
            "vnt2_web"
        }));
    }
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(sidecar_filename(true)),
    );
    candidates
        .into_iter()
        .find(|path| path.is_file() && path.metadata().is_ok_and(|meta| meta.len() > 0))
        .ok_or_else(|| anyhow::anyhow!("未找到内置 VNT Web 程序，请重新安装 VNT Desktop"))
}

fn stop_child(runtime: &mut KernelRuntime) {
    if let Some(mut child) = runtime.child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn child_running(runtime: &mut KernelRuntime) -> bool {
    runtime
        .child
        .as_mut()
        .is_some_and(|child| child.try_wait().ok().flatten().is_none())
}

fn spawn_child(
    runtime: &mut KernelRuntime,
    executable_path: &Path,
    config_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    stop_child(runtime);
    let mut command = Command::new(executable_path);
    command
        .arg("--desktop-config")
        .arg(config_path)
        .current_dir(data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    runtime.child =
        Some(command.spawn().with_context(|| {
            format!("启动内置 VNT Web 程序失败：{}", executable_path.display())
        })?);
    Ok(())
}

#[cfg(windows)]
fn service_snapshot() -> ServiceSnapshot {
    service_control::snapshot()
}

#[cfg(not(windows))]
fn service_snapshot() -> ServiceSnapshot {
    ServiceSnapshot::default()
}

#[cfg(windows)]
fn elevated_service_command(action: &str, config_path: &Path) -> anyhow::Result<()> {
    let action = service_control::Action::parse(std::ffi::OsStr::new(action))?;
    let desktop_path = std::env::current_exe().context("读取桌面程序路径失败")?;
    let status = runas::Command::new(&desktop_path)
        .arg(SERVICE_CONTROL_FLAG)
        .arg(action.as_str())
        .arg(DESKTOP_CONFIG_FLAG)
        .arg(config_path)
        .show(false)
        .gui(true)
        .status()
        .context("请求管理员权限失败")?;
    if !status.success() {
        bail!("VNT Web 服务操作未完成（可能取消了管理员授权）");
    }
    Ok(())
}

#[cfg(not(windows))]
fn elevated_service_command(_action: &str, _config_path: &Path) -> anyhow::Result<()> {
    bail!("当前系统暂不支持安装 VNT Web 服务")
}

async fn wait_until_ready(state: &DesktopState) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    loop {
        let config = state.kernel.lock().await.config.clone();
        let result = state
            .client
            .get(api_url(&config, "/api/version")?)
            .bearer_auth(&config.token)
            .send()
            .await;
        if result.is_ok_and(|response| response.status().is_success()) {
            return Ok(());
        }
        if started.elapsed() >= Duration::from_secs(10) {
            bail!("VNT Web 内核启动超时，请检查监听地址和端口是否被占用");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

async fn kernel_health(state: &DesktopState, config: &KernelConfig) -> bool {
    state
        .client
        .get(match api_url(config, "/api/version") {
            Ok(url) => url,
            Err(_) => return false,
        })
        .bearer_auth(&config.token)
        .send()
        .await
        .is_ok_and(|response| response.status().is_success())
}

async fn ensure_process_kernel(state: &DesktopState) -> anyhow::Result<bool> {
    if service_snapshot().installed {
        return Ok(false);
    }
    let mut runtime = state.kernel.lock().await;
    if child_running(&mut runtime) {
        return Ok(false);
    }
    spawn_child(
        &mut runtime,
        &state.executable_path,
        &state.config_path,
        &state.data_dir,
    )?;
    Ok(true)
}

async fn build_status(state: &DesktopState) -> Result<KernelStatus, String> {
    let config = state.kernel.lock().await.config.clone();
    let service = service_snapshot();
    let running = kernel_health(state, &config).await;
    Ok(KernelStatus {
        running,
        port: config.port,
        listen_address: config.listen_address.clone(),
        listen_endpoint: listen_endpoint(&config)
            .map_err(|error| error.to_string())?
            .to_string(),
        token: config.token.clone(),
        url: access_url(&config).map_err(|error| error.to_string())?,
        mode: if service.installed {
            "service"
        } else {
            "process"
        },
        service_supported: cfg!(windows),
        service_installed: service.installed,
        service_running: service.running,
        auto_start: if service.installed {
            service.auto_start
        } else {
            config.auto_start
        },
    })
}

#[tauri::command]
async fn api_request(
    state: tauri::State<'_, DesktopState>,
    method: String,
    path: String,
    body: Option<String>,
) -> Result<serde_json::Value, String> {
    if !path.starts_with("/api/") {
        return Err("只允许调用 VNT API".to_string());
    }
    if ensure_process_kernel(&state)
        .await
        .map_err(|error| error.to_string())?
    {
        wait_until_ready(&state)
            .await
            .map_err(|error| error.to_string())?;
    }
    let config = state.kernel.lock().await.config.clone();
    let method: reqwest::Method = method.parse().map_err(|_| "HTTP 方法无效".to_string())?;
    let mut request = state
        .client
        .request(
            method,
            api_url(&config, &path).map_err(|error| error.to_string())?,
        )
        .bearer_auth(&config.token);
    if let Some(body) = body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("无法连接 VNT Web 内核：{error}"))?;
    response
        .json()
        .await
        .map_err(|error| format!("VNT Web 内核返回了无效响应：{error}"))
}

#[tauri::command]
async fn kernel_status(state: tauri::State<'_, DesktopState>) -> Result<KernelStatus, String> {
    if ensure_process_kernel(&state)
        .await
        .map_err(|error| error.to_string())?
    {
        wait_until_ready(&state)
            .await
            .map_err(|error| error.to_string())?;
    }
    build_status(&state).await
}

#[tauri::command]
async fn save_and_restart_kernel(
    state: tauri::State<'_, DesktopState>,
    config: KernelConfigInput,
) -> Result<KernelStatus, String> {
    let config: KernelConfig = config.into();
    validate_kernel_config(&config).map_err(|error| error.to_string())?;
    let service = service_snapshot();
    if config.auto_start && !service.installed {
        return Err("请先安装为系统服务，再启用开机启动".to_string());
    }

    if service.installed {
        {
            let mut runtime = state.kernel.lock().await;
            runtime.config = config;
            save_kernel_config(&state.config_path, &runtime.config)
                .map_err(|error| error.to_string())?;
        }
        let config_path = state.config_path.clone();
        tokio::task::spawn_blocking(move || elevated_service_command("restart", &config_path))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error| error.to_string())?;
    } else {
        let mut runtime = state.kernel.lock().await;
        let previous = runtime.config.clone();
        stop_child(&mut runtime);
        runtime.config = config;
        if let Err(error) = save_kernel_config(&state.config_path, &runtime.config).and_then(|_| {
            spawn_child(
                &mut runtime,
                &state.executable_path,
                &state.config_path,
                &state.data_dir,
            )
        }) {
            runtime.config = previous;
            let _ = save_kernel_config(&state.config_path, &runtime.config);
            let _ = spawn_child(
                &mut runtime,
                &state.executable_path,
                &state.config_path,
                &state.data_dir,
            );
            return Err(format!("重启 VNT Web 内核失败：{error:#}"));
        }
    }
    wait_until_ready(&state)
        .await
        .map_err(|error| error.to_string())?;
    build_status(&state).await
}

#[tauri::command]
async fn install_kernel_service(
    state: tauri::State<'_, DesktopState>,
) -> Result<KernelStatus, String> {
    if !cfg!(windows) {
        return Err("当前系统暂不支持安装 VNT Web 服务".to_string());
    }
    if service_snapshot().installed {
        return build_status(&state).await;
    }

    {
        let mut runtime = state.kernel.lock().await;
        stop_child(&mut runtime);
        save_kernel_config(&state.config_path, &runtime.config)
            .map_err(|error| error.to_string())?;
    }
    let config_path = state.config_path.clone();
    let result =
        tokio::task::spawn_blocking(move || elevated_service_command("install", &config_path))
            .await
            .map_err(|error| error.to_string())?;
    if let Err(error) = result {
        let mut runtime = state.kernel.lock().await;
        let _ = spawn_child(
            &mut runtime,
            &state.executable_path,
            &state.config_path,
            &state.data_dir,
        );
        return Err(error.to_string());
    }
    wait_until_ready(&state)
        .await
        .map_err(|error| error.to_string())?;
    build_status(&state).await
}

#[tauri::command]
async fn uninstall_kernel_service(
    state: tauri::State<'_, DesktopState>,
) -> Result<KernelStatus, String> {
    if !cfg!(windows) {
        return Err("当前系统不支持 VNT Web 服务".to_string());
    }
    if !service_snapshot().installed {
        if ensure_process_kernel(&state)
            .await
            .map_err(|error| error.to_string())?
        {
            wait_until_ready(&state)
                .await
                .map_err(|error| error.to_string())?;
        }
        return build_status(&state).await;
    }

    let config_path = state.config_path.clone();
    tokio::task::spawn_blocking(move || elevated_service_command("uninstall", &config_path))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;

    {
        let mut runtime = state.kernel.lock().await;
        runtime.config.auto_start = false;
        save_kernel_config(&state.config_path, &runtime.config)
            .map_err(|error| error.to_string())?;
        spawn_child(
            &mut runtime,
            &state.executable_path,
            &state.config_path,
            &state.data_dir,
        )
        .map_err(|error| format!("服务已卸载，但启动桌面内核失败：{error:#}"))?;
    }
    wait_until_ready(&state)
        .await
        .map_err(|error| error.to_string())?;
    build_status(&state).await
}

#[tauri::command]
async fn prepare_app_update(state: tauri::State<'_, DesktopState>) -> Result<bool, String> {
    if !service_snapshot().installed {
        return Ok(false);
    }

    let config_path = state.config_path.clone();
    tokio::task::spawn_blocking(move || elevated_service_command("stop", &config_path))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| format!("更新前停止 VNT Web 服务失败：{error:#}"))?;
    Ok(true)
}

#[tauri::command]
async fn restore_service_after_update(state: tauri::State<'_, DesktopState>) -> Result<(), String> {
    if !service_snapshot().installed {
        return Ok(());
    }

    let config_path = state.config_path.clone();
    tokio::task::spawn_blocking(move || elevated_service_command("restart", &config_path))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| format!("恢复 VNT Web 服务失败：{error:#}"))?;
    wait_until_ready(&state)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn generate_web_token() -> String {
    generate_token()
}

#[tauri::command]
fn open_web_url(app: AppHandle, url: String) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("只允许打开 HTTP(S) 地址".to_string());
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|error| error.to_string())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn toggle_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        match window.is_visible() {
            Ok(true) => {
                let _ = window.hide();
            }
            _ => show_main_window(app),
        }
    }
}

fn install_rustls_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub fn run() -> Result<(), tauri::Error> {
    // reqwest 使用 rustls-no-provider，必须在 Tauri 插件或 HTTP 客户端初始化前
    // 明确选择整个桌面进程统一使用的 ring Provider。
    install_rustls_crypto_provider();
    let app = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            api_request,
            kernel_status,
            save_and_restart_kernel,
            install_kernel_service,
            uninstall_kernel_service,
            prepare_app_update,
            restore_service_after_update,
            generate_web_token,
            open_web_url
        ])
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let config_path = data_dir.join(KERNEL_CONFIG_FILE);
            let mut config = load_kernel_config(&config_path);
            let service = service_snapshot();
            config.auto_start = service.installed && service.auto_start;
            save_kernel_config(&config_path, &config)?;
            let executable_path = resolve_sidecar_path()?;
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?;
            let mut runtime = KernelRuntime {
                config,
                child: None,
            };
            if service.installed {
                if !service.running
                    && let Err(error) = elevated_service_command("restart", &config_path)
                {
                    eprintln!("无法启动 VNT Web Windows 服务：{error:#}");
                }
            } else {
                spawn_child(&mut runtime, &executable_path, &config_path, &data_dir)?;
            }
            app.manage(DesktopState {
                kernel: tokio::sync::Mutex::new(runtime),
                config_path,
                data_dir,
                executable_path,
                client,
            });

            let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "退出 VNT", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let mut tray = TrayIconBuilder::with_id("vnt-tray")
                .tooltip("VNT Desktop")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => {
                        EXITING.store(true, Ordering::SeqCst);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        toggle_main_window(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event
                && !EXITING.load(Ordering::SeqCst)
            {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())?;

    app.run(|app, event| {
        if let tauri::RunEvent::Exit = event
            && let Some(state) = app.try_state::<DesktopState>()
            && let Ok(mut runtime) = state.kernel.try_lock()
        {
            stop_child(&mut runtime);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installs_ring_before_building_reqwest_client() {
        install_rustls_crypto_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        reqwest::Client::builder().build().unwrap();
    }

    #[test]
    fn migrates_old_global_setting() {
        let raw: LegacyKernelConfig = toml::from_str(
            "enabled = false\nport = 20000\nglobal = true\ntoken = \"1234567890123456\"\n",
        )
        .unwrap();
        assert!(raw.global);
        assert!(raw.listen_address.is_none());
    }

    #[test]
    fn wildcard_listen_uses_loopback_for_desktop_requests() {
        let config = KernelConfig {
            listen_address: "0.0.0.0".to_string(),
            ..KernelConfig::default()
        };
        assert_eq!(
            client_endpoint(&config).unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[cfg(windows)]
    #[test]
    fn parses_service_control_command_before_tauri_startup() {
        let request = parse_service_control_args([
            std::ffi::OsString::from(SERVICE_CONTROL_FLAG),
            std::ffi::OsString::from("restart"),
            std::ffi::OsString::from(DESKTOP_CONFIG_FLAG),
            std::ffi::OsString::from(r"C:\Users\test\web_access.toml"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(request.action, service_control::Action::Restart);
        assert!(request.config_path.is_absolute());
    }

    #[cfg(windows)]
    #[test]
    fn ignores_normal_desktop_arguments() {
        assert!(
            parse_service_control_args([std::ffi::OsString::from("--some-app-argument")])
                .unwrap()
                .is_none()
        );
    }
}
