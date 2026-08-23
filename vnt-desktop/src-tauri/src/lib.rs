use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};
use tauri_plugin_opener::OpenerExt;
use tokio_util::sync::CancellationToken;
use vnt_web::VntService;

#[cfg(windows)]
mod wintun;

static EXITING: AtomicBool = AtomicBool::new(false);
const WEB_ACCESS_CONFIG: &str = "web_access.toml";

#[derive(Clone, Deserialize, Serialize)]
#[serde(default)]
struct WebAccessConfig {
    enabled: bool,
    port: u16,
    global: bool,
    token: String,
}

impl Default for WebAccessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 19099,
            global: false,
            token: vnt_web::generate_access_token(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WebAccessStatus {
    enabled: bool,
    running: bool,
    port: u16,
    global: bool,
    token: String,
    url: String,
    listen_address: String,
}

struct WebRuntime {
    config: WebAccessConfig,
    cancellation: Option<CancellationToken>,
    handle: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

struct DesktopState {
    service: VntService,
    web: tokio::sync::Mutex<WebRuntime>,
    config_path: PathBuf,
}

fn load_web_config(path: &Path) -> WebAccessConfig {
    let mut config: WebAccessConfig = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default();
    if config.port == 0 {
        config.port = 19099;
    }
    if config.token.len() < 16 {
        config.token = vnt_web::generate_access_token();
    }
    config
}

fn save_web_config(path: &Path, config: &WebAccessConfig) -> anyhow::Result<()> {
    std::fs::write(path, toml::to_string_pretty(config)?)?;
    Ok(())
}

fn listen_addr(config: &WebAccessConfig) -> SocketAddr {
    let ip = if config.global {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    SocketAddr::new(ip, config.port)
}

fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

fn access_url(config: &WebAccessConfig) -> String {
    let host = if config.global {
        lan_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    format!("http://{}:{}/?token={}", host, config.port, config.token)
}

async fn stop_web(runtime: &mut WebRuntime) {
    if let Some(cancellation) = runtime.cancellation.take() {
        cancellation.cancel();
    }
    if let Some(handle) = runtime.handle.take() {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => log::warn!("Web service stopped with error: {error:#}"),
            Err(error) if !error.is_cancelled() => log::warn!("Web service task failed: {error}"),
            Err(_) => {}
        }
    }
}

async fn start_web(service: &VntService, runtime: &mut WebRuntime) -> anyhow::Result<()> {
    if !runtime.config.enabled {
        return Ok(());
    }
    let cancellation = CancellationToken::new();
    let handle = service
        .start_http(
            listen_addr(&runtime.config),
            runtime.config.token.clone(),
            cancellation.clone(),
        )
        .await?;
    runtime.cancellation = Some(cancellation);
    runtime.handle = Some(handle);
    Ok(())
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
    state
        .service
        .request(&method, &path, body)
        .await
        .map_err(|error| format!("{error:#}"))
}

fn web_status(runtime: &WebRuntime) -> WebAccessStatus {
    WebAccessStatus {
        enabled: runtime.config.enabled,
        running: runtime
            .handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished()),
        port: runtime.config.port,
        global: runtime.config.global,
        token: runtime.config.token.clone(),
        url: access_url(&runtime.config),
        listen_address: listen_addr(&runtime.config).to_string(),
    }
}

#[tauri::command]
async fn web_access_status(
    state: tauri::State<'_, DesktopState>,
) -> Result<WebAccessStatus, String> {
    let runtime = state.web.lock().await;
    Ok(web_status(&runtime))
}

#[tauri::command]
async fn update_web_access(
    state: tauri::State<'_, DesktopState>,
    config: WebAccessConfig,
) -> Result<WebAccessStatus, String> {
    if config.port == 0 {
        return Err("监听端口必须在 1-65535 之间".to_string());
    }
    if config.token.len() < 16 {
        return Err("访问令牌至少需要 16 个字符".to_string());
    }

    let mut runtime = state.web.lock().await;
    stop_web(&mut runtime).await;
    let previous = runtime.config.clone();
    runtime.config = config;
    if let Err(error) = start_web(&state.service, &mut runtime).await {
        runtime.config = previous;
        if let Err(restore_error) = start_web(&state.service, &mut runtime).await {
            log::error!("Failed to restore Web service: {restore_error:#}");
        }
        return Err(format!("无法启动 Web 服务：{error:#}"));
    }
    save_web_config(&state.config_path, &runtime.config)
        .map_err(|error| format!("保存 Web 访问设置失败：{error:#}"))?;
    Ok(web_status(&runtime))
}

#[tauri::command]
fn generate_web_token() -> String {
    vnt_web::generate_access_token()
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

pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            api_request,
            web_access_status,
            update_web_access,
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
            std::env::set_current_dir(&data_dir)?;
            vnt2::log::log_init("vnt-desktop");

            #[cfg(windows)]
            wintun::ensure_wintun(&data_dir)?;

            let config_path = data_dir.join(WEB_ACCESS_CONFIG);
            let config = load_web_config(&config_path);
            save_web_config(&config_path, &config)?;
            let service = tauri::async_runtime::block_on(VntService::new_desktop(None))?;
            let mut web = WebRuntime {
                config,
                cancellation: None,
                handle: None,
            };
            if let Err(error) = tauri::async_runtime::block_on(start_web(&service, &mut web)) {
                log::error!("Failed to restore Web access service: {error:#}");
                web.config.enabled = false;
                save_web_config(&config_path, &web.config)?;
            }
            app.manage(DesktopState {
                service,
                web: tokio::sync::Mutex::new(web),
                config_path,
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
        .run(tauri::generate_context!())
}
