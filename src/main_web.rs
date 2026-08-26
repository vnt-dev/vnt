use anyhow::{Context, bail};
use clap::Parser;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

#[cfg(windows)]
mod extract_wintun_dll;
#[cfg(windows)]
mod web_service;

/// VNT Web 服务。
#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// 本地 HTTP 服务监听地址。
    #[arg(long)]
    addr: Option<SocketAddr>,
    /// 加载 VNT 配置路径，配置内容参考 Web 端的配置格式。
    #[arg(long)]
    conf: Option<PathBuf>,
    /// Web API 访问令牌；未指定时会生成随机令牌并输出到日志。
    #[arg(long, env = "VNT_WEB_TOKEN")]
    token: Option<String>,
    /// 读取桌面端保存的内核设置。
    #[arg(long, hide = true)]
    desktop_config: Option<PathBuf>,
    /// 由 Windows 服务控制管理器启动。
    #[cfg(windows)]
    #[arg(long, hide = true)]
    service: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub(crate) struct DesktopKernelConfig {
    listen_address: String,
    port: u16,
    token: String,
}

impl Default for DesktopKernelConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1".to_string(),
            port: 19099,
            token: String::new(),
        }
    }
}

impl DesktopKernelConfig {
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(
            &std::fs::read_to_string(path)
                .with_context(|| format!("读取桌面端内核设置失败：{}", path.display()))?,
        )
        .context("解析桌面端内核设置失败")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let _: std::net::IpAddr = self
            .listen_address
            .parse()
            .context("桌面端内核监听地址无效")?;
        if self.port == 0 {
            bail!("桌面端内核监听端口不能为 0");
        }
        if self.token.len() < 16 {
            bail!("桌面端内核访问令牌至少需要 16 个字符");
        }
        Ok(())
    }

    fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(SocketAddr::new(self.listen_address.parse()?, self.port))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    #[cfg(windows)]
    {
        if args.service {
            return web_service::dispatch(args);
        }
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("创建异步运行时失败")?
        .block_on(run_server(args, None))
}

pub(crate) async fn run_server(
    mut args: Args,
    service_cancellation: Option<CancellationToken>,
) -> anyhow::Result<()> {
    if let Some(config_path) = args.desktop_config.as_deref() {
        let config = DesktopKernelConfig::load(config_path)?;
        args.addr = Some(config.socket_addr()?);
        args.token = Some(config.token);
        let data_dir = config_path
            .parent()
            .context("桌面端内核设置路径缺少父目录")?;
        std::fs::create_dir_all(data_dir)?;
        std::env::set_current_dir(data_dir)
            .with_context(|| format!("切换数据目录失败：{}", data_dir.display()))?;
    }

    vnt2::log::log_init("vnt2-web");
    log::info!("version: {:?}", env!("CARGO_PKG_VERSION"));
    #[cfg(windows)]
    extract_wintun_dll::extract_wintun();

    let addr = args.addr.unwrap_or("127.0.0.1:19099".parse()?);
    let token = args.token.unwrap_or_else(vnt_web::generate_access_token);
    let browser_host = if addr.ip().is_unspecified() {
        "127.0.0.1".to_string()
    } else {
        addr.ip().to_string()
    };
    log::info!("Web access token: {}", token);
    log::info!(
        "Web access URL: http://{}:{}/?token={}",
        browser_host,
        addr.port(),
        token
    );

    let service = vnt_web::VntService::new(args.conf).await?;
    let cancellation = CancellationToken::new();
    let handle = service
        .start_http(addr, token, cancellation.clone())
        .await?;

    if let Some(service_cancellation) = service_cancellation {
        service_cancellation.cancelled().await;
    } else {
        shutdown_signal().await?;
    }
    cancellation.cancel();
    handle.await??;
    Ok(())
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
