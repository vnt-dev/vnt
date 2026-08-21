use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[cfg(windows)]
mod extract_wintun_dll;

/// vnt web服务
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 本地http服务监听地址
    #[clap(long)]
    addr: Option<SocketAddr>,
    /// 加载vnt配置路径，配置内容参考web端的配置格式
    #[clap(long)]
    conf: Option<PathBuf>,
    /// Web API 访问令牌；未指定时会生成随机令牌并输出到日志
    #[clap(long, env = "VNT_WEB_TOKEN")]
    token: Option<String>,
}

#[tokio::main]
pub async fn main() {
    if let Err(e) = main0().await {
        log::error!("{:?}", e);
    }
}
async fn main0() -> anyhow::Result<()> {
    let args = Args::parse();

    vnt2::log::log_init("vnt2");
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
    vnt_web::run_http_server(addr, args.conf, token).await?;
    Ok(())
}
