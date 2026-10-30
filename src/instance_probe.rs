//! 抢锁失败后的探测：找出本机已有的客户端，把它的状态打印出来。
//!
//! 单实例锁只能告诉调用方"已被占用"，但用户真正需要知道的是"谁在占用、
//! 现在是什么状态"。这里依次尝试两条路径：
//!
//! 1. `vnt2_cli` 的 ctrl IPC（完整状态），由 [`crate::main_cli`] 直接调用
//!    `vnt_ipc::client`，因此不在本模块内。
//! 2. VNT Desktop 内核的 HTTP API：先读它写下的 `web_access.toml` 拿到
//!    监听地址与令牌，再请求 `/api/instances` 列出实例。
//!
//! 探测是"尽力而为"的：任何一步失败都只降级为更少的输出，不影响主流程。

use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 桌面端内核未写配置时的默认监听端口。
const DEFAULT_KERNEL_PORT: u16 = 19099;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1200);
const READ_TIMEOUT: Duration = Duration::from_millis(1500);

/// VNT Desktop 内核记录下来的接入信息（字段与 `web_access.toml` 对应）。
#[derive(Debug, serde::Deserialize)]
struct KernelAccess {
    #[serde(default = "default_listen_address")]
    listen_address: String,
    #[serde(default = "default_kernel_port")]
    port: u16,
    #[serde(default)]
    token: String,
}

fn default_listen_address() -> String {
    "127.0.0.1".to_string()
}

fn default_kernel_port() -> u16 {
    DEFAULT_KERNEL_PORT
}

#[derive(Debug, serde::Deserialize)]
struct ApiEnvelope<T> {
    #[serde(default)]
    code: i32,
    #[serde(default)]
    msg: String,
    data: Option<T>,
}

#[derive(Debug, serde::Deserialize)]
struct InstanceSummary {
    #[serde(default)]
    config_name: String,
    #[serde(default)]
    status: String,
}

/// 探测 VNT Desktop 内核，返回可直接打印的状态描述。
///
/// `None` 表示没有探测到桌面端内核在运行。
pub async fn probe_desktop_kernel() -> Option<String> {
    let access = read_kernel_access()?;
    let addr = format!("{}:{}", access.listen_address, access.port);
    let body = http_get_body(&addr, "/api/instances", &access.token).await?;
    let envelope: ApiEnvelope<Vec<InstanceSummary>> = serde_json::from_str(&body).ok()?;
    if envelope.code != 0 {
        return Some(format!(
            "VNT Desktop 内核在 {addr} 运行，但查询实例失败：{}",
            envelope.msg
        ));
    }
    let instances = envelope.data.unwrap_or_default();
    let mut lines = vec![format!("VNT Desktop 内核在 {addr} 运行，实例：")];
    if instances.is_empty() {
        lines.push("  （暂无配置）".to_string());
    }
    for instance in instances {
        let name = if instance.config_name.is_empty() {
            "未命名配置".to_string()
        } else {
            instance.config_name
        };
        let status = if instance.status.is_empty() {
            "未知".to_string()
        } else {
            instance.status
        };
        lines.push(format!("  - {name}：{status}"));
    }
    Some(lines.join("\n"))
}

/// 读取桌面端内核写入的 `web_access.toml`。
fn read_kernel_access() -> Option<KernelAccess> {
    for path in kernel_access_candidates() {
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(access) = toml::from_str::<KernelAccess>(&content) else {
            continue;
        };
        return Some(access);
    }
    None
}

/// 桌面端数据目录的候选位置，按平台排列。
fn kernel_access_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(appdata) = std::env::var_os("APPDATA") {
        candidates.push(PathBuf::from(&appdata).join("com.vnt.desktop").join("web_access.toml"));
    }
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        candidates.push(PathBuf::from(&config).join("com.vnt.desktop").join("web_access.toml"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        candidates.push(home.join(".config/com.vnt.desktop/web_access.toml"));
        candidates.push(
            home.join("Library/Application Support/com.vnt.desktop/web_access.toml"),
        );
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        candidates.push(PathBuf::from(&local).join("com.vnt.desktop").join("web_access.toml"));
    }
    candidates
}

/// 最小 HTTP/1.1 GET：只取响应体。
///
/// 不用现成的 HTTP 客户端是刻意的——探测发生在启动失败路径上，不应引入
/// TLS provider 之类的额外初始化负担；失败一律返回 `None` 由调用方降级。
async fn http_get_body(addr: &str, path: &str, token: &str) -> Option<String> {
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {token}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut buffer = Vec::new();
    tokio::time::timeout(READ_TIMEOUT, stream.read_to_end(&mut buffer))
        .await
        .ok()?
        .ok()?;
    let response = String::from_utf8_lossy(&buffer);
    let (head, body) = response.split_once("\r\n\r\n")?;
    // 未处理分块编码：桌面端返回的是定长 JSON，分块场景直接放弃解析。
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        return None;
    }
    let status_ok = head
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200"));
    if !status_ok {
        return None;
    }
    Some(body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_access_defaults_are_localhost() {
        let access: KernelAccess = toml::from_str("").expect("空配置应可用默认值");
        assert_eq!(access.listen_address, "127.0.0.1");
        assert_eq!(access.port, DEFAULT_KERNEL_PORT);
        assert!(access.token.is_empty());
    }

    #[test]
    fn kernel_access_parses_desktop_file() {
        let access: KernelAccess = toml::from_str(
            "listen_address = \"127.0.0.1\"\nport = 19099\ntoken = \"0123456789abcdef\"\n",
        )
        .expect("应能解析桌面端写入的配置");
        assert_eq!(access.port, 19099);
        assert_eq!(access.token, "0123456789abcdef");
    }

    #[test]
    fn instance_summary_tolerates_missing_fields() {
        let envelope: ApiEnvelope<Vec<InstanceSummary>> =
            serde_json::from_str(r#"{"code":0,"msg":"success","data":[{"config_name":"home"}]}"#)
                .expect("缺失字段应可解析");
        let instances = envelope.data.expect("data 应存在");
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].config_name, "home");
        assert!(instances[0].status.is_empty());
    }
}
