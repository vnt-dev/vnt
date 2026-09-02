use anyhow::{Context, bail};
use futures::StreamExt;
use std::time::Duration;

/// 响应体最大长度，地址列表一般远小于此值
const MAX_BODY: usize = 1024 * 1024;

/// 请求 dynamic://http(s)://xxx 接口，返回文本响应体（换行分隔的服务器地址列表）。
/// HTTPS 使用系统根证书做标准校验。
pub(crate) async fn http_get_text(url: &str) -> anyhow::Result<String> {
    // reqwest 以 rustls-no-provider 模式集成：本 crate 的 rustls 启用 ring 特性，
    // 构建 client 前确保进程内已安装默认 CryptoProvider（已安装则忽略冲突）
    let _ = rustls::crypto::ring::default_provider().install_default();

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(format!("vnt/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build http client failed")?;
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("request {url} failed"))?
        .error_for_status()
        .with_context(|| format!("request {url} failed"))?;

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read response body of {url} failed"))?;
        if body.len() + chunk.len() > MAX_BODY {
            bail!("response body of {url} too large");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("dynamic server list is not valid utf-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 启动一个本地服务：读取请求后返回固定的 HTTP 响应
    async fn spawn_http_server(response: Vec<u8>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await.unwrap(); // 读完请求头即可
            stream.write_all(&response).await.unwrap();
        });
        addr
    }

    /// Content-Length 定长响应的地址列表
    #[tokio::test]
    async fn http_get_content_length() {
        let body = "tcp://127.0.0.1:29872\nquic://127.0.0.1:29873\n";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let addr = spawn_http_server(response.into_bytes()).await;
        let text = http_get_text(&format!("http://{addr}/servers"))
            .await
            .unwrap();
        assert_eq!(text, body);
    }

    /// chunked 编码响应的地址列表
    #[tokio::test]
    async fn http_get_chunked() {
        let chunk1 = "tcp://127.0.0.1:29872\r\n";
        let chunk2 = "wss://127.0.0.1:80\r\n";
        let mut response = String::from(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        response.push_str(&format!("{:x}\r\n{}\r\n", chunk1.len(), chunk1));
        response.push_str(&format!("{:x}\r\n{}\r\n", chunk2.len(), chunk2));
        response.push_str("0\r\n\r\n");

        let addr = spawn_http_server(response.into_bytes()).await;
        let text = http_get_text(&format!("http://{addr}/servers"))
            .await
            .unwrap();
        assert_eq!(text, "tcp://127.0.0.1:29872\r\nwss://127.0.0.1:80\r\n");
    }

    /// 非 2xx 状态码必须报错
    #[tokio::test]
    async fn http_get_rejects_non_2xx() {
        let response = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let addr = spawn_http_server(response.to_vec()).await;
        assert!(
            http_get_text(&format!("http://{addr}/missing"))
                .await
                .is_err()
        );
    }
}
