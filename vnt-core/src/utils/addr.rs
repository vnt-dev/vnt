use anyhow::{Result, anyhow};

/// 将 host:port 地址拆分为 host 与端口。
/// - IPv6 必须用方括号形式，如 `[::1]:443`，返回的 host 不含方括号
/// - host 可以是域名或 IP 字面量，此处不做 DNS 解析，由调用方在使用时解析
/// - 端口缺失、非法或 host 为空时返回错误
pub(crate) fn split_host_port(addr: &str) -> Result<(&str, u16)> {
    let (host, port) = if let Some(stripped) = addr.strip_prefix('[') {
        let pos = stripped
            .find(']')
            .ok_or_else(|| anyhow!("invalid address: {addr}"))?;
        let port = stripped[pos + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| anyhow!("address has no port: {addr}"))?;
        (&stripped[..pos], port)
    } else if addr.contains(':') && !addr.contains('.') && addr.matches(':').count() > 1 {
        // 裸 IPv6，未带端口
        return Err(anyhow!("address has no port: {addr}"));
    } else if let Some((host, port)) = addr.rsplit_once(':') {
        let port = port
            .parse()
            .map_err(|_| anyhow!("invalid address: {addr}"))?;
        (host, port)
    } else {
        return Err(anyhow!("address has no port: {addr}"));
    };
    if host.is_empty() {
        return Err(anyhow!("invalid address: {addr}"));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_ipv4_and_domain() {
        assert_eq!(split_host_port("1.2.3.4:443").unwrap(), ("1.2.3.4", 443));
        assert_eq!(
            split_host_port("example.com:29872").unwrap(),
            ("example.com", 29872)
        );
    }

    #[test]
    fn splits_bracketed_ipv6() {
        assert_eq!(split_host_port("[::1]:443").unwrap(), ("::1", 443));
        assert_eq!(
            split_host_port("[2001:db8::1]:29872").unwrap(),
            ("2001:db8::1", 29872)
        );
    }

    #[test]
    fn rejects_missing_or_invalid_port() {
        assert!(split_host_port("example.com").is_err());
        assert!(split_host_port("1.2.3.4").is_err());
        assert!(split_host_port("::1").is_err()); // 裸 IPv6 无端口
        assert!(split_host_port("example.com:abc").is_err());
        assert!(split_host_port("example.com:").is_err());
        assert!(split_host_port(":443").is_err()); // 空 host
        assert!(split_host_port("[::1").is_err()); // 括号未闭合
    }
}
