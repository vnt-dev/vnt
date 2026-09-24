use anyhow::Context;
use args_config::{Args, CtrlConfig, FileConfig, build_config_from_args_and_file};
use std::path::Path;
use vnt_ipc as vnt_core;

use vnt_core::context::config::Config;
use vnt_core::log_manager::InstanceLog;
use vnt_core::managed_config::Subscription;

pub mod args_config;
mod cli_subscription;

#[cfg(windows)]
mod extract_wintun_dll;

#[tokio::main]
pub async fn main() {
    if let Err(error) = main0().await {
        log::error!("{error:?}");
    }
}

async fn main0() -> anyhow::Result<()> {
    let args = Args::parse_compatible();

    vnt2::log::log_init("vnt2");
    log::info!("version: {:?}", env!("CARGO_PKG_VERSION"));
    #[cfg(windows)]
    extract_wintun_dll::extract_wintun();
    if args.conf_example {
        FileConfig::print_example(Some(Path::new("example_config.toml")))?;
        return Ok(());
    }

    let local_file = args
        .conf
        .as_deref()
        .map(FileConfig::load)
        .transpose()
        .context("failed to load config")?;
    if let Some(path) = &args.conf {
        log::info!("loaded config from {path:?}");
    }

    let subscription = args.subscription.clone().or_else(|| {
        local_file
            .as_ref()
            .and_then(|file| file.subscription.clone())
    });
    // 实例日志：网络核心与订阅监听器的错误写入其中（CLI 无查看界面，仅记录）
    let instance_log = std::sync::Arc::new(InstanceLog::new("cli"));
    let subscription = subscription
        .as_deref()
        .map(Subscription::parse)
        .transpose()?;
    let ctrl_port = args
        .ctrl_port
        .or_else(|| local_file.as_ref().and_then(|file| file.ctrl_port));
    cli_subscription::run(args, local_file, subscription, instance_log, ctrl_port).await
}

/// 解析本地配置。`managed` 为 true 时身份字段（network_code/device_id/ip/
/// device_name）一律让位给订阅信封：本地与 CLI 的同类值全部剥除，缺失的
/// network_code 以空占位符通过必填校验。实例只会在首份信封合并后才启动，
/// 合并规则始终以信封身份为准（见 `merge_present_config`）。
fn resolve_configuration(
    args: &Args,
    local_file: Option<&FileConfig>,
    managed: bool,
) -> anyhow::Result<(Config, CtrlConfig, String)> {
    let mut effective_args = args.clone();
    let mut merged = if let Some(local) = local_file {
        local.clone()
    } else {
        FileConfig::default()
    };
    if managed {
        effective_args.network_code = None;
        effective_args.device_id = None;
        effective_args.ip = None;
        effective_args.device_name = None;
        merged.network_code = None;
        merged.device_id = None;
        merged.ip = None;
        merged.device_name = None;
        // 占位身份：首份订阅信封到达后由 merge_present_config 覆盖
        if effective_args.network_code.is_none() && merged.network_code.is_none() {
            effective_args.network_code = Some(String::new());
        }
    }
    let (config, ctrl) = build_config_from_args_and_file(Some(effective_args), Some(merged))
        .context("invalid configuration")?;
    let mut comparable = config.clone();
    comparable.managed = None;
    let signature = format!("{comparable:?}|ctrl_port={:?}", ctrl.ctrl_port);
    Ok((config, ctrl, signature))
}

#[cfg(test)]
mod tests {
    use super::{Args, FileConfig, Subscription, resolve_configuration};
    use clap::Parser;

    /// v:2 载荷：{v, server, cert_mode, join_id, credential_key}
    const SUBSCRIPTION: &str = "vnt2://join/2/eyJ2IjoyLCJzZXJ2ZXIiOiJ0Y3A6Ly8xMjcuMC4wLjE6Mjk4NzIiLCJjZXJ0X21vZGUiOiJzdGFuZGFyZCIsImpvaW5faWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJjcmVkZW50aWFsX2tleSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ";

    #[test]
    fn managed_mode_allows_missing_local_identity() {
        let args = Args::try_parse_from(["vnt2_cli"]).unwrap();
        let (config, _, _) = resolve_configuration(&args, None, true).unwrap();
        // 占位身份：首份订阅信封到达后由 merge_present_config 覆盖
        assert!(config.network_code.is_empty());
    }

    #[test]
    fn ordinary_mode_still_requires_network_code() {
        let args = Args::try_parse_from(["vnt2_cli"]).unwrap();
        let error = resolve_configuration(&args, None, false)
            .err()
            .expect("ordinary mode must fail without network_code");
        assert!(format!("{error:#}").contains("network_code"));
    }

    #[test]
    fn managed_mode_ignores_local_and_cli_identity_fields() {
        let args = Args::try_parse_from([
            "vnt2_cli",
            "--network-code",
            "cli-net",
            "--device-id",
            "cli-dev",
        ])
        .unwrap();
        let local: FileConfig = toml::from_str(
            r#"
network_code = "local-net"
device_id = "local-dev"
ip = "10.20.0.3/24"
device_name = "local-name"
mtu = 1400
"#,
        )
        .unwrap();
        let (config, _, _) = resolve_configuration(&args, Some(&local), true).unwrap();
        assert!(config.network_code.is_empty());
        // 非身份字段仍然来自本地配置
        assert_eq!(config.mtu, Some(1400));
    }

    #[test]
    fn subscription_link_parses_v2_payload() {
        let subscription = Subscription::parse(SUBSCRIPTION).unwrap();
        assert_eq!(
            subscription.join_id,
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(subscription.server, "tcp://127.0.0.1:29872");
    }
}
