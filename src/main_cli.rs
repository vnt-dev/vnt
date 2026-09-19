use anyhow::{Context, bail};
use args_config::{Args, CtrlConfig, FileConfig, build_config_from_args_and_file};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use vnt_ipc as vnt_core;

use vnt_core::api::{ApplyAction, ReconfigureFallback};
use vnt_core::context::config::{Config, VirtualIp};
use vnt_core::core::NetworkManager;
use vnt_core::managed_config::Subscription;
use vnt_core::protocol::control_message::{SubscriptionConfigAck, SubscriptionConfigApplyStatus};
use vnt_core::utils::task_control::TaskGroupManager;
use vnt_ipc::core::RegisterResponse;

pub mod args_config;

#[cfg(windows)]
mod extract_wintun_dll;

#[derive(Clone)]
struct SubscriptionContext {
    link: Subscription,
    remote_toml: String,
    revision: u64,
    managed_ip: VirtualIp,
    managed_device_name: String,
}

#[derive(Clone)]
struct RollbackState {
    config: Config,
    signature: String,
    subscription_context: Option<SubscriptionContext>,
    ctrl_port: Option<u16>,
    failed_revision: u64,
}

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

    let subscription = args.subscription.as_deref().or_else(|| {
        local_file
            .as_ref()
            .and_then(|file| file.subscription.as_deref())
    });
    let mut subscription_context = if let Some(value) = subscription {
        let link = Subscription::parse(value)?;
        let Some(envelope) = fetch_subscription_config_with_retry(&link).await? else {
            log::info!("启动已取消");
            return Ok(());
        };
        let managed_ip = VirtualIp::new(envelope.managed_ip, envelope.managed_prefix_len)
            .context("订阅配置中的 IP 无效")?;
        Some(SubscriptionContext {
            link,
            remote_toml: envelope.toml,
            revision: envelope.revision,
            managed_ip,
            managed_device_name: envelope.managed_device_name,
        })
    } else {
        None
    };

    let (mut current_config, initial_ctrl, mut current_signature) =
        resolve_configuration(&args, local_file.as_ref(), subscription_context.as_ref())?;
    validate_configuration(&current_config)?;
    log_configuration(&current_config);

    let group_manager = TaskGroupManager::new();
    let mut ipc_sender: Option<tokio::sync::watch::Sender<vnt_core::api::VntApi>> = None;
    let mut ctrl_port = initial_ctrl.ctrl_port;
    let mut rollback: Option<RollbackState> = None;
    let mut failed_revision = None;
    let mut pending_error_ack: Option<(u64, String)> = None;

    'supervisor: loop {
        let (task_group, task_group_guard) = group_manager.create_task()?;
        let mut network_manager = match NetworkManager::create_network(
            Box::new(current_config.clone()),
            task_group,
        )
        .await
        {
            Ok(manager) => manager,
            Err(error) => {
                drop(task_group_guard);
                if let Some(previous) = rollback.take() {
                    let message = format!("create network: {error:#}");
                    log::error!(
                        "应用订阅链接配置 revision {} 失败，恢复上一版本: {message}",
                        previous.failed_revision
                    );
                    current_config = previous.config;
                    current_signature = previous.signature;
                    subscription_context = previous.subscription_context;
                    ctrl_port = previous.ctrl_port;
                    failed_revision = Some(previous.failed_revision);
                    pending_error_ack = Some((previous.failed_revision, message));
                    continue 'supervisor;
                }
                return Err(error).context("create network");
            }
        };

        let reg_msg = loop {
            match network_manager.register().await {
                Ok(RegisterResponse::Success(response)) => break response,
                Ok(RegisterResponse::Failed(error)) => {
                    let message = format!("注册失败：{}", error.message);
                    if let Some(previous) = rollback.take() {
                        log::error!(
                            "应用订阅链接配置 revision {} 失败，恢复上一版本: {message}",
                            previous.failed_revision
                        );
                        group_manager.stop();
                        network_manager.wait_all_stopped().await;
                        drop(network_manager);
                        drop(task_group_guard);
                        current_config = previous.config;
                        current_signature = previous.signature;
                        subscription_context = previous.subscription_context;
                        ctrl_port = previous.ctrl_port;
                        failed_revision = Some(previous.failed_revision);
                        pending_error_ack = Some((previous.failed_revision, message));
                        continue 'supervisor;
                    }
                    bail!(message)
                }
                Err(error) => {
                    log::error!("Register failed: {error:?}");
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                }
            }
        };
        if network_manager.device_mode().has_device() {
            log::info!(
                "启动网络：{}/{} ({})",
                reg_msg.ip,
                reg_msg.prefix_len,
                network_manager.device_mode()
            );
            if let Err(error) = network_manager.start_device().await.context("start device") {
                if let Some(previous) = rollback.take() {
                    let message = format!("{error:#}");
                    log::error!(
                        "应用订阅链接配置 revision {} 失败，恢复上一版本: {message}",
                        previous.failed_revision
                    );
                    group_manager.stop();
                    network_manager.wait_all_stopped().await;
                    drop(network_manager);
                    drop(task_group_guard);
                    current_config = previous.config;
                    current_signature = previous.signature;
                    subscription_context = previous.subscription_context;
                    ctrl_port = previous.ctrl_port;
                    failed_revision = Some(previous.failed_revision);
                    pending_error_ack = Some((previous.failed_revision, message));
                    continue 'supervisor;
                }
                return Err(error);
            }
            if let Err(error) = network_manager
                .set_device_network_ip(reg_msg.ip, reg_msg.prefix_len)
                .await
                .context("set network ip")
            {
                if let Some(previous) = rollback.take() {
                    let message = format!("{error:#}");
                    log::error!(
                        "应用订阅链接配置 revision {} 失败，恢复上一版本: {message}",
                        previous.failed_revision
                    );
                    group_manager.stop();
                    network_manager.wait_all_stopped().await;
                    drop(network_manager);
                    drop(task_group_guard);
                    current_config = previous.config;
                    current_signature = previous.signature;
                    subscription_context = previous.subscription_context;
                    ctrl_port = previous.ctrl_port;
                    failed_revision = Some(previous.failed_revision);
                    pending_error_ack = Some((previous.failed_revision, message));
                    continue 'supervisor;
                }
                return Err(error);
            }
        } else {
            log::info!(
                "启动网络：{}/{} (无虚拟网卡)",
                reg_msg.ip,
                reg_msg.prefix_len
            );
        }

        let api = network_manager.vnt_api();
        if subscription_context.is_some() && !api.has_verified_config_server() {
            log::warn!("当前服务器不支持此订阅链接的实时同步；组网将继续运行");
        }
        if let Some(sender) = &ipc_sender {
            let _ = sender.send(api.clone());
        } else if ctrl_port.is_none_or(|port| port != 0) {
            let (sender, receiver) = tokio::sync::watch::channel(api.clone());
            ipc_sender = Some(sender);
            tokio::spawn(async move {
                if let Err(error) = vnt_ipc::server::run_server_dynamic(ctrl_port, receiver).await {
                    log::error!("ipc:{error:?}");
                }
            });
        }

        rollback.take();
        if let Some((revision, error)) = pending_error_ack.take() {
            acknowledge(
                &api,
                revision,
                SubscriptionConfigApplyStatus::SubscriptionConfigError,
                Some(error),
            )
            .await;
        }

        tokio::select! {
                _ = network_manager.wait_all_stopped() => {
                    break 'supervisor;
                }
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Ctrl+c received!");
                    group_manager.stop();
                    break 'supervisor;
                }
                update = wait_subscription_update(api.clone()), if subscription_context.is_some() => {
                    let Some(update) = update else { continue; };
                    let context = subscription_context.as_ref().expect("subscription branch");
                    if update.revision <= context.revision {
                        continue;
                    }
                    if failed_revision == Some(update.revision) {
                        continue;
                    }
                    if failed_revision.is_some_and(|revision| update.revision > revision) {
                        failed_revision = None;
                    }
                    let candidate_subscription = SubscriptionContext {
                        link: context.link.clone(),
                        remote_toml: update.toml,
                        revision: update.revision,
                        managed_ip: match VirtualIp::new(
                            update.managed_ip,
                            update.managed_prefix_len,
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                log::error!(
                                    "订阅链接配置 revision {} 中的 IP 无效: {error:#}",
                                    update.revision
                                );
                                acknowledge(
                                    &api,
                                    update.revision,
                                    SubscriptionConfigApplyStatus::SubscriptionConfigError,
                                    Some(error.to_string()),
                                ).await;
                                continue;
                            }
                        },
                        managed_device_name: update.managed_device_name,
                    };
                    let resolved = resolve_configuration(
                        &args,
                        local_file.as_ref(),
                        Some(&candidate_subscription),
                    ).and_then(|(config, ctrl, signature)| {
                        validate_configuration(&config)?;
                        Ok((config, ctrl, signature))
                    });
                    let (candidate, candidate_ctrl, candidate_signature) = match resolved {
                        Ok(value) => value,
                        Err(error) => {
                            log::error!("订阅链接配置 revision {} 校验失败: {error:#}", update.revision);
                            acknowledge(
                                &api,
                                update.revision,
                                SubscriptionConfigApplyStatus::SubscriptionConfigError,
                                Some(error.to_string()),
                            ).await;
                            continue;
                        }
                    };

                    if candidate_signature == current_signature {
                        subscription_context = Some(candidate_subscription);
                        acknowledge_applied(
                            &api,
                            update.revision,
                            &current_config,
                            &current_signature,
                            "NO_CHANGE",
                            Vec::new(),
                        ).await;
                        continue;
                    }
                    if candidate_ctrl.ctrl_port != ctrl_port {
                        log::warn!("订阅链接更新了 ctrl_port；现有控制监听端口会保持到本进程退出");
                    }
                    match api.reconfigure(Box::new(candidate.clone())).await {
                        Ok(report) if matches!(
                            report.action,
                            ApplyAction::NoChange | ApplyAction::Live | ApplyAction::ComponentReload
                        ) => {
                            log::info!(
                                "订阅链接配置 revision {} 已在线应用（{:?}）: {}",
                                update.revision,
                                report.action,
                                report.changed_fields.join(", ")
                            );
                            subscription_context = Some(candidate_subscription);
                            current_config = candidate;
                            current_signature = candidate_signature;
                            ctrl_port = candidate_ctrl.ctrl_port;
                            acknowledge_applied(
                                &api,
                                update.revision,
                                &current_config,
                                &current_signature,
                                match report.action {
                                    ApplyAction::NoChange => "NO_CHANGE",
                                    ApplyAction::Live => "LIVE",
                                    ApplyAction::ComponentReload => "COMPONENT_RELOAD",
                                    ApplyAction::InstanceRestart => unreachable!(),
                                },
                                report.changed_fields,
                            ).await;
                            continue;
                        }
                        Err(error) if error.fallback == ReconfigureFallback::KeepCurrent => {
                            log::error!(
                                "订阅链接配置 revision {} 在线应用失败，旧配置保持运行: {error:#}",
                                update.revision
                            );
                            acknowledge(
                                &api,
                                update.revision,
                                SubscriptionConfigApplyStatus::SubscriptionConfigError,
                                Some(error.to_string()),
                            ).await;
                            continue;
                        }
                        Ok(_) | Err(_) => {}
                    }
                    acknowledge(
                        &api,
                        update.revision,
                        SubscriptionConfigApplyStatus::SubscriptionConfigStaged,
                        None,
                    ).await;
                    log::info!("收到订阅链接配置 revision {}，正在进程内重建网络实例", update.revision);
                    rollback = Some(RollbackState {
                        config: current_config.clone(),
                        signature: current_signature.clone(),
                        subscription_context: subscription_context.clone(),
                        ctrl_port,
                        failed_revision: update.revision,
                    });
                    subscription_context = Some(candidate_subscription);
                    current_config = candidate;
                    current_signature = candidate_signature;
                    ctrl_port = candidate_ctrl.ctrl_port;
                    group_manager.stop();
                    network_manager.wait_all_stopped().await;
                    drop(network_manager);
                    drop(task_group_guard);
                    continue 'supervisor;
                }
        }
    }

    log::info!("stop network");
    Ok(())
}

/// Fetches the initial managed configuration until it succeeds or the user cancels startup.
async fn fetch_subscription_config_with_retry(
    link: &Subscription,
) -> anyhow::Result<Option<vnt_core::protocol::control_message::SubscriptionConfigEnvelope>> {
    let mut attempts = 0_u64;
    loop {
        let result = tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(None),
            result = link.fetch() => result,
        };
        match result {
            Ok(envelope) => return Ok(Some(envelope)),
            Err(error) => {
                attempts += 1;
                log::error!("获取订阅配置失败（第 {attempts} 次）：{error:#}；5 秒后重试");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(None),
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                }
            }
        }
    }
}

fn resolve_configuration(
    args: &Args,
    local_file: Option<&FileConfig>,
    subscription_context: Option<&SubscriptionContext>,
) -> anyhow::Result<(Config, CtrlConfig, String)> {
    let mut remote = if let Some(context) = subscription_context {
        parse_remote_config(&context.remote_toml)?
    } else {
        FileConfig::default()
    };
    remote.subscription = None;
    remote.event_script = None;
    // Managed identity belongs to the subscription link, never to either TOML
    // layer. Clear both inputs before merging, then inject it below.
    remote.network_code = None;
    remote.device_id = None;
    remote.ip = None;
    remote.device_name = None;
    let mut merged = if let Some(local) = local_file {
        let mut local = local.clone();
        local.network_code = None;
        local.device_id = None;
        local.ip = None;
        local.device_name = None;
        remote.overlay(local)
    } else {
        remote
    };
    let mut effective_args = args.clone();
    if let Some(context) = subscription_context {
        effective_args.network_code = Some(context.link.network_code.clone());
        effective_args.device_id = Some(context.link.device_id.clone());
        effective_args.ip = None;
        effective_args.device_name = None;
        // Also populate the file layer so all configuration builders observe
        // the same effective identity if their precedence changes later.
        merged.network_code = Some(context.link.network_code.clone());
        merged.device_id = Some(context.link.device_id.clone());
    }
    let (mut config, ctrl) = build_config_from_args_and_file(Some(effective_args), Some(merged))
        .context("invalid configuration")?;
    if let Some(context) = subscription_context {
        config.network_code.clone_from(&context.link.network_code);
        config.device_id.clone_from(&context.link.device_id);
        config.ip = Some(context.managed_ip);
        config.device_name.clone_from(&context.managed_device_name);
        config.managed = Some(context.link.registration(context.revision));
    }
    let mut comparable = config.clone();
    comparable.managed = None;
    let signature = format!("{comparable:?}|ctrl_port={:?}", ctrl.ctrl_port);
    Ok((config, ctrl, signature))
}

fn parse_remote_config(content: &str) -> anyhow::Result<FileConfig> {
    let value: toml::Value = toml::from_str(content).context("服务端配置 TOML 无效")?;
    let table = value.as_table().context("服务端配置 TOML 根节点必须是表")?;
    for forbidden in ["subscription", "event_script", "config_name"] {
        if table.contains_key(forbidden) {
            bail!("服务端禁止下发字段 '{forbidden}'");
        }
    }
    toml::from_str(content).context("服务端配置字段或类型无效")
}

fn validate_configuration(config: &Config) -> anyhow::Result<()> {
    let mut config = config.clone();
    config.normalize()?;
    config.check()
}

async fn acknowledge(
    api: &vnt_core::api::VntApi,
    revision: u64,
    status: SubscriptionConfigApplyStatus,
    error: Option<String>,
) {
    let _ = api
        .acknowledge_subscription_config(SubscriptionConfigAck::new(
            revision,
            status,
            error.unwrap_or_default(),
            Vec::new(),
        ))
        .await;
}

async fn acknowledge_applied(
    api: &vnt_core::api::VntApi,
    revision: u64,
    config: &Config,
    effective_signature: &str,
    apply_mode: &str,
    changed_fields: Vec<String>,
) {
    let mut ack = SubscriptionConfigAck::new(
        revision,
        SubscriptionConfigApplyStatus::SubscriptionConfigApplied,
        String::new(),
        Vec::new(),
    );
    ack.apply_mode = apply_mode.to_string();
    ack.changed_fields = changed_fields;
    ack.effective_device_name = config.device_name.clone();
    if let Some(ip) = config.ip {
        ack.effective_ip = ip.ip();
        ack.effective_prefix_len = ip.prefix_len().into();
    } else if let Some(network) = api.network() {
        ack.effective_ip = network.ip;
        ack.effective_prefix_len = network.prefix_len.into();
    }
    ack.effective_output = config.output.clone();
    ack.allow_ikev2 = config.allow_ikev2;
    ack.allow_wireguard = config.allow_wireguard;
    ack.allow_mapping = config.allow_port_mapping;
    ack.effective_config_sha256 = Sha256::digest(effective_signature.as_bytes()).to_vec();
    let _ = api.acknowledge_subscription_config(ack).await;
}

async fn wait_subscription_update(
    api: vnt_core::api::VntApi,
) -> Option<vnt_core::protocol::control_message::SubscriptionConfigEnvelope> {
    loop {
        let updates = api.next_subscription_config_updates().await?;
        if let Some(update) = updates.into_iter().max_by_key(|value| value.revision) {
            return Some(update);
        }
    }
}

fn log_configuration(config: &Config) {
    log::info!(
        "server: {}",
        config
            .server_addr
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    log::info!("network code: {}", config.network_code);
    log::info!("device id: {}", config.device_id);
    log::info!("device name: {}", config.device_name);
    log::info!("cert mode: {}", config.cert_mode);
}

#[cfg(test)]
mod tests {
    use super::{Args, FileConfig, Subscription, SubscriptionContext, resolve_configuration};
    use clap::Parser;

    const SUBSCRIPTION: &str = "vnt2://join/1/eyJ2IjoxLCJzZXJ2ZXIiOiJ0Y3A6Ly8xMjcuMC4wLjE6Mjk4NzIiLCJjZXJ0X21vZGUiOiJzdGFuZGFyZCIsIm5ldHdvcmtfY29kZSI6Im1hbmFnZWQtbmV0IiwiZGV2aWNlX2lkIjoibWFuYWdlZC1kZXYiLCJjcmVkZW50aWFsX2tleSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ";

    #[test]
    fn subscription_identity_overrides_remote_local_and_cli_values() {
        let args = Args::try_parse_from([
            "vnt2_cli",
            "--network-code",
            "cli-net",
            "--device-id",
            "cli-dev",
            "--ip",
            "10.20.0.2/24",
            "--device-name",
            "cli-name",
        ])
        .unwrap();
        let local: FileConfig = toml::from_str(
            r#"
network_code = "local-net"
device_id = "local-dev"
ip = "10.20.0.3/24"
device_name = "local-name"
"#,
        )
        .unwrap();
        let context = SubscriptionContext {
            link: Subscription::parse(SUBSCRIPTION).unwrap(),
            remote_toml: r#"
server = ["tcp://127.0.0.1:29872"]
cert_mode = "standard"
network_code = "remote-net"
device_id = "remote-dev"
ip = "10.20.0.4/24"
device_name = "remote-name"
"#
            .to_string(),
            revision: 7,
            managed_ip: "10.20.0.9/24".parse().unwrap(),
            managed_device_name: "managed-name".to_string(),
        };

        let (config, _, _) = resolve_configuration(&args, Some(&local), Some(&context)).unwrap();
        assert_eq!(config.network_code, "managed-net");
        assert_eq!(config.device_id, "managed-dev");
        assert_eq!(config.ip, Some("10.20.0.9/24".parse().unwrap()));
        assert_eq!(config.device_name, "managed-name");
        let managed = config.managed.unwrap();
        assert_eq!(managed.network_code, "managed-net");
        assert_eq!(managed.device_id, "managed-dev");
    }

    #[test]
    fn subscription_envelope_metadata_changes_effective_signature() {
        let args = Args::try_parse_from(["vnt2_cli"]).unwrap();
        let mut context = SubscriptionContext {
            link: Subscription::parse(SUBSCRIPTION).unwrap(),
            remote_toml: r#"
server = ["tcp://127.0.0.1:29872"]
cert_mode = "standard"
"#
            .to_string(),
            revision: 7,
            managed_ip: "10.20.0.8/24".parse().unwrap(),
            managed_device_name: "managed-name".to_string(),
        };

        let (_, _, old_signature) = resolve_configuration(&args, None, Some(&context)).unwrap();
        context.revision = 8;
        context.managed_ip = "10.20.0.9/24".parse().unwrap();
        let (config, _, new_signature) =
            resolve_configuration(&args, None, Some(&context)).unwrap();

        assert_eq!(config.ip, Some("10.20.0.9/24".parse().unwrap()));
        assert_ne!(old_signature, new_signature);
    }
}
