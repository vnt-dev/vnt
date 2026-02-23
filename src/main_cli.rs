use anyhow::{Context, bail};
use args_config::{Args, FileConfig, build_config_from_args_and_file};
use route_manager::Route;
use std::path::Path;
use vnt_ipc as vnt_core;

use vnt_core::core::NetworkManager;
use vnt_core::utils::task_control::TaskGroupManager;
use vnt_ipc::core::RegisterResponse;

pub mod args_config;

#[cfg(windows)]
mod extract_wintun_dll;

#[tokio::main]
pub async fn main() {
    if let Err(e) = main0().await {
        log::error!("{:?}", e);
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
    let file_cfg = if let Some(path) = args.conf.as_ref() {
        log::info!("loaded config from {:?}", path);
        Some(FileConfig::load(path).context("failed to load config")?)
    } else {
        None
    };
    let (config, ctrl_config) =
        build_config_from_args_and_file(Some(args), file_cfg).context("invalid configuration")?;

    log::info!(
        "server: {}",
        config
            .server_addr
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    log::info!("network code: {}", config.network_code);
    log::info!("device id: {}", config.device_id);
    log::info!("device name: {}", config.device_name);
    log::info!("cert mode: {}", config.cert_mode);
    log::info!("compress: {}", config.compress);
    log::info!("rtx(quic channel): {}", config.rtx);
    let sub_input = config.input.clone();
    if !config.input.is_empty() {
        let x = config
            .input
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        log::info!("Sub network input:{x}");
    }
    if !config.output.is_empty() {
        let x = config
            .output
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");
        log::info!("Sub network output:{x}");
    }

    if let Some(password_sign) = config.key_sign() {
        log::info!("password sign: {:?}", password_sign);
    }

    let group_manager = TaskGroupManager::new();
    let (task_group, task_group_guard) =
        group_manager.create_task().context("create task group")?;

    let mut network_manager = NetworkManager::create_network(Box::new(config), task_group)
        .await
        .context("create network")?;
    let reg_msg = loop {
        let reg_msg = match network_manager.register().await {
            Ok(rs) => rs,
            Err(e) => {
                log::error!("Register failed: {:?}", e);
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
    if !network_manager.is_no_tun() {
        log::info!("启动网络：{}/{}", reg_msg.ip, reg_msg.prefix_len);
        network_manager.start_tun().await.context("start tun")?;
        network_manager
            .set_tun_network_ip(reg_msg.ip, reg_msg.prefix_len)
            .await
            .context("set network ip")?;
        if !sub_input.is_empty() {
            let if_index = network_manager
                .tun_if_index()
                .await
                .context("tun_if_index")?;
            let mut route_manager = route_manager::RouteManager::new()?;
            for x in sub_input {
                let route = Route::new(x.net.network().into(), x.net.prefix_len())
                    .with_gateway(x.target_ip.into())
                    .with_if_index(if_index);
                if let Err(e) = route_manager.add(&route) {
                    log::error!("add route [{route}] error: {e:?}");
                } else {
                    log::info!("add route [{route}] successful");
                }
            }
        }
    } else {
        log::info!(
            "启动网络：{}/{} (无虚拟网卡)",
            reg_msg.ip,
            reg_msg.prefix_len
        );
    }
    let vnt_api = network_manager.vnt_api();
    if ctrl_config.ctrl_port.is_none_or(|p| p != 0) {
        tokio::spawn(async move {
            if let Err(e) = vnt_ipc::server::run_server(ctrl_config.ctrl_port, vnt_api).await {
                log::error!("ipc:{e:?}");
            }
        });
    }
    loop {
        tokio::select! {
            _ = network_manager.wait_all_stopped() => {
                break;
            }

            _ = tokio::signal::ctrl_c() => {
                log::info!("Ctrl+c received!");
                break;
            }
        }
    }
    drop(task_group_guard);
    log::info!("stop network");
    Ok(())
}
