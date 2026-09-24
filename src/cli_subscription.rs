use super::{Args, FileConfig, resolve_configuration};
use anyhow::Context;
use std::sync::Arc;
use vnt_core::api::VntApi;
use vnt_core::log_manager::InstanceLog;
use vnt_core::managed_config::Subscription;
use vnt_core::network_info::{ChangeOutcome, RuntimeChangeManager, RuntimeEvent};
use vnt_ipc as vnt_core;

pub(crate) async fn run(
    args: Args,
    local_file: Option<FileConfig>,
    subscription: Option<Subscription>,
    log: Arc<InstanceLog>,
    ctrl_port: Option<u16>,
) -> anyhow::Result<()> {
    // 配置管理器：持有订阅连接与组网实例；托管模式在此等待服务端首份配置
    // （本地配置的身份字段已剥离，resolved 时 network_code 仅为占位符，
    // 首份信封到达后由 merge_present_config 以信封身份覆盖）
    let (local_config, _, _) =
        resolve_configuration(&args, local_file.as_ref(), subscription.is_some())?;
    let mut manager = RuntimeChangeManager::new(local_config, subscription, log.clone()).await?;
    let network = manager.start_device().await?;
    log::info!(
        "启动网络：{}/{} (设备模式 {})",
        network.ip,
        network.prefix_len,
        manager.device_mode()
    );
    let mut ipc = IpcPublisher::new(ctrl_port);
    ipc.publish(manager.api());
    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("install Ctrl+C handler")?;
                log::info!("Ctrl+c received!");
                break;
            }
            event = manager.next_event() => {
                match event {
                    Ok(RuntimeEvent::InstanceStopped) => break,
                    Ok(RuntimeEvent::Changed(change)) => {
                        match manager.apply_change(&change).await {
                            Ok(ChangeOutcome::Applied) => {
                                log::info!("已应用运行期变化（完整入栈路由 {} 条）", change.routes.len());
                                // 实例可能被内部重建，刷新 IPC 对外 API
                                ipc.publish(manager.api());
                            }
                            // 桌面平台的 rebuild/need_fd 均由 apply_change 内部处理
                            Ok(ChangeOutcome::Rebuild) | Ok(ChangeOutcome::NeedFd(_)) => {}
                            Err(error) => {
                                log::warn!("应用运行期变化失败: {error:#}");
                            }
                        }
                    }
                    Err(error) => {
                        log::warn!("运行期变化监听结束: {error:#}");
                        break;
                    }
                }
            }
        }
    }
    manager.stop().await;
    log::info!("stop network");
    Ok(())
}

struct IpcPublisher {
    ctrl_port: Option<u16>,
    sender: Option<tokio::sync::watch::Sender<VntApi>>,
}

impl IpcPublisher {
    fn new(ctrl_port: Option<u16>) -> Self {
        Self {
            ctrl_port,
            sender: None,
        }
    }

    fn publish(&mut self, api: Option<VntApi>) {
        let Some(api) = api else {
            return;
        };
        if let Some(sender) = &self.sender {
            let _ = sender.send(api);
            return;
        }
        if self.ctrl_port == Some(0) {
            return;
        }
        let (sender, receiver) = tokio::sync::watch::channel(api);
        self.sender = Some(sender);
        let ctrl_port = self.ctrl_port;
        tokio::spawn(async move {
            if let Err(error) = vnt_ipc::server::run_server_dynamic(ctrl_port, receiver).await {
                log::error!("ipc:{error:?}");
            }
        });
    }
}
