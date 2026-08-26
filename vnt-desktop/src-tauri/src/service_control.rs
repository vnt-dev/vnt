use anyhow::{Context, bail};
use serde::Deserialize;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub(crate) const SERVICE_NAME: &str = "VntWeb";
const SERVICE_DISPLAY_NAME: &str = "VNT Web Kernel";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    Install,
    Restart,
    Stop,
    Uninstall,
}

impl Action {
    pub(crate) fn parse(value: &OsStr) -> anyhow::Result<Self> {
        match value.to_str() {
            Some("install") => Ok(Self::Install),
            Some("restart") => Ok(Self::Restart),
            Some("stop") => Ok(Self::Stop),
            Some("uninstall") => Ok(Self::Uninstall),
            _ => bail!("未知的 VNT Web 服务操作：{}", value.to_string_lossy()),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Restart => "restart",
            Self::Stop => "stop",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Snapshot {
    pub(crate) installed: bool,
    pub(crate) running: bool,
    pub(crate) auto_start: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ServiceConfig {
    auto_start: bool,
}

pub(crate) fn snapshot() -> Snapshot {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return Snapshot::default();
    };
    let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
    ) else {
        return Snapshot::default();
    };
    let running = service.query_status().is_ok_and(|status| {
        matches!(
            status.current_state,
            ServiceState::Running | ServiceState::StartPending
        )
    });
    let auto_start = service
        .query_config()
        .is_ok_and(|config| config.start_type == ServiceStartType::AutoStart);
    Snapshot {
        installed: true,
        running,
        auto_start,
    }
}

pub(crate) fn execute(
    action: Action,
    sidecar_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    if !config_path.is_absolute() {
        bail!("桌面端内核设置路径必须是绝对路径");
    }
    match action {
        Action::Install => install(sidecar_path, config_path),
        Action::Restart => restart(sidecar_path, config_path),
        Action::Stop => stop(),
        Action::Uninstall => uninstall(),
    }
}

fn install(sidecar_path: &Path, config_path: &Path) -> anyhow::Result<()> {
    let auto_start = load_auto_start(config_path)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("连接 Windows 服务管理器失败")?;
    let info = service_info(sidecar_path, config_path, auto_start)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_CONFIG;
    let service = match manager.create_service(&info, access) {
        Ok(service) => service,
        Err(_) => manager
            .open_service(SERVICE_NAME, access)
            .context("打开已存在的 VNT Web 服务失败")?,
    };
    service
        .change_config(&info)
        .context("更新 VNT Web 服务配置失败")?;
    service
        .set_description("为 VNT Desktop 提供本地 Web API 和虚拟网络内核。")
        .context("设置 VNT Web 服务说明失败")?;
    start_if_stopped(&service)
}

fn restart(sidecar_path: &Path, config_path: &Path) -> anyhow::Result<()> {
    let auto_start = load_auto_start(config_path)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("连接 Windows 服务管理器失败")?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::QUERY_CONFIG;
    let service = manager
        .open_service(SERVICE_NAME, access)
        .context("VNT Web 服务尚未安装")?;

    stop_open_service(&service)?;
    service
        .change_config(&service_info(sidecar_path, config_path, auto_start)?)
        .context("更新 VNT Web 服务配置失败")?;
    service
        .start::<&str>(&[])
        .context("启动 VNT Web 服务失败")?;
    wait_for_state(&service, ServiceState::Running, Duration::from_secs(15))
}

fn stop() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("连接 Windows 服务管理器失败")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .context("VNT Web 服务尚未安装")?;
    stop_open_service(&service)
}

fn uninstall() -> anyhow::Result<()> {
    if !snapshot().installed {
        return Ok(());
    }
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("连接 Windows 服务管理器失败")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("VNT Web 服务尚未安装")?;
    stop_open_service(&service)?;
    service.delete().context("删除 VNT Web 服务失败")?;
    Ok(())
}

fn load_auto_start(config_path: &Path) -> anyhow::Result<bool> {
    let config: ServiceConfig = toml::from_str(
        &std::fs::read_to_string(config_path)
            .with_context(|| format!("读取桌面端内核设置失败：{}", config_path.display()))?,
    )
    .context("解析桌面端内核设置失败")?;
    Ok(config.auto_start)
}

fn service_info(
    sidecar_path: &Path,
    config_path: &Path,
    auto_start: bool,
) -> anyhow::Result<ServiceInfo> {
    if !sidecar_path.is_absolute() || !sidecar_path.is_file() {
        bail!(
            "未找到安装目录内的 VNT Web 程序：{}",
            sidecar_path.display()
        );
    }
    Ok(ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: if auto_start {
            ServiceStartType::AutoStart
        } else {
            ServiceStartType::OnDemand
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: sidecar_path.to_path_buf(),
        launch_arguments: vec![
            OsString::from("--service"),
            OsString::from("--desktop-config"),
            config_path.as_os_str().to_os_string(),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    })
}

fn stop_open_service(service: &windows_service::service::Service) -> anyhow::Result<()> {
    match service.query_status()?.current_state {
        ServiceState::Stopped => return Ok(()),
        ServiceState::StopPending => {}
        _ => {
            service.stop().context("停止 VNT Web 服务失败")?;
        }
    }
    wait_for_state(service, ServiceState::Stopped, Duration::from_secs(15))
}

fn start_if_stopped(service: &windows_service::service::Service) -> anyhow::Result<()> {
    match service.query_status()?.current_state {
        ServiceState::Running => return Ok(()),
        ServiceState::Stopped => {
            service
                .start::<&str>(&[])
                .context("启动 VNT Web 服务失败")?;
        }
        ServiceState::StopPending => {
            wait_for_state(service, ServiceState::Stopped, Duration::from_secs(15))?;
            service
                .start::<&str>(&[])
                .context("启动 VNT Web 服务失败")?;
        }
        _ => {}
    }
    wait_for_state(service, ServiceState::Running, Duration::from_secs(15))
}

fn wait_for_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
    timeout: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    loop {
        let current = service.query_status()?.current_state;
        if current == expected {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            bail!(
                "等待 VNT Web 服务状态 {:?} 超时，当前状态为 {:?}",
                expected,
                current
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_registration_uses_explicit_sidecar_and_config_paths() {
        let sidecar = std::env::current_exe().unwrap();
        let config = sidecar.parent().unwrap().join("web_access.toml");
        let info = service_info(&sidecar, &config, true).unwrap();

        assert_eq!(info.executable_path, sidecar);
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(
            info.launch_arguments,
            vec![
                OsString::from("--service"),
                OsString::from("--desktop-config"),
                config.into_os_string(),
            ]
        );
    }
}
