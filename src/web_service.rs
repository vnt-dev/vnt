use crate::{Args, run_server};
use anyhow::Context;
use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "VntWeb";
static SERVICE_ARGS: OnceLock<Args> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub(crate) fn dispatch(args: Args) -> anyhow::Result<()> {
    SERVICE_ARGS
        .set(args)
        .map_err(|_| anyhow::anyhow!("Windows 服务参数已初始化"))?;
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("注册 Windows 服务入口失败")?;
    Ok(())
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        log::error!("VNT Web Windows service failed: {error:#}");
    }
}

fn run_service() -> anyhow::Result<()> {
    let args = SERVICE_ARGS
        .get()
        .context("Windows 服务参数尚未初始化")?
        .clone();
    let cancellation = CancellationToken::new();
    let stop_token = cancellation.clone();
    let event_handler = move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop_token.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("注册 Windows 服务控制处理器失败")?;
    status_handle.set_service_status(service_status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        1,
        Duration::from_secs(10),
    ))?;
    status_handle.set_service_status(service_status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        0,
        Duration::ZERO,
    ))?;

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("创建 Windows 服务异步运行时失败")?
        .block_on(run_server(args, Some(cancellation)));

    status_handle.set_service_status(service_status(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        0,
        Duration::ZERO,
    ))?;
    result
}

fn service_status(
    current_state: ServiceState,
    controls_accepted: ServiceControlAccept,
    checkpoint: u32,
    wait_hint: Duration,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state,
        controls_accepted,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint,
        wait_hint,
        process_id: None,
    }
}
