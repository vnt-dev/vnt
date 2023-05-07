// #[macro_use]
// extern crate windows_service;

use std::ffi::OsString;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows_service::{define_windows_service, service_control_handler, service_dispatcher};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;

use switch::core::{Config, Switch};

use crate::{config, StartArgs};
use crate::windows::SERVICE_NAME;

define_windows_service!(ffi_service_main, switch_service_main);
pub fn switch_service_main(arguments: Vec<OsString>) {
    if !arguments.is_empty() {
        if let Some(str) = arguments[0].to_str() {
            if str == "log" {
                let _ = config::log_config::log_service_init();
            }
        }
    }
    thread::spawn(|| match service_main() {
        Ok(_) => {}
        Err(e) => {
            log::error!("{:?}", e);
        }
    });
}

fn service_main() -> windows_service::Result<()> {
    let parker = crossbeam::sync::Parker::new();
    let un_parker = parker.unparker().clone();
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            // Notifies a service to report its current status information to the service
            // control manager. Always return NoError even if not implemented.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,

            // Handle stop
            ServiceControl::Stop => {
                un_parker.unpark();
                log::info!("handler 服务停止");
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler.
    // The returned status handle should be used to report service status changes to the system.
    let status_handle =
        service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Tell the system that service is running
    status_handle.set_service_status(ServiceStatus {
        service_type: crate::windows::SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    match start_switch() {
        Ok(switch) => {
            parker.park();
            if let Err(e) = switch.stop() {
                log::warn!("switch stop:{:?}",e)
            }
        }
        Err(e) => {
            log::error!("{:?}",e);
        }
    }
    status_handle.set_service_status(ServiceStatus {
        service_type: crate::windows::SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })
}

fn start_switch() -> switch::Result<Arc<Switch>> {
    match config::default_config(StartArgs::default()) {
        Ok(start_config) => {
            let config = Config::new(
                start_config.tap,
                start_config.token,
                start_config.device_id,
                start_config.name,
                start_config.server,
                start_config.nat_test_server,
            );
            let switch = Switch::start(config)?;
            log::info!("switch-service服务启动");
            let switch = Arc::new(switch);
            let command_server = crate::command::server::CommandServer::new();
            let switch1 = switch.clone();
            thread::spawn(move || {
                if let Err(e) = config::update_pid(std::process::id()) {
                    log::error!("{:?}", e);
                }
                if let Err(e) = command_server.start(switch1) {
                    log::error!("{:?}", e);
                }
            });
            Ok(switch)
        }
        Err(e) => {
            return Err(switch::error::Error::Stop(e));
        }
    }
}

pub fn start() {
    log::info!("以服务的方式启动");
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).unwrap();
}
