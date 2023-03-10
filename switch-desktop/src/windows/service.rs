// #[macro_use]
// extern crate windows_service;

use std::ffi::OsString;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::net::ToSocketAddrs;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};
use switch::core::{Config, Switch};
use crate::windows::config::read_config;

define_windows_service!(ffi_service_main, switch_service_main);
pub fn switch_service_main(_arguments: Vec<OsString>) {
    thread::spawn(|| match service_main() {
        Ok(_) => {}
        Err(e) => {
            log::warn!("{:?}", e);
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
        service_control_handler::register(crate::windows::SERVICE_NAME, event_handler)?;

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
    if let Ok(switch) = start_switch() {
        parker.park();
        if let Err(e) = switch.stop() {
            log::warn!("switch stop:{:?}",e)
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
    if let Some(config) = read_config() {
        let device_id = config.device_id;
        if device_id.trim().is_empty() {
            return Err(switch::error::Error::Stop("MAC address error".to_string()));
        }
        let server_address = if let Some(server_address) = config.server
            .to_socket_addrs()?
            .next() {
            server_address
        } else {
            return Err(switch::error::Error::Stop("server address error".to_string()));
        };
        let mut nat_test_server = config.nat_test_server.iter()
            .flat_map(|a| a.to_socket_addrs())
            .flatten()
            .collect::<Vec<_>>();
        ;
        if nat_test_server.is_empty() {
            return Err(switch::error::Error::Stop("nat test server address error".to_string()));
        }
        let config = Config::new(
            config.token,
            device_id,
            config.name,
            server_address,
            nat_test_server);
        let switch = Switch::start(config)?;
        log::info!("switch-service服务启动");
        let switch = Arc::new(switch);
        let command_server = crate::command::server::CommandServer::new();
        let switch1 = switch.clone();
        thread::spawn(move || {
            if let Err(e) = command_server.start(switch1) {
                log::warn!("{:?}", e);
            }
        });
        Ok(switch)
    } else {
        Err(switch::error::Error::Stop("配置文件为空".to_string()))
    }
}

pub fn start() {
    log::info!("以服务的方式启动");
    service_dispatcher::start("switch-service", ffi_service_main).unwrap();
}
