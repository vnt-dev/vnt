// #[macro_use]
// extern crate windows_service;

use std::ffi::OsString;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use switch::{Config, Switch};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;
use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

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
                log::info!("handler 服务停止");
                un_parker.unpark();
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
    if let Some(config) = read_config() {
        let mac_address = mac_address::get_mac_address().unwrap().unwrap().to_string();
        let un_parker = parker.unparker().clone();
        let server_address = "nat1.wherewego.top:29875"
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let nat_test_server = vec![
            "nat1.wherewego.top:35061"
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
            "nat1.wherewego.top:35062"
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
            "nat2.wherewego.top:35061"
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
            "nat2.wherewego.top:35062"
                .to_socket_addrs()
                .unwrap()
                .next()
                .unwrap(),
        ];
        match Config::new(
            config.token,
            mac_address,
            config.name,
            server_address,
            nat_test_server,
            move || {
                un_parker.unpark();
            },
        ) {
            Ok(config) => match Switch::start(config) {
                Ok(switch) => {
                    log::info!("switch-service服务启动");
                    let switch = Arc::new(switch);
                    let command_server = crate::command::server::CommandServer::new();
                    let switch1 = switch.clone();
                    thread::spawn(move || {
                        if let Err(e) = command_server.start(switch1) {
                            log::warn!("{:?}", e);
                        }
                    });
                    parker.park();
                    switch.stop_async();
                    thread::sleep(Duration::from_secs(1));
                    log::info!("switch-service服务停止");
                }
                Err(e) => {
                    log::error!("{:?}", e);
                }
            },
            Err(e) => {
                log::error!("{:?}", e);
            }
        };
    } else {
        log::info!("配置文件为空");
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

pub fn start() {
    log::info!("以服务的方式启动");
    service_dispatcher::start("switch-service", ffi_service_main).unwrap();
}
