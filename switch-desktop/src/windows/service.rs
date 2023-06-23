// #[macro_use]
// extern crate windows_service;

use std::ffi::OsString;
use std::sync::Arc;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;
use clap::Parser;

use windows_service::{define_windows_service, service_control_handler, service_dispatcher};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
};
use windows_service::service_control_handler::ServiceControlHandlerResult;

use switch::core::{Config, Switch};

use crate::{BaseArgs, Commands, config};
use crate::windows::SERVICE_NAME;

define_windows_service!(ffi_service_main, switch_service_main);
pub fn switch_service_main(arguments: Vec<OsString>) {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            match service_main(arguments).await {
                Ok(_) => {}
                Err(e) => {
                    log::error!("启动服务失败：{:?}",e);
                }
            }
        })
}

async fn service_main(arguments: Vec<OsString>) -> windows_service::Result<()> {
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
    match start_switch(arguments).await {
        Ok(_) => {
            parker.park();

        }
        Err(e) => {
            log::error!("服务启动失败 {:?}",e);
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

fn auto_config_path() -> io::Result<PathBuf> {
    Ok(config::get_win_server_home().join("auto_config.yaml"))
}

fn save_auto_config(start_config: config::StartConfig) -> io::Result<()> {
    let mut file = std::fs::File::create(auto_config_path()?)?;
    let config = config::ArgsConfig::new(start_config);
    match serde_yaml::to_string(&config) {
        Ok(yaml) => {
            file.write_all(yaml.as_bytes())
        }
        Err(e) => {
            Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
        }
    }
}

async fn start_switch(arguments: Vec<OsString>) -> switch::Result<()> {
    let start_config = match BaseArgs::try_parse_from(arguments) {
        Ok(args) => {
            match args.command {
                Commands::Start(args) => {
                    if args.log {
                        let _ = config::log_config::log_service_init();
                    }
                    if let Some(config_path) = &args.config {
                        match config::read_config_file(config_path.into()) {
                            Ok(start_config) => {
                                if let Err(e) = save_auto_config(start_config.clone()) {
                                    log::warn!("配置文件保存失败:{:?}",e);
                                }
                                start_config
                            }
                            Err(e) => {
                                log::error!("{:?}", e);
                                return Err(switch::error::Error::Stop(e));
                            }
                        }
                    } else {
                        match config::default_config(args) {
                            Ok(start_config) => {
                                if let Err(e) = save_auto_config(start_config.clone()) {
                                    log::warn!("配置文件保存失败:{:?}",e);
                                }
                                start_config
                            }
                            Err(e) => {
                                log::error!("{:?}", e);
                                return Err(switch::error::Error::Stop(e));
                            }
                        }
                    }
                }
                _ => {
                    return Err(switch::error::Error::Stop("配置文件错误".to_string()));
                }
            }
        }
        Err(_) => {
            match config::read_config_file(auto_config_path()?) {
                Ok(start_config) => {
                    if start_config.log {
                        let _ = config::log_config::log_service_init();
                    }
                    start_config
                }
                Err(e) => {
                    return Err(switch::error::Error::Stop(e));
                }
            }
        }
    };
    let config = Config::new(
        start_config.tap,
        start_config.token,
        start_config.device_id,
        start_config.name,
        start_config.server,
        start_config.nat_test_server,
        start_config.in_ips,
        start_config.out_ips,
    );
    log::info!("switch-service服务启动");


    tokio::spawn(async move  {
         match Switch::start(config).await {
            Ok(switch) => {
                let switch = Arc::new(switch);
                let command_server = crate::command::server::CommandServer::new();
                if let Err(e) = config::update_pid(std::process::id()) {
                    log::error!("{:?}", e);
                }
                if let Err(e) = command_server.start(switch) {
                    log::error!("{:?}", e);
                }
            }
            Err(e) => {
                log::error!("{:?}", e);
            }
        };

    });
    Ok(())
}

pub fn start() {
    log::info!("以服务的方式启动");
    service_dispatcher::start(SERVICE_NAME, ffi_service_main).unwrap();
}
