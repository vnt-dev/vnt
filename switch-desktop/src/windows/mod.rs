use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;
use std::{io, thread};
use std::net::ToSocketAddrs;

use console::style;

use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::Error;

use crate::{BaseArgs, Commands, config, console_out};
use crate::config::BaseConfig;

pub mod service;
mod windows_admin_check;

pub const SERVICE_FLAG: &'static str = "start_switch_service_v1_";
pub const SERVICE_NAME: &'static str = "switch-service-v1";
pub const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

fn command(cmd: &str) {
    if let Err(e) = command_(cmd) {
        println!("{}:{:?}", style("连接服务错误(Connection service error)").red(), e);
    }
}

fn command_(cmd: &str) -> io::Result<()> {
    match crate::command::client::CommandClient::new() {
        Ok(command_client) => {
            match cmd {
                "route" => {
                    let list = command_client.route()?;
                    console_out::console_route_table(list);
                }
                "list" => {
                    let list = command_client.list()?;
                    console_out::console_device_list(list);
                }
                "list-all" => {
                    let list = command_client.list()?;
                    console_out::console_device_list_all(list);
                }
                "status" => {
                    let status = command_client.status()?;
                    console_out::console_status(status);
                }
                _ => {}
            }
        }
        Err(e) => {
            log::error!("{:?}",e);
            println!(
                "{}:{:?}",
                style("连接服务错误(Connection service error)").red(), e
            );
        }
    };
    Ok(())
}

fn admin_check() -> bool {
    if !windows_admin_check::is_app_elevated() {
        println!(
            "{}",
            style("请使用管理员权限运行(Please run with administrator privileges)").red()
        );
        true
    } else {
        false
    }
}

fn not_started() -> bool {
    match service_state() {
        Ok(state) => {
            if state == ServiceState::Running {
                return false;
            } else {
                println!("服务未启动")
            }
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
    return true;
}

pub fn main0(base_args: BaseArgs) {
    match base_args.command {
        Commands::Start(args) => {
            if admin_check() {
                return;
            }
            match config::default_config(args) {
                Ok(base_config) => {
                    match service_state() {
                        Ok(state) => {
                            if state == ServiceState::Stopped {
                                config::save_config(config::ArgsConfig::new(
                                    base_config.token.clone(),
                                    base_config.name.clone(),
                                    base_config.server.to_string(),
                                    base_config.nat_test_server.iter().map(|v| v.to_string()).collect::<Vec<String>>(),
                                    base_config.device_id.clone(),
                                ))
                                    .unwrap();
                                match start() {
                                    Ok(_) => {
                                        //需要检查启动状态
                                        std::thread::sleep(std::time::Duration::from_secs(2));
                                        println!("{}", style("启动成功(Start successfully)").green())
                                    }
                                    Err(e) => {
                                        log::error!("{:?}", e);
                                    }
                                }
                            } else {
                                println!("服务未停止(Service not stopped)");
                            }
                        }
                        Err(e) => {
                            match e {
                                Error::Winapi(ref e) => {
                                    if let Some(code) = e.raw_os_error() {
                                        if code == 1060 {
                                            //指定的服务未安装。
                                            println!(
                                                "{}",
                                                style("服务未安装，在当前进程启动(The service is not installed and started in the current process)").red()
                                            );
                                            crate::start(base_config.token, base_config.name, base_config.server, base_config.nat_test_server, base_config.device_id);
                                            return;
                                        }
                                    }
                                }
                                _ => {}
                            }
                            println!("{:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("{}", style(e).red());
                }
            };
            pause();
        }
        Commands::Stop => {
            if not_started() {
                return;
            }
            match stop() {
                Ok(_) => {
                    println!("{}", style("停止成功(Stopped successfully)").green())
                }
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
            pause();
        }
        Commands::Install(args) => {
            let path: PathBuf = args.path.into();
            if !path.exists() {
                std::fs::create_dir_all(&path).unwrap();
            }
            if !path.is_dir() {
                println!("参数必须为文件目录(Parameter must be a file directory)");
            } else {
                if let Err(e) = install(path, args.auto) {
                    log::error!("{:?}", e);
                } else {
                    println!("{}", style("安装成功(Installation succeeded)").green())
                }
            }
            pause();
        }
        Commands::Uninstall => {
            if let Err(e) = uninstall() {
                log::error!("{:?}", e);
            } else {
                println!("{}", style("卸载成功(Uninstall succeeded)").green())
            }
            pause();
        }
        Commands::Config(args) => {}
        Commands::Route => {
            if not_started() {
                return;
            }
            command("route");
        }
        Commands::List { all } => {
            if not_started() {
                return;
            }
            if all {
                command("list-all");
            } else {
                command("list");
            }
        }
        Commands::Status => {
            if not_started() {
                return;
            }
            command("status");
        }
    }
}

fn pause() {
    println!(
        "{}",
        style("按任意键退出(Press any key to exit)...").green()
    );
    use console::Term;
    let term = Term::stdout();
    let _ = term.read_char().unwrap();
}

fn install(path: PathBuf, auto: bool) -> Result<(), Error> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let current_exe_path = std::env::current_exe().unwrap();
    let service_path = path.join("switch-service-v1.exe");
    std::fs::copy(current_exe_path, service_path.as_path()).unwrap();
    if let Err(e) = std::fs::copy("wintun.dll", path.join("wintun.dll").as_path()) {
        if e.kind() == io::ErrorKind::NotFound {
            println!("Not fount 'wintun.dll'. Please put 'wintun.dll' in the current directory");
            std::process::exit(0);
        } else {
            panic!("{:?}", e)
        }
    }
    let mut launch_arguments = Vec::new();
    launch_arguments.push(OsString::from(SERVICE_FLAG));
    launch_arguments.push(OsString::from(
        dirs::home_dir().unwrap().join(".switch").to_str().unwrap(),
    ));
    let start_type = if auto {
        ServiceStartType::AutoStart
    } else {
        ServiceStartType::OnDemand
    };
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("switch service v1"),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_path.into(),
        launch_arguments,
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };
    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description("A VPN")?;
    Ok(())
}

fn uninstall() -> Result<(), Error> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;

    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        service.stop()?;
        // Wait for service to stop
        thread::sleep(Duration::from_secs(1));
    }

    service.delete()?;
    Ok(())
}

fn start() -> Result<(), Error> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[""])
}

fn service_state() -> Result<ServiceState, Error> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service_access = ServiceAccess::QUERY_STATUS;
    let service = service_manager.open_service(SERVICE_NAME, service_access)?;
    let service_status = service.query_status()?;
    return Ok(service_status.current_state);
}

fn stop() -> Result<(), Error> {
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;
    Ok(())
}
