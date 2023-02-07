use std::{io, thread};
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use console::style;
use windows_service::Error;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use crate::config;

pub mod service;
mod windows_admin_check;

#[derive(Parser, Debug)]
#[command(
author = "Lu Beilin",
version,
about = "一个虚拟网络工具,启动后会获取一个ip,相同token下的设备之间可以用ip直接通信"
)]
struct Args {
    /// 32位字符
    /// 相同token的设备之间才能通信。
    /// 建议使用uuid保证唯一性。
    /// 32-bit characters.
    /// Only devices with the same token can communicate with each other.
    /// It is recommended to use uuid to ensure uniqueness
    #[arg(long)]
    token: Option<String>,
    /// 给设备一个名称，为空时默认用系统版本信息
    #[arg(long)]
    name: Option<String>,
    /// 安装服务，安装后可以后台运行，需要指定安装路径
    #[arg(long)]
    install: Option<String>,
    /// 卸载服务
    #[arg(long)]
    uninstall: bool,
    /// 启动，启动时可以附加参数 --token，如果没有token，则会读取配置文件中上一次使用的token
    /// 安装服务后，会以服务的方式在后台启动，此时可以关闭命令行窗口
    #[arg(long)]
    start: bool,
    #[arg(long)]
    /// 停止，安装服务后，使用 --stop停止服务
    stop: bool,
    /// 启动服务后，使用 --list 查看设备列表
    #[arg(long)]
    list: bool,
    /// 启动服务后，使用 --status 查看设备状态
    #[arg(long)]
    status: bool,
}

pub const SERVICE_FLAG: &'static str = "start_switch_service_";
pub const SERVICE_NAME: &'static str = "switch-service";
pub const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

pub fn main0() {
    let args = Args::parse();
    if args.list || args.status {
        match service_state() {
            Ok(state) => {
                if state == ServiceState::Running {
                    let command_client = crate::command::client::CommandClient::new().unwrap();
                    let out = if args.list {
                        command_client.list().unwrap()
                    } else if args.status {
                        command_client.status().unwrap()
                    } else {
                        "".to_string()
                    };
                    println!("{}", out);
                } else {
                    println!("服务未启动")
                }
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
        return;
    }
    if !windows_admin_check::is_app_elevated() {
        println!("{}", style("请使用管理员权限运行").red());
        return;
    }
    if let Some(path) = args.install {
        let path: PathBuf = path.into();
        if !path.exists() {
            std::fs::create_dir_all(&path).unwrap();
        }
        if !path.is_dir() {
            println!("参数必须为文件目录");
        } else {
            if let Err(e) = install(path) {
                log::error!("{:?}", e);
            } else {
                println!("{}", style("安装成功").green())
            }
        }
    } else if args.uninstall {
        if let Err(e) = uninstall() {
            log::error!("{:?}", e);
        } else {
            println!("{}", style("卸载成功").green())
        }
    } else if args.start {
        if args.token.is_none() {
            println!("{}", style("需要参数 --token").red());
        } else {
            let token = args.token.clone().unwrap();
            match service_state() {
                Ok(state) => {
                    if state == ServiceState::Stopped {
                        config::save_config(config::ArgsConfig::new(
                            token.clone(),
                            args.name.clone(),
                        ))
                            .unwrap();
                        match start() {
                            Ok(_) => {
                                //需要检查启动状态
                                println!("{}", style("启动成功").green())
                            }
                            Err(e) => {
                                log::error!("{:?}", e);
                            }
                        }
                    } else {
                        println!("服务未停止");
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
                                        style("服务未安装，在当前进程启动").red()
                                    );
                                    crate::start(token, args.name);
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
    } else if args.stop {
        match stop() {
            Ok(_) => {
                println!("{}", style("停止成功").green())
            }
            Err(e) => {
                log::error!("{:?}", e);
            }
        }
    } else {
        println!("使用参数 -h 查看帮助")
    }
    pause();
}

fn pause() {
    println!("{}", style("按任意键退出...").green());
    use console::Term;
    let term = Term::stdout();
    let _ = term.read_char().unwrap();
}

fn install(path: PathBuf) -> Result<(), Error> {
    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let current_exe_path = std::env::current_exe().unwrap();
    let service_path = path.join("switch-service.exe");
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
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("switch service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
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
