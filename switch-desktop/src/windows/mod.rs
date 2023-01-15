use clap::Parser;
use console::style;

pub mod service;

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
    token: String,
    /// 给设备一个名称，为空时默认用系统版本信息
    #[arg(long)]
    name: Option<String>,
    /// 安装服务，安装后可以后台运行
    #[arg(long)]
    install: bool,
    /// 卸载服务
    #[arg(long)]
    uninstall: bool,
    /// 启动，启动时可以附加参数 --token，如果没有token，则会读取配置文件中上一次使用的token
    /// 安装服务后，会以服务的方式在后台启动，此时可以关闭命令行窗口
    #[arg(long)]
    start: bool,
    #[arg(long)]
    /// 停止，安装服务后，使用--stop停止服务
    stop: bool,

}

const SERVICE_FLAG: &'static str = "start_switch_service_";
const SERVICE_NAME: &'static str = "switch-service";

pub fn main0() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && args[1] == SERVICE_FLAG {
        //以服务的方式启动
        service::start();
    }
    let args = Args::parse();
    if args.install {
        if let Err(e) = install() {
            log::error!("{:?}",e);
        }else{
            println!("{}",style("安装成功").green())
        }
        pause();
        return;
    }
    if args.uninstall {
        if let Err(e) = uninstall() {
            log::error!("{:?}",e);
        }else{
            println!("{}",style("卸载成功").green())
        }
        pause();
        return;
    }
    if args.start {
        if let Err(e) = start() {
            log::error!("{:?}",e);
            // 在当前进程启动
        }
        pause();
    }
}

fn pause() {
    println!("按任意键退出...");
    std::io::stdin().read_u8().unwrap();
}


fn install() -> Result<(), windows_service::Error> {
    use std::ffi::OsString;
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service_binary_path = std::env::current_exe().unwrap();
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from("switch service"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary_path.into(),
        launch_arguments: vec![OsString::from(SERVICE_FLAG); 1],
        dependencies: vec![],
        account_name: None, // run as System
        account_password: None,
    };
    let service = service_manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description("A VPN")?;
    Ok(())
}

fn uninstall() -> Result<(), windows_service::Error> {
    use std::{thread, time::Duration};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

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

fn start() -> Result<(), windows_service::Error> {
    use std::env;
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager = ServiceManager::local_computer(None::<&str>, manager_access)?;
    let service = service_manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[])
}