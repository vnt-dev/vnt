use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use console::style;
use switch::core::{Config, Switch};
use switch::handle::PeerDeviceStatus;
use crate::config::log_config::{log_init, log_init_service};


mod command;
mod config;
#[cfg(windows)]
mod windows;

mod unix;
mod console_out;

#[derive(Parser, Debug)]
#[command(
author = "Lu Beilin",
version,
about = "一个虚拟网络工具,启动后会获取一个ip,相同token下的设备之间可以用ip直接通信"
)]
pub struct BaseArgs {
    // /// 不超过64个字符
    // /// 相同token的设备之间才能通信。
    // /// 建议使用uuid保证唯一性。
    // /// No more than 64 characters
    // /// Only devices with the same token can communicate with each other.
    // /// It is recommended to use uuid to ensure uniqueness
    // #[arg(long)]
    // token: Option<String>,
    // /// 给设备一个名称，为空时默认用系统版本信息
    // /// Give the device a name. If it is blank, the system version information will be used by default
    // #[arg(long)]
    // name: Option<String>,
    // /// 设备唯一标识，为空时默认使用MAC地址，不超过64个字符
    // /// Unique identification of the device. If it is blank, the MAC address is used by default. No more than 64 characters
    // #[arg(long)]
    // device_id: Option<String>,
    // /// 注册和中继服务器地址
    // /// Register and relay server address
    // #[arg(long)]
    // server: Option<String>,
    // /// NAT检测服务地址，使用逗号分隔
    // /// NAT detection service address. Use comma to separate
    // #[arg(long)]
    // nat_test_server: Option<String>,
    // /// 开机自启动
    // /// Software automatically start up at boot.
    // #[cfg(windows)]
    // #[arg(long)]
    // auto: bool,
    // #[arg(long)]
    // start: bool,
    //
    // // /// 启动，启动时可以附加参数 --token，如果没有token，则会读取配置文件中上一次使用的token
    // // /// 安装服务后，会以服务的方式在后台启动，此时可以关闭命令行窗口
    // // /// When starting, you can attach the parameter -- token. If there is no token, the last token used in the configuration file will be read. After installing the service, it will be started in the background as a service. At this time, you can close the command line window
    // // #[arg(subcommand)]
    // // start111: Option<StartArgs>,
    // #[arg(long)]
    // /// 停止，启动服务后，使用 --stop停止服务
    // /// Stop. After starting the service, use -- stop to stop the service
    // stop: bool,
    // /// 启动服务后，使用 --list 查看设备列表
    // /// After starting the service, use -- list to view the device list
    // #[arg(long)]
    // list: bool,
    // /// 启动服务后，使用 --status 查看设备状态
    // /// After starting the service, use -- status to view the device status
    // #[arg(long)]
    // status: bool,
    // /// 启动服务后，使用 --route 查看所有路由
    // /// After starting the service, use -- route to View all routes
    // #[arg(long)]
    // route: bool,
    //
    // /// 安装服务，安装后可以后台运行，需要指定安装路径
    // /// The installation service can run in the background after installation, and the installation path needs to be specified
    // #[cfg(windows)]
    // #[arg(long)]
    // install: Option<String>,
    // /// 卸载服务
    // /// Uninstall service
    // #[cfg(windows)]
    // #[arg(long)]
    // uninstall: bool,
    #[clap(subcommand)]
    command: Commands,

}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 启动
    Start(StartArgs),
    /// 停止后台服务
    Stop,
    /// 安装服务
    /// Install service
    #[cfg(windows)]
    Install(InstallArgs),
    /// 卸载服务
    /// Uninstall service
    #[cfg(windows)]
    Uninstall,
    /// 配置
    #[cfg(windows)]
    Config(ConfigArgs),
    /// 查看路由
    /// View route
    Route,
    /// 查看设备列表
    ///  View device list
    List {
        /// 查看所有
        #[arg(short, long)]
        all: bool
    },
    /// 查看设备当前状态
    /// View the current status of the device
    Status,
}

#[derive(Parser, Debug)]
pub struct StartArgs {
    /// 不超过64个字符
    /// 相同token的设备之间才能通信。
    /// 建议使用uuid保证唯一性。
    /// No more than 64 characters
    /// Only devices with the same token can communicate with each other.
    /// It is recommended to use uuid to ensure uniqueness
    #[arg(long)]
    token: Option<String>,
    /// 给设备一个名称，为空时默认用系统版本信息
    /// Give the device a name. If it is blank, the system version information will be used by default
    #[arg(long, action)]
    name: Option<String>,
    /// 设备唯一标识，为空时默认使用MAC地址，不超过64个字符
    /// Unique identification of the device. If it is blank, the MAC address is used by default. No more than 64 characters
    #[arg(long)]
    device_id: Option<String>,
    /// 注册和中继服务器地址
    /// Register and relay server address
    #[arg(long)]
    server: Option<String>,
    /// NAT检测服务地址，使用逗号分隔
    /// NAT detection service address. Use comma to separate
    #[arg(long)]
    nat_test_server: Option<String>,
}

#[derive(Parser, Debug)]
pub struct InstallArgs {
    /// 安装路径
    /// Service installation path
    #[arg(long)]
    path: String,
    /// 服务开机自启动
    /// Autostart on system startup
    #[arg(long)]
    auto: bool,
}

#[derive(Parser, Debug)]
pub struct ConfigArgs {
    /// 服务开机自启动
    /// Autostart on system startup
    #[arg(long)]
    auto: bool,
    /// 取消服务开机自启动
    /// started manually
    #[arg(long)]
    not_auto: bool,
}


#[cfg(windows)]
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == windows::SERVICE_FLAG {
        //以服务的方式启动
        let _ = log_init_service(PathBuf::from(&args[2]));
        config::set_home(PathBuf::from(&args[2]));
        log::info!("config  {:?}", PathBuf::from(&args[2]));
        log::info!("config  {:?}", config::read_config());
        windows::service::start();
        return;
    } else {
        let home = dirs::home_dir().unwrap().join(".switch");
        config::set_home(home);
        let _ = log_init();
        let args = BaseArgs::parse();
        windows::main0(args);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    let _ = log_init();
    let args = Args::parse();
    if sudo::RunningAs::Root != sudo::check() {
        println!(
            "{}",
            style("需要使用root权限执行(Need to execute with root permission)...").red()
        );
        sudo::escalate_if_needed().unwrap();
    }
    println!("{}", style("starting...").green());
    start(args.token, args.name);
}

pub fn start(token: String, name: String, server_address: SocketAddr, nat_test_server: Vec<SocketAddr>, device_id: String) {
    let config = Config::new(
        token,
        device_id,
        name,
        server_address,
        nat_test_server,
    );
    let switch = match Switch::start(config) {
        Ok(switch) => switch,
        Err(e) => {
            log::error!("{:?}", e);
            return;
        }
    };
    use console::Term;
    let term = Term::stdout();
    println!("{}", style("started").green());
    let current_device = switch.current_device();
    println!(
        "当前虚拟ip(virtual ip): {:?}",
        style(current_device.virtual_ip()).green()
    );
    println!(
        "虚拟网关(virtual gateway): {:?}",
        style(current_device.virtual_gateway()).green()
    );
    loop {
        println!(
            "{}",
            style("Please enter the command (Usage: list,status,exit,help):").color256(102)
        );
        match term.read_line() {
            Ok(cmd) => {
                if command(cmd.trim(), &switch).is_err() {
                    println!("{}", style("stopping").red());
                    if let Err(e) = switch.stop() {
                        println!("stop:{:?}", e);
                    }
                    break;
                }
            }
            Err(e) => {
                println!("read_line:{:?}", e);
                println!("{}", style("stopping...").red());
                if let Err(e) = switch.stop() {
                    println!("stop:{:?}", e);
                }
                break;
            }
        }
    }
    println!("{}", style("stopped").red());
    std::process::exit(1);
}


fn command(cmd: &str, switch: &Switch) -> Result<(), ()> {
    match cmd {
        "route" => {
            let list = command::server::command_route(switch);
            console_out::console_route_table(list);
        }
        "list" => {
            let list = command::server::command_list(switch);
            console_out::console_device_list(list);
        }
        "status" => {
            let status = command::server::command_status(switch);
            console_out::console_status(status);
        }
        "help" | "h" => {
            println!("Options: ");
            println!(
                "{} , Query the virtual IP of other devices",
                style("list").green()
            );
            println!("{} , View current device status", style("status").green());
            println!("{} , Exit the program", style("exit").green());
        }
        "exit" => {
            return Err(());
        }
        _ => {
            println!("command '{}' not fount. ", style(cmd).red());
            println!("Try to enter: '{}'", style("help").green());
        }
    }
    Ok(())
}
