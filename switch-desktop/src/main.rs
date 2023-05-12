use std::thread;
use std::time::Duration;
use clap::{Parser, Subcommand};
use console::style;

use switch::core::Switch;

use crate::config::log_config::log_init;

mod command;
mod config;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(any(unix))]
mod unix;
mod console_out;

#[derive(Parser, Debug)]
#[command(
author = "Lu Beilin",
version,
about = "一个虚拟网络工具,启动后会获取一个ip,相同token下的设备之间可以用ip直接通信"
)]
pub struct BaseArgs {
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
    #[cfg(target_os = "windows")]
    Install(InstallArgs),
    /// 卸载服务
    /// Uninstall service
    #[cfg(target_os = "windows")]
    Uninstall,
    /// 配置
    #[cfg(target_os = "windows")]
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

#[derive(Parser, Debug,Default)]
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
    /// 关闭命令服务，关闭后不能在其他进程直接使用route、list等命令查看信息
    /// Turn off the command service. After turning off, you cannot directly use the route, list and other commands to view information in other processes
    #[cfg(any(unix))]
    #[arg(long)]
    off_command_server: bool,
    /// 记录日志，输出在 home/.switch_desktop 目录下，长时间使用时不建议开启
    /// Output the log in the "home/.switch_desktop" directory
    #[arg(long)]
    log: bool,
    /// 使用tap网卡
    #[arg(long)]
    tap: Option<bool>,
}

#[cfg(target_os = "windows")]
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

#[cfg(target_os = "windows")]
#[derive(Parser, Debug)]
pub struct ConfigArgs {
    /// 服务开机自启动
    /// Autostart on system startup
    #[arg(long)]
    auto: bool,
}


#[cfg(windows)]
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == windows::SERVICE_FLAG {
        //以服务的方式启动
        config::set_home(std::path::PathBuf::from(&args[2]));
        windows::service::start();
        return;
    } else {
        let home = dirs::home_dir().unwrap().join(".switch_desktop");
        config::set_home(home);
        let args = BaseArgs::parse();
        if let Commands::Start(start_args) = &args.command {
            if start_args.log {
                let _ = log_init();
            }
        }
        windows::main0(args);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn main() {
    if sudo::RunningAs::Root != sudo::check() {
        println!(
            "{}",
            style("需要使用root权限执行(Need to execute with root permission)...").red()
        );
        sudo::escalate_if_needed().unwrap();
    }
    let args = BaseArgs::parse();
    let home = dirs::home_dir().unwrap().join(".switch_desktop");
    config::set_home(home);
    if let Commands::Start(start_args) = &args.command {
        if start_args.log {
            let _ = log_init();
        }
    }
    unix::main0(args);
}

pub fn console_listen(switch: &Switch) {
    use console::Term;
    let term = Term::stdout();
    println!("{}", style("启动成功 started").green());
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
                if cmd.is_empty() {
                    log::warn!("非正常返回");
                    return;
                }
                if command(cmd.trim(), &switch).is_err() {
                    println!("{}", style("stopping").red());
                    if let Err(e) = switch.stop() {
                        println!("stop:{:?}", e);
                    }
                    thread::sleep(Duration::from_secs(2));
                    break;
                }
            }
            Err(e) => {
                log::error!("read_line:{:?}", e);
                println!("{}", style("stopping...").red());
                if let Err(e) = switch.stop() {
                    log::error!("stop:{:?}", e);
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
                break;
            }
        }
    }
    println!("{}", style("stopped").red());
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
