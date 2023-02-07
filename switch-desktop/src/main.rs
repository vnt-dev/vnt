use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

use clap::Parser;
use console::style;

use switch::handle::{PeerDeviceStatus, RouteType};
use switch::*;

#[cfg(windows)]
mod command;
#[cfg(windows)]
mod config;
#[cfg(windows)]
mod windows;

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
    /// Give the device a name. If it is blank, the system version information will be used by default
    #[arg(long)]
    name: Option<String>,
}

#[cfg(windows)]
fn log_init_service(home: PathBuf) -> io::Result<()> {
    if !home.exists() {
        std::fs::create_dir(&home)?;
    }
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch-service.log"))?;
    match log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Info),
        ) {
        Ok(config) => {
            let _ = log4rs::init_config(config);
        }
        Err(_) => {}
    }
    Ok(())
}

fn log_init() -> io::Result<()> {
    let home = dirs::home_dir().unwrap().join(".switch");
    if !home.exists() {
        std::fs::create_dir(&home)?;
    }
    let stderr = log4rs::append::console::ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stderr)
        .build();
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch.log"))?;
    match log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .appender(
            log4rs::config::Appender::builder()
                .filter(Box::new(log4rs::filter::threshold::ThresholdFilter::new(
                    log::LevelFilter::Error,
                )))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(log::LevelFilter::Info),
        ) {
        Ok(config) => {
            let _ = log4rs::init_config(config);
        }
        Err(_) => {}
    }
    Ok(())
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
        let _ = log_init();
        windows::main0();
    }
    // println!("{}", style("starting...").green());
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

pub fn start(token: String, name: Option<String>) {
    let mac_address = mac_address::get_mac_address().unwrap().unwrap().to_string();
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
    let switch = match Config::new(
        token,
        mac_address,
        name,
        server_address,
        nat_test_server,
        || {},
    ) {
        Ok(config) => match Switch::start(config) {
            Ok(switch) => switch,
            Err(e) => {
                log::error!("{:?}", e);
                return;
            }
        },
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
        style(current_device.virtual_ip).green()
    );
    println!(
        "虚拟网关(virtual gateway): {:?}",
        style(current_device.virtual_gateway).green()
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
                    switch.stop();
                    break;
                }
            }
            Err(e) => {
                println!("read_line:{:?}", e);
                println!("{}", style("stopping...").red());
                switch.stop();
                break;
            }
        }
    }
    println!("{}", style("stopped").red());
    std::process::exit(1);
}

fn command(cmd: &str, switch: &Switch) -> Result<(), ()> {
    match cmd {
        "list" => {
            let server_rt = switch.server_rt();
            let device_list = switch.device_list();
            if device_list.is_empty() {
                println!("No other devices found");
                return Ok(());
            }
            for peer_device_info in device_list {
                let route = switch.route(&peer_device_info.virtual_ip);
                if peer_device_info.status == PeerDeviceStatus::Online {
                    if route.route_type == RouteType::P2P {
                        let str = if route.rt >= 0 {
                            format!(
                                "[{}] {}(p2p delay:{}ms)",
                                peer_device_info.name, peer_device_info.virtual_ip, route.rt
                            )
                        } else {
                            format!(
                                "[{}] {}(p2p)",
                                peer_device_info.name, peer_device_info.virtual_ip
                            )
                        };
                        println!("{}", style(str).green());
                    } else {
                        let str = if server_rt >= 0 {
                            format!(
                                "[{}] {}(relay delay:{}ms)",
                                peer_device_info.name,
                                peer_device_info.virtual_ip,
                                server_rt * 2
                            )
                        } else {
                            format!(
                                "[{}] {}(relay)",
                                peer_device_info.name, peer_device_info.virtual_ip
                            )
                        };
                        println!("{}", style(str).blue());
                    }
                } else {
                    let str = format!(
                        "[{}] {}(Offline)",
                        peer_device_info.name, peer_device_info.virtual_ip
                    );
                    println!("{}", style(str).red());
                }
            }
        }
        "status" => {
            let server_rt = switch.server_rt();
            let current_device = switch.current_device();
            println!("Virtual ip:{}", style(current_device.virtual_ip).green());
            println!(
                "Virtual gateway:{}",
                style(current_device.virtual_gateway).green()
            );
            println!(
                "Connection status :{}",
                style(format!("{:?}", switch.connection_status())).green()
            );
            println!(
                "Relay server :{}",
                style(current_device.connect_server).green()
            );
            if server_rt >= 0 {
                println!("Delay of relay server :{}ms", style(server_rt).green());
            }
            if let Some(nat_info) = switch.nat_info() {
                println!(
                    "NAT type :{}",
                    style(format!("{:?}", nat_info.nat_type)).green()
                );
            }
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
