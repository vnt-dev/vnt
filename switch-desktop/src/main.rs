use clap::Parser;
use console::style;

use switch::handle::RouteType;
use switch::*;

#[cfg(windows)]
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
    #[arg(short, long)]
    token: String,
}

fn log_init() {
    let home = dirs::home_dir().unwrap().join(".switch");
    if !home.exists() {
        std::fs::create_dir(&home).expect(" Failed to create '.switch' directory");
    }
    let logfile = log4rs::append::file::FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new(
            "{d(%+)(utc)} [{f}:{L}] {h({l})} {M}:{m}{n}\n",
        )))
        .build(home.join("switch.log"))
        .unwrap();
    let config = log4rs::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .build(
            log4rs::config::Root::builder()
                .appender("logfile")
                .build(log::LevelFilter::Info),
        )
        .unwrap();
    let _ = log4rs::init_config(config);
}

fn main() {
    log_init();
    let args = Args::parse();
    #[cfg(windows)]
    if !windows_admin_check::is_app_elevated() {
        let args: Vec<_> = std::env::args().collect();
        println!("{}", style("正在启动管理员权限执行...").red());
        if let Some(absolute_path) = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|p| p.to_string()))
        {
            let _ = runas::Command::new(&absolute_path)
                .args(&args[1..])
                .status()
                .expect("failed to execute");
        } else {
            panic!("failed to execute")
        }
        return;
    }

    #[cfg(any(unix))]
    if sudo::RunningAs::Root != sudo::check() {
        println!("{}", style("需要使用root权限执行...").red());
        sudo::escalate_if_needed().unwrap();
    }
    println!("{}", style("starting...").green());
    let mac_address = mac_address::get_mac_address().unwrap().unwrap().to_string();
    let switch = Switch::start(Config::new(args.token, mac_address)).unwrap();
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
            for ip in device_list {
                let route = switch.route(&ip);
                if route.route_type == RouteType::P2P {
                    let str = if route.rt >= 0 {
                        format!("{}(p2p delay:{}ms)", ip, route.rt)
                    } else {
                        format!("{}(p2p)", ip)
                    };
                    println!("{}", style(str).green());
                } else {
                    let str = if server_rt >= 0 {
                        format!("{}(relay delay:{}ms)", ip, server_rt * 2)
                    } else {
                        format!("{}(relay)", ip)
                    };
                    println!("{}", style(str).blue());
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
