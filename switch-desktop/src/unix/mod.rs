use std::sync::Arc;

use console::style;
use fs2::FileExt;

use switch::core::{Config, Switch};

use crate::{BaseArgs, Commands, config};
use crate::command::{command, CommandEnum};


pub async fn main0(base_args: BaseArgs) {
    match base_args.command {
        Commands::Start(args) => {
            let start_config = if let Some(config_path) = &args.config {
                match config::read_config_file(config_path.into()) {
                    Ok(start_config) => {
                        start_config
                    }
                    Err(e) => {
                        println!("{}", style(&e).red());
                        log::error!("{:?}", e);
                        return;
                    }
                }
            } else {
                match config::default_config(args) {
                    Ok(start_config) => {
                        start_config
                    }
                    Err(e) => {
                        println!("{}", style(&e).red());
                        log::error!("{:?}", e);
                        return;
                    }
                }
            };
            let off_command_server = start_config.off_command_server;
            let config = Config::new(
                start_config.tap,
                start_config.token.clone(),
                start_config.device_id.clone(),
                start_config.name.clone(),
                start_config.server,
                start_config.nat_test_server.clone(),
                start_config.in_ips.clone(),
                start_config.out_ips.clone(),
            );
            let lock = match config::lock_file() {
                Ok(lock) => {
                    lock
                }
                Err(e) => {
                    log::error!("{:?}",e);
                    println!("文件锁定失败:{:?}", e);
                    return;
                }
            };
            if lock.try_lock_exclusive().is_err() {
                println!("{}", style("文件被重复打开").red());
                return;
            }
            let switch = match Switch::start(config).await {
                Ok(switch) => {
                    switch
                }
                Err(e) => {
                    log::error!("{:?}", e);
                    println!("启动switch失败:{:?}", e);
                    lock.unlock().unwrap();
                    return;
                }
            };
            let switch = Arc::new(switch);
            let command_server = crate::command::server::CommandServer::new();
            if off_command_server {
                crate::console_listen(&switch);
                log::info!("前台任务结束");
            } else {
                if let Err(e) = config::update_pid(std::process::id()) {
                    log::error!("{:?}", e);
                }
                let switch1 = switch.clone();
                let handle = std::thread::Builder::new().name("cmd-server".into()).spawn(move || {
                    if let Err(e) = command_server.start(switch1) {
                        log::error!("{:?}", e);
                    }
                }).unwrap();
                crate::console_listen(&switch);
                if let Err(e) = handle.join() {
                    log::error!("后台任务异常{:?}",e);
                } else {
                    log::info!("后台任务结束");
                }
            }
            lock.unlock().unwrap();
        }
        Commands::Stop => {
            command(CommandEnum::Stop);
            if let Ok(pid) = config::read_pid() {
                if pid != 0 {
                    let kill_cmd = format!("kill {}", pid);
                    let kill_out = std::process::Command::new("sh")
                        .arg("-c")
                        .arg(&kill_cmd)
                        .output()
                        .expect("sh exec error!");
                    if !kill_out.status.success() {
                        println!("cmd:{:?},err:{:?}", kill_cmd, kill_out);
                        return;
                    }
                }
            }
            println!("stopped")
        }
        Commands::Route => {
            command(CommandEnum::Route);
        }
        Commands::List { all } => {
            if all {
                command(CommandEnum::ListAll);
            } else {
                command(CommandEnum::List);
            }
        }
        Commands::Status => {
            command(CommandEnum::Status);
        }
    }
}