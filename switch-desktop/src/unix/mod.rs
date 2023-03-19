use std::sync::Arc;

use console::style;
use fs2::FileExt;

use switch::core::{Config, Switch};

use crate::{BaseArgs, Commands, config};
use crate::command::{command, CommandEnum};


pub fn main0(base_args: BaseArgs) {
    match base_args.command {
        Commands::Start(args) => {
            let off_command_server = args.off_command_server;
            match config::default_config(args) {
                Ok(start_config) => {
                    if sudo::RunningAs::Root != sudo::check() {
                        println!(
                            "{}",
                            style("需要使用root权限执行(Need to execute with root permission)...").red()
                        );
                        sudo::escalate_if_needed().unwrap();
                    }

                    let config = Config::new(
                        start_config.token.clone(),
                        start_config.device_id.clone(),
                        start_config.name.clone(),
                        start_config.server,
                        start_config.nat_test_server.clone(),
                    );
                    let nat_test_server = start_config.nat_test_server.iter().map(|v| v.to_string()).collect::<Vec<String>>();
                    let args_config = config::ArgsConfig::new(
                        start_config.token.clone(),
                        start_config.name.clone(),
                        start_config.server.to_string(),
                        nat_test_server,
                        start_config.device_id.clone(),
                    );
                    let lock = match config::lock_file() {
                        Ok(lock) => {
                            lock
                        }
                        Err(e) => {
                            log::error!("{:?}",e);
                            return;
                        }
                    };
                    if lock.try_lock_exclusive().is_err() {
                        println!("{}", style("文件被重复打开").red());
                        return;
                    }
                    if let Err(e) = config::save_config(args_config) {
                        log::error!("{:?}",e);
                        lock.unlock().unwrap();
                        return;
                    }
                    let switch = match Switch::start(config) {
                        Ok(switch) => {
                            switch
                        }
                        Err(e) => {
                            log::error!("{:?}", e);
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
                        let handle = std::thread::spawn(move || {
                            if let Err(e) = command_server.start(switch1) {
                                log::error!("{:?}", e);
                            }
                        });
                        crate::console_listen(&switch);
                        if let Err(e) = handle.join() {
                            log::error!("后台任务异常{:?}",e);
                        } else {
                            log::info!("后台任务结束");
                        }
                    }
                    lock.unlock().unwrap();
                }
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
        }
        Commands::Stop => {
            if sudo::RunningAs::Root != sudo::check() {
                println!(
                    "{}",
                    style("需要使用root权限执行(Need to execute with root permission)...").red()
                );
                sudo::escalate_if_needed().unwrap();
            }
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