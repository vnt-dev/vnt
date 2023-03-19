use std::io;
use console::style;
use crate::console_out;

pub mod client;
pub mod server;
pub mod entity;

pub enum CommandEnum {
    Route,
    List,
    ListAll,
    Status,
    #[cfg(any(unix))]
    Stop,
}

pub fn command(cmd: CommandEnum) {
    if let Err(e) = command_(cmd) {
        println!("{}:{:?}", style("连接后台服务错误(Connection background service error)").red(), e);
    }
}

fn command_(cmd: CommandEnum) -> io::Result<()> {
    match client::CommandClient::new() {
        Ok(command_client) => {
            match cmd {
                CommandEnum::Route => {
                    let list = command_client.route()?;
                    console_out::console_route_table(list);
                }
                CommandEnum::List => {
                    let list = command_client.list()?;
                    console_out::console_device_list(list);
                }
                CommandEnum::ListAll => {
                    let list = command_client.list()?;
                    console_out::console_device_list_all(list);
                }
                CommandEnum::Status => {
                    let status = command_client.status()?;
                    console_out::console_status(status);
                }
                #[cfg(any(unix))]
                CommandEnum::Stop => {
                    command_client.stop()?;
                }
            }
        }
        Err(e) => {
            log::error!("{:?}",e);
            println!(
                "{}:{:?}",
                style("连接后台服务错误(Connection background service error)").red(), e
            );
        }
    };
    Ok(())
}
