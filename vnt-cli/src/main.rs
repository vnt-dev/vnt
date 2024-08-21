use common::callback;
use console::style;
use vnt::core::{Config, Vnt};
mod root_check;
fn main() {
    let (config, _vnt_link_config, cmd) = match common::cli::parse_args_config() {
        Ok(rs) => {
            if let Some(rs) = rs {
                rs
            } else {
                return;
            }
        }
        Err(e) => {
            log::error!(
                "parse error={:?} cmd={:?}",
                e,
                std::env::args().collect::<Vec<String>>()
            );
            println!("{}", style(format!("Error {:?}", e)).red());
            return;
        }
    };
    main0(config, cmd)
}
fn main0(config: Config, _show_cmd: bool) {
    if !root_check::is_app_elevated() {
        println!("Please run it with administrator or root privileges");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        sudo::escalate_if_needed().unwrap();
        return;
    }
    #[cfg(feature = "port_mapping")]
    for (is_tcp, addr, dest) in config.port_mapping_list.iter() {
        if *is_tcp {
            println!("TCP port mapping {}->{}", addr, dest)
        } else {
            println!("UDP port mapping {}->{}", addr, dest)
        }
    }
    let vnt_util = match Vnt::new(config, callback::VntHandler {}) {
        Ok(vnt) => vnt,
        Err(e) => {
            log::error!("vnt create error {:?}", e);
            println!("error: {:?}", e);
            std::process::exit(1);
        }
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let vnt_c = vnt_util.clone();
        let mut signals = signal_hook::iterator::Signals::new(&[
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
        ])
        .unwrap();
        let handle = signals.handle();
        std::thread::spawn(move || {
            for sig in signals.forever() {
                match sig {
                    signal_hook::consts::SIGINT | signal_hook::consts::SIGTERM => {
                        println!("Received SIGINT, {}", sig);
                        vnt_c.stop();
                        handle.close();
                        break;
                    }
                    _ => {}
                }
            }
        });
    }
    #[cfg(feature = "command")]
    {
        let vnt_c = vnt_util.clone();
        std::thread::Builder::new()
            .name("CommandServer".into())
            .spawn(move || {
                if let Err(e) = common::command::server::CommandServer::new().start(vnt_c) {
                    log::warn!("cmd:{:?}", e);
                }
            })
            .expect("CommandServer");
        if _show_cmd {
            let mut cmd = String::new();
            loop {
                cmd.clear();
                println!("======== input:list,info,route,all,stop,chart_a,chart_b[:ip] ========");
                match std::io::stdin().read_line(&mut cmd) {
                    Ok(len) => {
                        if !common::command::command_str(&cmd[..len], &vnt_util) {
                            break;
                        }
                    }
                    Err(e) => {
                        println!("input err:{}", e);
                        break;
                    }
                }
            }
        }
    }

    vnt_util.wait()
}
