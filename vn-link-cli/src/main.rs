use common::callback;
use vn_link::config::VnLinkConfig;
use vn_link::vnt::core::Config;

fn main() {
    let (config, vnt_link_config, cmd) = match common::cli::parse_args_config() {
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
            println!("Error {:?}", e);
            return;
        }
    };
    let vnt_link_config = VnLinkConfig::new(vn_link::config::convert(vnt_link_config).unwrap());
    main0(config, vnt_link_config, cmd)
}

#[tokio::main]
async fn main0(config: Config, vn_link_config: VnLinkConfig, _show_cmd: bool) {
    #[cfg(feature = "port_mapping")]
    for (is_tcp, addr, dest) in config.port_mapping_list.iter() {
        if *is_tcp {
            println!("TCP port mapping {}->{}", addr, dest)
        } else {
            println!("UDP port mapping {}->{}", addr, dest)
        }
    }
    for x in &vn_link_config.mapping {
        if x.protocol.is_tcp() {
            println!("TCP vnt addr mapping 127.0.0.1:{}->{}", x.src_port, x.dest)
        } else {
            println!("UDP vnt addr mapping 127.0.0.1:{}->{}", x.src_port, x.dest)
        }
    }

    let vnt_util = match vn_link::VnLink::new(config, vn_link_config, callback::VntHandler {}).await
    {
        Ok(vnt) => vnt,
        Err(e) => {
            println!("error: {:?}", e);
            std::process::exit(1);
        }
    };

    #[cfg(feature = "command")]
    {
        let vnt_c = vnt_util.as_vnt().clone();
        std::thread::Builder::new()
            .name("CommandServer".into())
            .spawn(move || {
                if let Err(e) = common::command::server::CommandServer::new().start(vnt_c) {
                    log::warn!("cmd:{:?}", e);
                }
            })
            .expect("CommandServer");
        let vnt_c = vnt_util.as_vnt();
        if _show_cmd {
            use tokio::io::AsyncBufReadExt;
            let mut cmd = String::new();
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
            loop {
                cmd.clear();
                println!("======== input:list,info,route,all,stop,chart_a,chart_b[:ip] ========");
                match reader.read_line(&mut cmd).await {
                    Ok(len) => {
                        if !common::command::command_str(&cmd[..len], vnt_c) {
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
    vnt_util.wait().await
}
