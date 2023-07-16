use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;

use switch::core::Switch;


pub struct CommandServer {}

impl CommandServer {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandServer {
    pub async fn start(self, switch: Switch) -> io::Result<()> {
        let mut port = 21637 as u16;
        let udp = loop {
            match UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                port,
            ))).await {
                Ok(udp) => {
                    break udp;
                }
                Err(e) => {
                    if e.kind() == io::ErrorKind::AddrInUse {
                        port += 1;
                    } else {
                        log::error!("创建udp失败 {:?}", e);
                        return Err(e);
                    }
                }
            }
        };
        let path_buf = dirs::home_dir().unwrap().join(".switch_desktop").join("command-port");
        if !path_buf.parent().unwrap().exists() {
            std::fs::create_dir_all(path_buf.parent().unwrap())?;
        }
        std::fs::write(path_buf,udp.local_addr()?.port().to_string())?;
        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = udp.recv_from(&mut buf).await?;
            match std::str::from_utf8(&buf[..len]) {
                Ok(cmd) => {
                    if let Ok(out) = command(cmd, &switch) {
                        let _ = udp.send_to(out.as_bytes(), addr).await;
                        if "stopped" == &out {
                             break;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("{:?}", e);
                }
            }
        }
        Ok(())
    }
}


fn command(cmd: &str, switch: &Switch) -> io::Result<String> {
    let out_str = match cmd {
        "route" => {
            match serde_json::to_string(&crate::command::command_route(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "list" => {
            match serde_json::to_string(&crate::command::command_list(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "info" => {
            match serde_json::to_string(&crate::command::command_info(switch)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "stop" => {
            switch.stop()?;
            "stopped".to_string()
        }
        _ => {
            format!("command '{}' not found. \n Try to enter: 'help'\n", cmd)
        }
    };
    Ok(out_str)
}
