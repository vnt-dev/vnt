use std::io;
use std::io::Write;
use tokio::net::UdpSocket;

use vnt::core::Vnt;


pub struct CommandServer {}

impl CommandServer {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandServer {
    pub async fn start(self, vnt: Vnt) -> io::Result<()> {
        let udp = UdpSocket::bind("127.0.0.1:0").await?;
        let path_buf = crate::app_home()?.join("command-port");
        let mut file = std::fs::File::create(path_buf)?;
        file.write_all(udp.local_addr()?.port().to_string().as_bytes())?;
        file.sync_all()?;
        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = udp.recv_from(&mut buf).await?;
            match std::str::from_utf8(&buf[..len]) {
                Ok(cmd) => {
                    if let Ok(out) = command(cmd, &vnt) {
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


fn command(cmd: &str, vnt: &Vnt) -> io::Result<String> {
    let out_str = match cmd {
        "route" => {
            match serde_json::to_string(&crate::command::command_route(vnt)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "list" => {
            match serde_json::to_string(&crate::command::command_list(vnt)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "info" => {
            match serde_json::to_string(&crate::command::command_info(vnt)) {
                Ok(str) => {
                    str
                }
                Err(e) => {
                    format!("{:?}", e)
                }
            }
        }
        "stop" => {
            vnt.stop()?;
            "stopped".to_string()
        }
        _ => {
            format!("command '{}' not found. \n Try to enter: 'help'\n", cmd)
        }
    };
    Ok(out_str)
}
