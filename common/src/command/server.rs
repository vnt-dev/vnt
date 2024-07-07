use crate::command::command_chart_b;
use std::io;
use std::io::Write;
use std::net::UdpSocket;
use vnt::core::Vnt;

pub struct CommandServer {}

impl CommandServer {
    pub fn new() -> Self {
        Self {}
    }
}

impl CommandServer {
    pub fn start(self, vnt: Vnt) -> io::Result<()> {
        let udp = if let Ok(udp) = UdpSocket::bind("127.0.0.1:39271") {
            udp
        } else {
            UdpSocket::bind("127.0.0.1:0")?
        };
        let addr = udp.local_addr()?;
        log::info!("启动后台cmd:{:?}", addr);
        if let Err(e) = save_port(addr.port()) {
            log::warn!("保存后台命令端口失败：{:?}", e);
        }

        let mut buf = [0u8; 64];
        loop {
            let (len, addr) = udp.recv_from(&mut buf)?;
            match std::str::from_utf8(&buf[..len]) {
                Ok(cmd) => {
                    if let Ok(out) = command(cmd, &vnt) {
                        if let Err(e) = udp.send_to(out.as_bytes(), addr) {
                            log::warn!("cmd={},err={:?}", cmd, e);
                        }
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
fn save_port(port: u16) -> io::Result<()> {
    let path_buf = crate::cli::app_home()?.join("command-port");
    let mut file = std::fs::File::create(path_buf)?;
    file.write_all(port.to_string().as_bytes())?;
    file.sync_all()
}

fn command(cmd: &str, vnt: &Vnt) -> io::Result<String> {
    let cmd = cmd.trim();
    let out_str = match cmd {
        "route" => serde_yaml::to_string(&crate::command::command_route(vnt))
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "list" => serde_yaml::to_string(&crate::command::command_list(vnt))
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "info" => serde_yaml::to_string(&crate::command::command_info(vnt))
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "chart_a" => serde_yaml::to_string(&crate::command::command_chart_a(vnt))
            .unwrap_or_else(|e| format!("error {:?}", e)),
        "stop" => {
            vnt.stop();
            "stopped".to_string()
        }
        _ => {
            if let Some(ip) = cmd.strip_prefix("chart_b") {
                let chart = if ip.is_empty() {
                    command_chart_b(&vnt, &vnt.current_device().virtual_gateway.to_string())
                } else {
                    command_chart_b(&vnt, &ip[1..])
                };
                serde_yaml::to_string(&chart).unwrap_or_else(|e| format!("error {:?}", e))
            } else {
                format!(
                    "command '{}' not found.  Try to enter: 'route'/'list'/'stop' \n",
                    cmd
                )
            }
        }
    };
    Ok(out_str)
}
