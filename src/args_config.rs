use anyhow::anyhow;
use clap::Parser;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use vnt_core::context::config::{Config, DeviceMode, PeerAddress, TurnRule};
use vnt_core::nat::NetInput;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_ipc as vnt_core;
use vnt_ipc::port_mapping::PortMapping;

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct FileConfig {
    pub server: Option<Vec<String>>,
    pub peer_address: Option<Vec<String>>,
    pub turn: Option<Vec<String>>,
    pub network_code: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub no_punch: Option<bool>,
    pub no_broadcast: Option<bool>,
    pub rtx: Option<bool>,
    pub compress: Option<bool>,
    pub fec: Option<bool>,
    pub input: Option<Vec<NetInput>>,
    pub output: Option<Vec<Ipv4Net>>,
    pub no_nat: Option<bool>,
    pub device_mode: Option<DeviceMode>,
    #[serde(rename = "no_tun", skip_serializing)]
    pub legacy_no_tun: Option<bool>,
    pub mtu: Option<u16>,
    pub ctrl_port: Option<u16>,
    pub port_mapping: Option<Vec<String>>,
    pub allow_mapping: Option<bool>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_name: Option<String>,
    pub outbound_interface: Option<String>,
    pub password: Option<String>,
    pub cert_mode: Option<String>,
    pub udp_stun: Option<Vec<String>>,
    pub tcp_stun: Option<Vec<String>>,
    pub tunnel_port: Option<u16>,
}

impl FileConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&content)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    pub fn to_server_addr(&self) -> anyhow::Result<Vec<ProtocolAddress>> {
        if let Some(server_raw) = &self.server {
            let mut server_addr = Vec::with_capacity(server_raw.len());
            for x in server_raw {
                server_addr.push(
                    x.parse::<ProtocolAddress>()
                        .map_err(|e| anyhow!("invalid server address '{}': {}", x, e))?,
                )
            }
            Ok(server_addr)
        } else {
            Ok(Vec::new())
        }
    }
    pub fn to_peer_address(&self) -> anyhow::Result<Vec<PeerAddress>> {
        self.peer_address
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|value| {
                value
                    .parse::<PeerAddress>()
                    .map_err(|error| anyhow!("invalid peer address '{}': {}", value, error))
            })
            .collect()
    }
    pub fn to_turn(&self) -> anyhow::Result<Vec<TurnRule>> {
        self.turn
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|value| {
                value
                    .parse::<TurnRule>()
                    .map_err(|error| anyhow!("invalid turn rule '{}': {}", value, error))
            })
            .collect()
    }
    pub fn to_port_mapping(&self) -> anyhow::Result<Vec<PortMapping>> {
        if let Some(port_mapping_raw) = &self.port_mapping {
            let mut port_mapping = Vec::with_capacity(port_mapping_raw.len());
            for x in port_mapping_raw {
                port_mapping.push(
                    x.parse::<PortMapping>()
                        .map_err(|e| anyhow!("invalid port_mapping '{}': {}", x, e))?,
                )
            }
            Ok(port_mapping)
        } else {
            Ok(Vec::new())
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// 服务器地址 例如 `-s quic://127.0.0.1:29872`, 支持quic/tcp/wss/dynamic
    #[clap(short, long)]
    pub server: Vec<ProtocolAddress>,
    /// 可直连节点地址，可重复指定；支持 ip:端口、tcp://ip:端口、udp://ip:端口
    #[clap(long)]
    pub peer_address: Vec<PeerAddress>,
    /// 指定目标 IP/网段的优先中转节点，可重复指定，格式为 target,turn_ip
    #[clap(long)]
    pub turn: Vec<TurnRule>,
    /// 网络编号，相同编号的会组同一个局域网
    #[clap(short, long)]
    pub network_code: Option<String>,
    #[clap(short = 'k', long, hide = true)]
    pub token: Option<String>,
    /// 自定义虚拟IP
    #[clap(long)]
    pub ip: Option<Ipv4Addr>,
    /// 启用加密，设置加密密码
    #[clap(short, long)]
    pub password: Option<String>,
    /// 启用quic优化传输
    #[clap(long)]
    pub rtx: bool,
    /// 启用压缩 (LZ4)
    #[clap(short = 'z', long)]
    pub compress: bool,
    /// 启用 FEC 前向纠错，损失一定带宽来提升网络稳定性
    #[clap(long)]
    pub fec: bool,
    /// 入栈监听网段
    #[clap(short, long)]
    pub input: Vec<NetInput>,
    /// 出栈允许网段
    #[clap(short, long)]
    pub output: Vec<Ipv4Net>,
    /// 自定义设备名称
    #[clap(long, alias = "name")]
    pub device_name: Option<String>,
    /// 设备id
    #[clap(long, alias = "id")]
    pub device_id: Option<String>,
    /// 关闭自动 P2P 打洞；显式 peer-address 仍可直连
    #[clap(long)]
    pub no_punch: bool,
    /// 关闭虚拟网络内的 IPv4 广播和组播转发
    #[clap(long)]
    pub no_broadcast: bool,
    /// 服务端证书验证
    #[clap(long)]
    pub cert_mode: Option<CertValidationMode>,
    /// 虚拟网卡名称
    #[clap(long)]
    pub tun_name: Option<String>,
    /// 绑定对外通信 Socket 的出口网卡名称
    #[clap(long)]
    pub outbound_interface: Option<String>,
    /// 关闭内置子网NAT
    #[clap(long)]
    pub no_nat: bool,
    /// 虚拟网卡模式：no（无网卡）、tun（三层网卡）、tap（二层网卡）
    #[clap(long)]
    pub device_mode: Option<DeviceMode>,
    /// 端口映射，格式为：协议://本地监听地址-目标虚拟IP-目标映射地址
    #[clap(long)]
    pub port_mapping: Vec<PortMapping>,
    /// 是否允许作为端口映射出口，开启后其他设备才可使用本设备的ip为"目标虚拟IP"
    #[clap(long)]
    pub allow_mapping: bool,
    /// 设置mtu
    #[clap(long)]
    pub mtu: Option<u16>,
    /// 控制端口，设置0时禁用控制服务
    #[clap(long)]
    pub ctrl_port: Option<u16>,
    /// 隧道端口，用于P2P通信
    #[clap(long)]
    pub tunnel_port: Option<u16>,
    /// 读取配置文件
    #[arg(long)]
    pub conf: Option<PathBuf>,
    /// 输出配置文件示例
    #[clap(long)]
    pub conf_example: bool,
}
impl Args {
    pub fn parse_compatible() -> Self {
        let mut args = Args::parse();
        if args.network_code.is_none() {
            args.network_code = args.token.clone();
        }
        args
    }
}

pub struct CtrlConfig {
    pub ctrl_port: Option<u16>,
}

pub fn build_config_from_args_and_file(
    args: Option<Args>,
    file: Option<FileConfig>,
) -> anyhow::Result<(Config, CtrlConfig)> {
    if file
        .as_ref()
        .is_some_and(|config| config.legacy_no_tun == Some(true))
    {
        return Err(anyhow!(
            "configuration key 'no_tun' was removed; use device_mode = \"no|tun|tap\""
        ));
    }
    match (args, file) {
        (Some(args), Some(file)) => build_from_args_and_file(args, file),
        (Some(args), None) => build_from_args_only(args),
        (None, Some(file)) => build_from_file_only(file),
        (None, None) => Err(anyhow!("neither args nor config file provided")),
    }
}

fn build_from_args_and_file(args: Args, file: FileConfig) -> anyhow::Result<(Config, CtrlConfig)> {
    let server_addr = if args.server.is_empty() {
        file.to_server_addr()?
    } else {
        args.server
    };
    let peer_address = if args.peer_address.is_empty() {
        file.to_peer_address()?
    } else {
        args.peer_address
    };
    let turn = if args.turn.is_empty() {
        file.to_turn()?
    } else {
        args.turn
    };
    let port_mapping = if args.port_mapping.is_empty() {
        file.to_port_mapping()?
    } else {
        args.port_mapping
    };

    let network_code = args
        .network_code
        .or_else(|| file.network_code.clone())
        .ok_or_else(|| anyhow!("network_code is required"))?;

    let cert_mode = args
        .cert_mode
        .or_else(|| file.cert_mode.as_deref().and_then(|s| s.parse().ok()))
        .unwrap_or(CertValidationMode::InsecureSkipVerification);

    let device_id = match args.device_id.or_else(|| file.device_id.clone()) {
        Some(id) => id,
        None => vnt_core::utils::device_id::get_device_id()?,
    };

    let input = if args.input.is_empty() {
        file.input.unwrap_or_default()
    } else {
        args.input
    };

    let output = if args.output.is_empty() {
        file.output.unwrap_or_default()
    } else {
        args.output
    };
    let mut udp_stun = file.udp_stun.unwrap_or_default();
    for x in udp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }
    let mut tcp_stun = file.tcp_stun.unwrap_or_default();
    for x in tcp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }

    let config = Config {
        server_addr,
        peer_address,
        turn,
        network_code,
        ip: args.ip.or(file.ip),
        no_punch: args.no_punch || file.no_punch.unwrap_or(false),
        no_broadcast: args.no_broadcast || file.no_broadcast.unwrap_or(false),
        rtx: args.rtx || file.rtx.unwrap_or(false),
        compress: args.compress || file.compress.unwrap_or(false),
        fec: args.fec || file.fec.unwrap_or(false),
        device_id,
        device_name: args
            .device_name
            .or_else(|| file.device_name.clone())
            .unwrap_or_else(default_hostname),
        tun_name: args.tun_name.or_else(|| file.tun_name.clone()),
        outbound_interface: args
            .outbound_interface
            .or_else(|| file.outbound_interface.clone()),
        password: args.password.or_else(|| file.password.clone()),
        cert_mode,
        input,
        output,
        no_nat: args.no_nat || file.no_nat.unwrap_or(false),
        device_mode: args.device_mode.or(file.device_mode).unwrap_or_default(),
        mtu: args.mtu.or(file.mtu),
        port_mapping,
        allow_port_mapping: args.allow_mapping || file.allow_mapping.unwrap_or(false),
        udp_stun,
        tcp_stun,
        tunnel_port: args.tunnel_port.or(file.tunnel_port),
    };

    let ctrl_config = CtrlConfig {
        ctrl_port: args.ctrl_port.or(file.ctrl_port),
    };
    Ok((config, ctrl_config))
}

fn build_from_args_only(args: Args) -> anyhow::Result<(Config, CtrlConfig)> {
    let device_id = match args.device_id {
        Some(id) => id,
        None => vnt_core::utils::device_id::get_device_id()?,
    };
    let config = Config {
        server_addr: args.server,
        peer_address: args.peer_address,
        turn: args.turn,
        network_code: args
            .network_code
            .ok_or_else(|| anyhow!("network_code is required"))?,
        ip: args.ip,
        no_punch: args.no_punch,
        no_broadcast: args.no_broadcast,
        rtx: args.rtx,
        input: args.input,
        compress: args.compress,
        fec: args.fec,
        device_id,
        device_name: args.device_name.unwrap_or_else(default_hostname),
        tun_name: args.tun_name,
        outbound_interface: args.outbound_interface,
        password: args.password,
        cert_mode: args
            .cert_mode
            .unwrap_or(CertValidationMode::InsecureSkipVerification),
        output: args.output,
        no_nat: args.no_nat,
        device_mode: args.device_mode.unwrap_or_default(),
        mtu: args.mtu,
        port_mapping: args.port_mapping,
        allow_port_mapping: args.allow_mapping,
        tunnel_port: args.tunnel_port,
        ..Default::default()
    };
    let ctrl_config = CtrlConfig {
        ctrl_port: args.ctrl_port,
    };
    Ok((config, ctrl_config))
}

fn build_from_file_only(file: FileConfig) -> anyhow::Result<(Config, CtrlConfig)> {
    if file.legacy_no_tun == Some(true) {
        return Err(anyhow!(
            "configuration key 'no_tun' was removed; use device_mode = \"no|tun|tap\""
        ));
    }
    let server_addr = file.to_server_addr()?;
    let peer_address = file.to_peer_address()?;
    let turn = file.to_turn()?;
    let port_mapping = file.to_port_mapping()?;

    let cert_mode = file
        .cert_mode
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(CertValidationMode::InsecureSkipVerification);

    let device_id = match file.device_id.clone() {
        Some(id) => id,
        None => vnt_core::utils::device_id::get_device_id()?,
    };
    let mut udp_stun = file.udp_stun.unwrap_or_default();
    for x in udp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }
    let mut tcp_stun = file.tcp_stun.unwrap_or_default();
    for x in tcp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }

    let config = Config {
        server_addr,
        peer_address,
        turn,
        network_code: file
            .network_code
            .ok_or_else(|| anyhow!("network_code is required"))?,
        ip: file.ip,
        no_punch: file.no_punch.unwrap_or(false),
        no_broadcast: file.no_broadcast.unwrap_or(false),
        rtx: file.rtx.unwrap_or(false),
        input: file.input.unwrap_or_default(),
        compress: file.compress.unwrap_or(false),
        fec: file.fec.unwrap_or(false),
        device_id,
        device_name: file.device_name.clone().unwrap_or_else(default_hostname),
        tun_name: file.tun_name.clone(),
        outbound_interface: file.outbound_interface.clone(),
        password: file.password.clone(),
        cert_mode,
        output: file.output.unwrap_or_default(),
        no_nat: file.no_nat.unwrap_or(false),
        device_mode: file.device_mode.unwrap_or_default(),
        mtu: file.mtu,
        port_mapping,
        allow_port_mapping: file.allow_mapping.unwrap_or(false),
        udp_stun,
        tcp_stun,
        tunnel_port: file.tunnel_port,
    };
    let ctrl_config = CtrlConfig {
        ctrl_port: file.ctrl_port,
    };
    Ok((config, ctrl_config))
}

fn default_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default()
}

impl FileConfig {
    pub fn print_example(path: Option<&Path>) -> anyhow::Result<()> {
        const VERSION: &str = env!("CARGO_PKG_VERSION");

        let example = format!(
            r#"# ==================================
# VNT 配置文件示例（程序版本 v{version}）
# ==================================

# --- 网络配置 ---
# 网络编号，相同网络编号的会组在同一个虚拟网 (必填)
network_code = "your_network_code"

# 服务器地址列表(支持 quic / tcp / wss / dynamic) (必填)
# dynamic 协议使用dns txt解析记录值
server = ["quic://1.2.3.4:29872"]

# 可直连节点地址列表 (可选)
# 不带协议时同时尝试 TCP 和 UDP；也可用 tcp:// 或 udp:// 指定协议
# 地址端口应为对端配置的 tunnel_port
# peer_address = ["1.2.3.4:29873", "tcp://192.168.1.10:29873", "udp://[::1]:29873"]

# 指定目标虚拟 IP 或网段的优先中转虚拟 IP；填写网关 IP 时强制走服务器中继
# 命中目标不参与 P2P 打洞
# turn = ["10.26.0.0/24,10.26.0.2", "10.26.1.9,10.26.0.3"]

# ===简单使用以下参数可以不动===

# 自定义虚拟 IP (可选)
# ip = "10.10.0.2"

# 是否启用quic优化传输 (默认 false,设置为true时开启)
# rtx = false

# 是否启用 FEC 前向纠错，损失一定带宽来提升网络稳定性(默认 false,设置为true时开启)
# fec = false

# 是否关闭自动 P2P 打洞 (默认 false；显式 peer_address 仍可直连)
# no_punch = false

# 是否关闭 IPv4 广播和组播转发 (默认 false，即开启)
# no_broadcast = false

# 是否启用 LZ4 压缩 (默认 false,设置为true时开启)
# compress = false

# 入栈监听网段 (逗号分隔的 CIDR 和目标 IP)，用于点对网，将指定网段的流量发送到目标节点
# input = ["192.168.0.0/24,10.26.0.2", "192.168.1.0/24,10.26.0.3"]

# 出栈允许网段，用于点对网，允许指定网段的转发
# output = ["0.0.0.0/0"]

# 是否关闭内置子网NAT，关闭(设为true)后需要配置网卡转发，否则无法使用点对网。通常关闭内置子网NAT，使用系统的网卡转发，点对网性能会更好
# no_nat = false

# 虚拟网卡模式：no（无网卡）、tun（三层网卡，默认）、tap（二层网卡）
# device_mode = "tun"

# 端口映射，格式为：协议://本地监听地址-目标虚拟IP-目标映射地址
# 端口映射用于在本地监听指定端口，并将收到的网络流量经由指定虚拟节点转发到目标地址，从而实现跨网络或内网服务访问
# 例如 port_mapping = ["tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80"]
# tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80 则表示将本地tcp的81端口的数据转发到10.0.0.2:80
# tcp://0.0.0.0:81-10.0.0.2-192.168.1.10:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到192.168.1.10:80
# tcp://0.0.0.0:81-10.0.0.2-anyonehost:80 则表示将本地tcp的81端口的数据经过10.0.0.2转到anyonehost:80
# port_mapping = []

# 是否允许作为端口映射出口，开启(设置为true)后其他设备才可使用本设备的ip为"目标虚拟IP"
# 开启后虚拟网络其他设备可以使用此设备当跳板访问其他网络
# allow_mapping = false

# 控制服务的 tcp 端口
# ctrl_port = 11233

# 隧道端口，用于P2P通信 (默认为0，自动分配)
# tunnel_port = 0

# MTU 设置
# mtu = 1400

# --- 设备配置 ---

# 设备名称 (可选，默认读取本机 hostname)
# device_name = "my-device"

# 设备 ID (可选，不填自动生成，不同设备ID不能相同)
# device_id = "device-id-xxxx"

# 虚拟网卡名称
# tun_name = "vnt-tun"

# 绑定对外通信 Socket 的出口网卡名称（用于服务端通信、P2P 打洞及转发流量）
# outbound_interface = "Ethernet"

# --- 安全配置 ---

# 加密密码 (可选)
# password = "123456"

# 证书校验方式：
#   skip     跳过验证（默认）
#   standard 使用系统证书验证
#   finger   使用证书指纹验证，服务端启动时日志会输出指纹，
#            例如 finger:3bdd8675606837cdf95d5e13445606315762315a78555f9da652940a25feaec1
# cert_mode = "skip"

# --- 其他配置 ---
# 自定义stun地址，分别用于udp打洞和tcp打洞，需要单独配置，不设置则用默认stun
# udp_stun = ["stun.chat.bilibili.com"]
# tcp_stun = ["stun.nextcloud.com:443"]
"#,
            version = VERSION
        );
        println!("--- 示例配置文件内容 ---\n{}", example);
        if let Some(p) = path {
            std::fs::write(p, &example)?;
            println!("示例配置文件已写入 {}", p.display());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 纯参数模式下 --tunnel-port 不能被静默丢弃
    #[test]
    fn test_args_only_keeps_tunnel_port() {
        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--tunnel-port",
            "12345",
            "--outbound-interface",
            "Ethernet",
        ])
        .unwrap();
        let (config, _) = build_from_args_only(args).unwrap();
        assert_eq!(config.tunnel_port, Some(12345));
        assert_eq!(config.outbound_interface.as_deref(), Some("Ethernet"));
    }

    #[test]
    fn test_ipv4_broadcast_is_enabled_by_default_and_can_be_disabled() {
        let args = Args::try_parse_from(["vnt", "-s", "quic://127.0.0.1:29872", "-n", "test-net"])
            .unwrap();
        let (config, _) = build_from_args_only(args).unwrap();
        assert!(!config.no_broadcast);

        let file: FileConfig = toml::from_str(
            "no_broadcast = true\nserver = [\"quic://127.0.0.1:29872\"]\nnetwork_code = \"test-net\"",
        )
        .unwrap();
        let (config, _) = build_config_from_args_and_file(None, Some(file)).unwrap();
        assert!(config.no_broadcast);

        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--no-broadcast",
        ])
        .unwrap();
        let (config, _) = build_from_args_only(args).unwrap();
        assert!(config.no_broadcast);
    }

    #[test]
    fn test_peer_address_cli_and_file_precedence() {
        let file: FileConfig = toml::from_str(
            "peer_address = [\"udp://127.0.0.1:30001\"]\nnetwork_code = \"test-net\"\nserver = [\"quic://127.0.0.1:29872\"]",
        )
        .unwrap();
        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--peer-address",
            "tcp://127.0.0.1:30002",
            "--peer-address",
            "127.0.0.1:30003",
        ])
        .unwrap();
        let (config, _) = build_config_from_args_and_file(Some(args), Some(file)).unwrap();
        assert_eq!(config.peer_address.len(), 2);
        assert_eq!(config.peer_address[0].to_string(), "tcp://127.0.0.1:30002");
        assert_eq!(config.peer_address[1].to_string(), "127.0.0.1:30003");

        let file: FileConfig = toml::from_str(
            "peer_address = [\"udp://127.0.0.1:30001\"]\nnetwork_code = \"test-net\"\nserver = [\"quic://127.0.0.1:29872\"]",
        )
        .unwrap();
        let (config, _) = build_config_from_args_and_file(None, Some(file)).unwrap();
        assert_eq!(config.peer_address.len(), 1);
        assert_eq!(config.peer_address[0].to_string(), "udp://127.0.0.1:30001");
    }

    #[test]
    fn test_turn_cli_and_file_precedence() {
        let file: FileConfig = toml::from_str(
            "turn = [\"10.26.0.0/16,10.26.0.2\"]\nnetwork_code = \"test-net\"\nserver = [\"quic://127.0.0.1:29872\"]",
        )
        .unwrap();
        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--turn",
            "10.26.1.9,10.26.0.3",
        ])
        .unwrap();
        let (config, _) = build_config_from_args_and_file(Some(args), Some(file)).unwrap();
        assert_eq!(config.turn.len(), 1);
        assert_eq!(config.turn[0].to_string(), "10.26.1.9,10.26.0.3");

        let file: FileConfig = toml::from_str(
            "turn = [\"10.26.0.0/16,10.26.0.2\"]\nnetwork_code = \"test-net\"\nserver = [\"quic://127.0.0.1:29872\"]",
        )
        .unwrap();
        let (config, _) = build_config_from_args_and_file(None, Some(file)).unwrap();
        assert_eq!(config.turn[0].to_string(), "10.26.0.0/16,10.26.0.2");
    }

    #[test]
    fn test_device_mode_cli_and_legacy_rejection() {
        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--device-mode",
            "tap",
        ])
        .unwrap();
        let (config, _) = build_from_args_only(args).unwrap();
        assert_eq!(config.device_mode, DeviceMode::Tap);

        let legacy: FileConfig = toml::from_str("no_tun = true").unwrap();
        let error = match build_config_from_args_and_file(None, Some(legacy)) {
            Err(error) => error,
            Ok(_) => panic!("legacy no_tun = true must be rejected"),
        };
        assert!(error.to_string().contains("device_mode"));

        let legacy_false: FileConfig = toml::from_str(
            "no_tun = false\nserver = [\"quic://127.0.0.1:29872\"]\nnetwork_code = \"test\"",
        )
        .unwrap();
        build_config_from_args_and_file(None, Some(legacy_false))
            .expect("legacy no_tun = false should be ignored");
    }

    #[test]
    fn test_device_mode_cli_overrides_file_and_file_defaults() {
        let file: FileConfig = toml::from_str("device_mode = \"no\"").unwrap();
        let args = Args::try_parse_from(["vnt", "-s", "quic://127.0.0.1:29872", "-n", "test-net"])
            .unwrap();
        let (config, _) = build_config_from_args_and_file(Some(args), Some(file)).unwrap();
        assert_eq!(config.device_mode, DeviceMode::No);

        let file: FileConfig = toml::from_str("device_mode = \"no\"").unwrap();
        let args = Args::try_parse_from([
            "vnt",
            "-s",
            "quic://127.0.0.1:29872",
            "-n",
            "test-net",
            "--device-mode",
            "tap",
        ])
        .unwrap();
        let (config, _) = build_config_from_args_and_file(Some(args), Some(file)).unwrap();
        assert_eq!(config.device_mode, DeviceMode::Tap);
    }
}
