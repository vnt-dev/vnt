use anyhow::anyhow;
use clap::Parser;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use vnt_core::context::config::Config;
use vnt_core::nat::NetInput;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_ipc as vnt_core;
use vnt_ipc::port_mapping::PortMapping;

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct FileConfig {
    pub server: Option<Vec<String>>,
    pub network_code: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub no_punch: Option<bool>,
    pub rtx: Option<bool>,
    pub compress: Option<bool>,
    pub fec: Option<bool>,
    pub input: Option<Vec<NetInput>>,
    pub output: Option<Vec<Ipv4Net>>,
    pub no_nat: Option<bool>,
    pub no_tun: Option<bool>,
    pub mtu: Option<u16>,
    pub ctrl_port: Option<u16>,
    pub port_mapping: Option<Vec<String>>,
    pub allow_mapping: Option<bool>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub tun_name: Option<String>,
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
    /// 关闭打洞
    #[clap(long)]
    pub no_punch: bool,
    /// 服务端证书验证
    #[clap(long)]
    pub cert_mode: Option<CertValidationMode>,
    /// 虚拟网卡名称
    #[clap(long)]
    pub tun_name: Option<String>,
    /// 关闭内置子网NAT
    #[clap(long)]
    pub no_nat: bool,
    /// 禁用tun，禁用后只能充当流量出口或者进行端口映射，无需管理员权限
    #[clap(long)]
    pub no_tun: bool,
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
        network_code,
        ip: args.ip.or(file.ip),
        no_punch: args.no_punch || file.no_punch.unwrap_or(false),
        rtx: args.rtx || file.rtx.unwrap_or(false),
        compress: args.compress || file.compress.unwrap_or(false),
        fec: args.fec || file.fec.unwrap_or(false),
        device_id,
        device_name: args
            .device_name
            .or_else(|| file.device_name.clone())
            .unwrap_or_else(default_hostname),
        tun_name: args.tun_name.or_else(|| file.tun_name.clone()),
        password: args.password.or_else(|| file.password.clone()),
        cert_mode,
        input,
        output,
        no_nat: args.no_nat || file.no_nat.unwrap_or(false),
        no_tun: args.no_tun || file.no_tun.unwrap_or(false),
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
        network_code: args
            .network_code
            .ok_or_else(|| anyhow!("network_code is required"))?,
        ip: args.ip,
        no_punch: args.no_punch,
        rtx: args.rtx,
        input: args.input,
        compress: args.compress,
        fec: args.fec,
        device_id,
        device_name: args.device_name.unwrap_or_else(default_hostname),
        tun_name: args.tun_name,
        password: args.password,
        cert_mode: args
            .cert_mode
            .unwrap_or(CertValidationMode::InsecureSkipVerification),
        output: args.output,
        no_nat: args.no_nat,
        no_tun: args.no_tun,
        mtu: args.mtu,
        port_mapping: args.port_mapping,
        allow_port_mapping: args.allow_mapping,
        ..Default::default()
    };
    let ctrl_config = CtrlConfig {
        ctrl_port: args.ctrl_port,
    };
    Ok((config, ctrl_config))
}

fn build_from_file_only(file: FileConfig) -> anyhow::Result<(Config, CtrlConfig)> {
    let server_addr = file.to_server_addr()?;
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
        network_code: file
            .network_code
            .ok_or_else(|| anyhow!("network_code is required"))?,
        ip: file.ip,
        no_punch: file.no_punch.unwrap_or(false),
        rtx: file.rtx.unwrap_or(false),
        input: file.input.unwrap_or_default(),
        compress: file.compress.unwrap_or(false),
        fec: file.fec.unwrap_or(false),
        device_id,
        device_name: file.device_name.clone().unwrap_or_else(default_hostname),
        tun_name: file.tun_name.clone(),
        password: file.password.clone(),
        cert_mode,
        output: file.output.unwrap_or_default(),
        no_nat: file.no_nat.unwrap_or(false),
        no_tun: file.no_tun.unwrap_or(false),
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

# ===简单使用以下参数可以不动===

# 自定义虚拟 IP (可选)
# ip = "10.10.0.2"

# 是否启用quic优化传输 (默认 false,设置为true时开启)
# rtx = false

# 是否启用 FEC 前向纠错，损失一定带宽来提升网络稳定性(默认 false,设置为true时开启)
# fec = false

# 是否关闭 P2P 打洞 (默认 false,设置为true时关闭)
# no_punch = false

# 是否启用 LZ4 压缩 (默认 false,设置为true时开启)
# compress = false

# 入栈监听网段 (逗号分隔的 CIDR 和目标 IP)，用于点对网，将指定网段的流量发送到目标节点
# input = ["192.168.0.0/24,10.26.0.2", "192.168.1.0/24,10.26.0.3"]

# 出栈允许网段，用于点对网，允许指定网段的转发
# output = ["0.0.0.0/0"]

# 是否关闭内置子网NAT，关闭(设为true)后需要配置网卡转发，否则无法使用点对网。通常关闭内置子网NAT，使用系统的网卡转发，点对网性能会更好
# no_nat = false

# 是否关闭TUN虚拟网卡，关闭(设为true)后只能充当流量出口或者进行端口映射，关闭后无需管理员权限
# no_tun = false

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
