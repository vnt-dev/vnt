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
    pub network_secret: Option<String>,
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
    /// 鏈嶅姟鍣ㄥ湴鍧€ 渚嬪 `-s quic://127.0.0.1:29872`, 鏀寔quic/tcp/wss/dynamic
    #[clap(short, long)]
    pub server: Vec<ProtocolAddress>,
    /// 缃戠粶缂栧彿锛岀浉鍚岀紪鍙风殑浼氱粍鍚屼竴涓眬鍩熺綉
    #[clap(short, long)]
    pub network_code: Option<String>,
    #[clap(short = 'k', long, hide = true)]
    pub token: Option<String>,
    /// Network join secret used for registration validation
    #[clap(long)]
    pub network_secret: Option<String>,
    /// 鑷畾涔夎櫄鎷烮P
    #[clap(long)]
    pub ip: Option<Ipv4Addr>,
    /// 鍚敤鍔犲瘑锛岃缃姞瀵嗗瘑鐮?
    #[clap(short, long)]
    pub password: Option<String>,
    /// 鍚敤quic浼樺寲浼犺緭
    #[clap(long)]
    pub rtx: bool,
    /// 鍚敤鍘嬬缉 (LZ4)
    #[clap(short = 'z', long)]
    pub compress: bool,
    /// 鍚敤 FEC 鍓嶅悜绾犻敊锛屾崯澶变竴瀹氬甫瀹芥潵鎻愬崌缃戠粶绋冲畾鎬?
    #[clap(long)]
    pub fec: bool,
    /// 鍏ユ爤鐩戝惉缃戞
    #[clap(short, long)]
    pub input: Vec<NetInput>,
    /// 鍑烘爤鍏佽缃戞
    #[clap(short, long)]
    pub output: Vec<Ipv4Net>,
    /// 鑷畾涔夎澶囧悕绉?
    #[clap(long, alias = "name")]
    pub device_name: Option<String>,
    /// 璁惧id
    #[clap(long, alias = "id")]
    pub device_id: Option<String>,
    /// 鍏抽棴鎵撴礊
    #[clap(long)]
    pub no_punch: bool,
    /// 鏈嶅姟绔瘉涔﹂獙璇?
    #[clap(long)]
    pub cert_mode: Option<CertValidationMode>,
    /// 铏氭嫙缃戝崱鍚嶇О
    #[clap(long)]
    pub tun_name: Option<String>,
    /// 鍏抽棴鍐呯疆瀛愮綉NAT
    #[clap(long)]
    pub no_nat: bool,
    /// 绂佺敤tun锛岀鐢ㄥ悗鍙兘鍏呭綋娴侀噺鍑哄彛鎴栬€呰繘琛岀鍙ｆ槧灏勶紝鏃犻渶绠＄悊鍛樻潈闄?
    #[clap(long)]
    pub no_tun: bool,
    /// 绔彛鏄犲皠锛屾牸寮忎负锛氬崗璁?//鏈湴鐩戝惉鍦板潃-鐩爣铏氭嫙IP-鐩爣鏄犲皠鍦板潃
    #[clap(long)]
    pub port_mapping: Vec<PortMapping>,
    /// 鏄惁鍏佽浣滀负绔彛鏄犲皠鍑哄彛锛屽紑鍚悗鍏朵粬璁惧鎵嶅彲浣跨敤鏈澶囩殑ip涓?鐩爣铏氭嫙IP"
    #[clap(long)]
    pub allow_mapping: bool,
    /// 璁剧疆mtu
    #[clap(long)]
    pub mtu: Option<u16>,
    /// 鎺у埗绔彛锛岃缃?鏃剁鐢ㄦ帶鍒舵湇鍔?
    #[clap(long)]
    pub ctrl_port: Option<u16>,
    /// 闅ч亾绔彛锛岀敤浜嶱2P閫氫俊
    #[clap(long)]
    pub tunnel_port: Option<u16>,
    /// 璇诲彇閰嶇疆鏂囦欢
    #[arg(long)]
    pub conf: Option<PathBuf>,
    /// 杈撳嚭閰嶇疆鏂囦欢绀轰緥
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
        network_secret: args.network_secret.or_else(|| file.network_secret.clone()),
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
        network_secret: args.network_secret,
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
        network_secret: file.network_secret.clone(),
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
# VNT example config (v{version})
# Fields marked as Required have no default value.
# ==================================

# --- Required ---

# Virtual network identifier. Required. Default: none.
network_code = "your_network_code"

# Server addresses. Required. Default: none.
# Supported schemes: quic://, tcp://, wss://, dynamic://
# If the scheme is omitted, tcp:// is used.
server = ["quic://1.2.3.4:29872"]

# --- Common optional fields ---

# Virtual IP. Default: auto-assigned by the server.
# ip = "10.10.0.2"

# Enable QUIC optimized transport. Default: false.
# rtx = false

# Enable forward error correction. Default: false.
# fec = false

# Disable P2P hole punching. Default: false.
# no_punch = false

# Enable LZ4 compression. Default: false.
# compress = false

# Route subnet traffic to a virtual peer. Default: [].
# Format: "CIDR,target_virtual_ip"
# input = ["192.168.0.0/24,10.26.0.2", "192.168.1.0/24,10.26.0.3"]

# Allow this node to forward traffic to these destination subnets. Default: [].
# output = ["0.0.0.0/0"]

# Disable built-in subnet NAT. Default: false.
# no_nat = false

# Disable TUN device creation. Default: false.
# no_tun = false

# Port mapping rules. Default: [].
# Format: "tcp://listen_addr-virtual_target_ip-dst_host:dst_port"
# Example:
# port_mapping = ["tcp://0.0.0.0:81-10.0.0.2-10.0.0.2:80"]
# port_mapping = ["tcp://0.0.0.0:81-10.0.0.2-192.168.1.10:80"]
# port_mapping = ["tcp://0.0.0.0:81-10.0.0.2-anyonehost:80"]
# port_mapping = []

# Allow other peers to use this node as a port-mapping egress. Default: false.
# allow_mapping = false

# Local IPC control port for CLI mode. Default: 11233.
# If 11233 is occupied, a random free port is chosen automatically.
# Set to 0 to disable the local IPC server.
# ctrl_port = 11233

# Local P2P tunnel port. Default: 0 (auto-assign).
# tunnel_port = 0

# MTU. Default: 1380. Maximum: 1500.
# mtu = 1380

# --- Device identity ---

# Device name. Default: local hostname.
# device_name = "my-device"

# Device ID. Default: auto-generated from the local machine.
# device_id = "device-id-xxxx"

# TUN interface name. Default: OS/runtime chosen.
# tun_name = "vnt-tun"

# --- Security ---

# Join secret used for server-side admission control. Default: none.
# network_secret = "replace_with_a_long_random_secret"

# Payload encryption password. Default: none.
# password = "123456"

# Server certificate validation mode. Default: "skip".
# Options:
#   "skip"               - no certificate validation
#   "standard"           - validate against system root CAs
#   "finger:<sha256hex>" - pin by certificate fingerprint
# cert_mode = "skip"

# --- STUN ---

# UDP STUN servers. Default: built-in list.
# Built-in default:
# ["stun.miwifi.com:3478", "stun.chat.bilibili.com:3478", "stun.l.google.com:19302"]
# If a host has no port, :3478 is appended automatically.
# udp_stun = ["stun.chat.bilibili.com"]

# TCP STUN servers. Default: built-in list.
# Built-in default:
# ["stun.flashdance.cx:3478", "stun.sipnet.net:3478", "stun.nextcloud.com:443"]
# If a host has no port, :3478 is appended automatically.
# tcp_stun = ["stun.nextcloud.com:443"]
"#,
            version = VERSION
        );
        println!("--- 绀轰緥閰嶇疆鏂囦欢鍐呭 ---\n{}", example);
        if let Some(p) = path {
            std::fs::write(p, &example)?;
            println!("绀轰緥閰嶇疆鏂囦欢宸插啓鍏?{}", p.display());
        }

        Ok(())
    }
}

