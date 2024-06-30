use crate::args_parse::{ips_parse, out_ips_parse};
#[cfg(feature = "command")]
use crate::command;
use crate::{config, generated_serial_number};
use anyhow::anyhow;
use console::style;
use getopts::Options;
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use vnt::channel::punch::PunchModel;
use vnt::channel::UseChannelType;
use vnt::cipher::CipherModel;
use vnt::compression::Compressor;
use vnt::core::Config;

pub fn app_home() -> io::Result<PathBuf> {
    let root_path = match std::env::current_exe() {
        Ok(path) => {
            if let Some(v) = path.as_path().parent() {
                v.to_path_buf()
            } else {
                log::warn!("current_exe parent none:{:?}", path);
                PathBuf::new()
            }
        }
        Err(e) => {
            log::warn!("current_exe err:{:?}", e);
            PathBuf::new()
        }
    };
    let path = root_path.join("env");
    if !path.exists() {
        std::fs::create_dir_all(&path)?;
    }
    Ok(path)
}

pub fn parse_args_config() -> anyhow::Result<Option<(Config, Vec<String>, bool)>> {
    #[cfg(feature = "log")]
    let _ = log4rs::init_file("log4rs.yaml", Default::default());
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("k", "", "组网标识", "<token>");
    opts.optopt("n", "", "设备名称", "<name>");
    opts.optopt("d", "", "设备标识", "<id>");
    opts.optflag("c", "", "关闭交互式命令");
    opts.optopt("s", "", "注册和中继服务器地址", "<server>");
    opts.optmulti("e", "", "stun服务器", "<stun-server>");
    opts.optflag("a", "", "使用tap模式");
    opts.optopt("", "nic", "虚拟网卡名称,windows下使用tap则必填", "<tun0>");
    opts.optmulti("i", "", "配置点对网(IP代理)入站时使用", "<in-ip>");
    opts.optmulti("o", "", "配置点对网出站时使用", "<out-ip>");
    opts.optopt("w", "", "客户端加密", "<password>");
    opts.optflag("W", "", "服务端加密");
    opts.optopt("u", "", "自定义mtu(默认为1430)", "<mtu>");
    opts.optopt("", "ip", "指定虚拟ip", "<ip>");
    opts.optflag("", "relay", "仅使用服务器转发");
    opts.optopt("", "par", "任务并行度(必须为正整数)", "<parallel>");
    opts.optopt("", "model", "加密模式", "<model>");
    opts.optflag("", "finger", "指纹校验");
    opts.optopt("", "punch", "取值ipv4/ipv6", "<punch>");
    opts.optopt("", "ports", "监听的端口", "<port,port>");
    opts.optflag("", "cmd", "开启窗口输入");
    opts.optflag("", "no-proxy", "关闭内置代理");
    opts.optflag("", "first-latency", "优先延迟");
    opts.optopt("", "use-channel", "使用通道 relay/p2p", "<use-channel>");
    opts.optopt("", "packet-loss", "丢包率", "<packet-loss>");
    opts.optopt("", "packet-delay", "延迟", "<packet-delay>");
    opts.optmulti("", "dns", "dns", "<dns>");
    opts.optmulti("", "mapping", "mapping", "<mapping>");
    opts.optmulti("", "vnt-mapping", "vnt-mapping", "<mapping>");
    opts.optopt("f", "", "配置文件", "<conf>");
    opts.optopt("", "compressor", "压缩算法", "<lz4>");
    //"后台运行时,查看其他设备列表"
    opts.optflag("", "add", "后台运行时,添加地址");
    opts.optflag("", "list", "后台运行时,查看其他设备列表");
    opts.optflag("", "all", "后台运行时,查看其他设备完整信息");
    opts.optflag("", "info", "后台运行时,查看当前设备信息");
    opts.optflag("", "route", "后台运行时,查看数据转发路径");
    opts.optflag("", "stop", "停止后台运行");
    opts.optflag("h", "help", "帮助");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            print_usage(&program, opts);
            return Err(anyhow::anyhow!("{}", f.to_string()));
        }
    };
    if matches.opt_present("h") || args.len() == 1 {
        print_usage(&program, opts);
        return Ok(None);
    }

    #[cfg(feature = "command")]
    if matches.opt_present("list") {
        command::command(command::CommandEnum::List);
        return Ok(None);
    } else if matches.opt_present("info") {
        command::command(command::CommandEnum::Info);
        return Ok(None);
    } else if matches.opt_present("stop") {
        command::command(command::CommandEnum::Stop);
        return Ok(None);
    } else if matches.opt_present("route") {
        command::command(command::CommandEnum::Route);
        return Ok(None);
    } else if matches.opt_present("all") {
        command::command(command::CommandEnum::All);
        return Ok(None);
    }
    let conf = matches.opt_str("f");
    let (config, vnt_link_config, cmd) = if conf.is_some() {
        match config::read_config(&conf.unwrap()) {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow::anyhow!("conf err {}", e));
            }
        }
    } else {
        if !matches.opt_present("k") {
            print_usage(&program, opts);
            return Err(anyhow::anyhow!("parameter -k not found ."));
        }
        #[cfg(target_os = "windows")]
        #[cfg(feature = "integrated_tun")]
        let tap = matches.opt_present("a");
        #[cfg(feature = "integrated_tun")]
        let device_name = matches.opt_str("nic");
        let token: String = matches.opt_get("k").unwrap().unwrap();
        let device_id = matches.opt_get_default("d", String::new()).unwrap();
        let device_id = if device_id.is_empty() {
            config::get_device_id()
        } else {
            device_id
        };
        if device_id.is_empty() {
            print_usage(&program, opts);
            return Err(anyhow::anyhow!("parameter -d not found ."));
        }
        let name = matches
            .opt_get_default(
                "n",
                gethostname::gethostname()
                    .to_str()
                    .unwrap_or("UnknownName")
                    .to_string(),
            )
            .unwrap();
        let server_address_str = matches
            .opt_get_default("s", "vnt.wherewego.top:29872".to_string())
            .unwrap();

        let mut stun_server = matches.opt_strs("e");
        if stun_server.is_empty() {
            for x in config::PUB_STUN {
                stun_server.push(x.to_string());
            }
        }
        let dns = matches.opt_strs("dns");
        let in_ip = matches.opt_strs("i");
        let in_ip = match ips_parse(&in_ip) {
            Ok(in_ip) => in_ip,
            Err(e) => {
                print_usage(&program, opts);
                println!();
                println!("-i: {:?} {}", in_ip, e);
                return Err(anyhow::anyhow!("example: -i 192.168.0.0/24,10.26.0.3"));
            }
        };
        let out_ip = matches.opt_strs("o");
        let out_ip = match out_ips_parse(&out_ip) {
            Ok(out_ip) => out_ip,
            Err(e) => {
                print_usage(&program, opts);
                println!();
                println!("-o: {:?} {}", out_ip, e);
                return Err(anyhow::anyhow!("example: -o 0.0.0.0/0"));
            }
        };
        let password: Option<String> = matches.opt_get("w").unwrap();
        let server_encrypt = matches.opt_present("W");
        #[cfg(not(feature = "server_encrypt"))]
        {
            if server_encrypt {
                println!("Server encryption not supported");
                return Err(anyhow::anyhow!("Server encryption not supported"));
            }
        }
        let mtu: Option<String> = matches.opt_get("u").unwrap();
        let mtu = if let Some(mtu) = mtu {
            match u32::from_str(&mtu) {
                Ok(mtu) => Some(mtu),
                Err(e) => {
                    print_usage(&program, opts);
                    println!();
                    println!("'-u {}' {}", mtu, e);
                    return Err(anyhow::anyhow!("'-u {}' {}", mtu, e));
                }
            }
        } else {
            None
        };
        let virtual_ip: Option<String> = matches.opt_get("ip").unwrap();
        let virtual_ip =
            virtual_ip.map(|v| Ipv4Addr::from_str(&v).expect(&format!("'--ip {}' error", v)));
        if let Some(virtual_ip) = virtual_ip {
            if virtual_ip.is_unspecified() || virtual_ip.is_broadcast() || virtual_ip.is_multicast()
            {
                return Err(anyhow::anyhow!("'--ip {}' invalid", virtual_ip));
            }
        }
        let relay = matches.opt_present("relay");

        let cipher_model = match matches.opt_get::<CipherModel>("model") {
            Ok(model) => {
                #[cfg(not(any(feature = "aes_gcm", feature = "server_encrypt")))]
                {
                    if password.is_some() && model.is_none() {
                        return Err(anyhow::anyhow!("'--model ' undefined"));
                    }
                    model.unwrap_or(CipherModel::None)
                }
                #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
                model.unwrap_or(CipherModel::AesGcm)
            }
            Err(e) => {
                return Err(anyhow::anyhow!("'--model ' invalid,{}", e));
            }
        };

        let finger = matches.opt_present("finger");
        let punch_model = matches
            .opt_get::<PunchModel>("punch")
            .unwrap()
            .unwrap_or(PunchModel::All);
        let use_channel_type = matches
            .opt_get::<UseChannelType>("use-channel")
            .unwrap()
            .unwrap_or_else(|| {
                if relay {
                    UseChannelType::Relay
                } else {
                    UseChannelType::All
                }
            });

        let ports = matches
            .opt_get::<String>("ports")
            .unwrap_or(None)
            .map(|v| v.split(",").map(|x| x.parse().unwrap_or(0)).collect());

        let cmd = matches.opt_present("cmd");
        #[cfg(feature = "ip_proxy")]
        #[cfg(feature = "integrated_tun")]
        let no_proxy = matches.opt_present("no-proxy");
        let first_latency = matches.opt_present("first-latency");
        let packet_loss = matches
            .opt_get::<f64>("packet-loss")
            .expect("--packet-loss");
        let packet_delay = matches
            .opt_get::<u32>("packet-delay")
            .expect("--packet-delay")
            .unwrap_or(0);
        #[cfg(feature = "port_mapping")]
        let port_mapping_list = matches.opt_strs("mapping");
        let vnt_mapping_list = matches.opt_strs("vnt-mapping");
        let compressor = if let Some(compressor) = matches.opt_str("compressor").as_ref() {
            Compressor::from_str(compressor)
                .map_err(|e| anyhow!("{}", e))
                .unwrap()
        } else {
            Compressor::None
        };
        let config = match Config::new(
            #[cfg(feature = "integrated_tun")]
            #[cfg(target_os = "windows")]
            tap,
            token,
            device_id,
            name,
            server_address_str,
            dns,
            stun_server,
            in_ip,
            out_ip,
            password,
            mtu,
            virtual_ip,
            #[cfg(feature = "integrated_tun")]
            #[cfg(feature = "ip_proxy")]
            no_proxy,
            server_encrypt,
            cipher_model,
            finger,
            punch_model,
            ports,
            first_latency,
            #[cfg(feature = "integrated_tun")]
            device_name,
            use_channel_type,
            packet_loss,
            packet_delay,
            #[cfg(feature = "port_mapping")]
            port_mapping_list,
            compressor,
        ) {
            Ok(config) => config,
            Err(e) => {
                println!("config.toml error: {}", e);
                std::process::exit(1);
            }
        };
        (config, vnt_mapping_list, cmd)
    };
    println!("version {}", vnt::VNT_VERSION);
    println!("Serial:{}", generated_serial_number::SERIAL_NUMBER);
    log::info!(
        "version:{},Serial:{}",
        vnt::VNT_VERSION,
        generated_serial_number::SERIAL_NUMBER
    );
    Ok(Some((config, vnt_link_config, cmd)))
}

fn print_usage(program: &str, _opts: Options) {
    println!("Usage: {} [options]", program);
    println!("version:{}", vnt::VNT_VERSION);
    println!("Serial:{}", generated_serial_number::SERIAL_NUMBER);
    println!("Options:");
    println!(
        "  -k <token>          {}",
        green("使用相同的token,就能组建一个局域网络".to_string())
    );
    println!("  -n <name>           给设备一个名字,便于区分不同设备,默认使用系统版本");
    println!("  -d <id>             设备唯一标识符,不使用--ip参数时,服务端凭此参数分配虚拟ip,注意不能重复");
    println!(
        "  -s <server>         注册和中继服务器地址,协议支持使用tcp://和ws://和wss://,默认为udp://"
    );
    println!("  -e <stun-server>    stun服务器,用于探测NAT类型,可使用多个地址,如-e stun.miwifi.com -e turn.cloudflare.com");
    #[cfg(target_os = "windows")]
    #[cfg(feature = "integrated_tun")]
    println!(
        "  -a                  使用tap模式,默认使用tun模式,使用tap时需要配合'--nic'参数指定tap网卡"
    );
    println!("  -i <in-ip>          配置点对网(IP代理)时使用,-i 192.168.0.0/24,10.26.0.3表示允许接收网段192.168.0.0/24的数据");
    println!("                      并转发到10.26.0.3,可指定多个网段");
    println!("  -o <out-ip>         配置点对网时使用,-o 192.168.0.0/24表示允许将数据转发到192.168.0.0/24,可指定多个网段");

    println!("  -w <password>       使用该密码生成的密钥对客户端数据进行加密,并且服务端无法解密,使用相同密码的客户端才能通信");
    #[cfg(feature = "server_encrypt")]
    println!("  -W                  加密当前客户端和服务端通信的数据,请留意服务端指纹是否正确");
    println!("  -u <mtu>            自定义mtu(不加密默认为1450，加密默认为1410)");
    #[cfg(feature = "file_config")]
    println!("  -f <conf_file>      读取配置文件中的配置");

    println!("  --ip <ip>           指定虚拟ip,指定的ip不能和其他设备重复,必须有效并且在服务端所属网段下,默认情况由服务端分配");
    let mut enums = String::new();
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    enums.push_str("/aes_gcm");
    #[cfg(feature = "chacha20_poly1305")]
    enums.push_str("/chacha20_poly1305/chacha20");
    #[cfg(feature = "aes_cbc")]
    enums.push_str("/aes_cbc");
    #[cfg(feature = "aes_ecb")]
    enums.push_str("/aes_ecb");
    #[cfg(feature = "sm4_cbc")]
    enums.push_str("/sm4_cbc");
    enums.push_str("/xor");
    println!(
        "  --model <model>     加密模式(默认aes_gcm),可选值{}",
        &enums[1..]
    );
    #[cfg(any(
        feature = "aes_gcm",
        feature = "chacha20_poly1305",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    println!("  --finger            增加数据指纹校验,可增加安全性,如果服务端开启指纹校验,则客户端也必须开启");
    println!("  --punch <punch>     取值ipv4/ipv6/all,ipv4表示仅使用ipv4打洞");
    println!("  --ports <port,port> 取值0~65535,指定本地监听的一组端口,默认监听两个随机端口,使用过多端口会增加网络负担");
    #[cfg(feature = "command")]
    println!("  --cmd               开启交互式命令,使用此参数开启控制台输入");
    #[cfg(feature = "ip_proxy")]
    #[cfg(feature = "integrated_tun")]
    println!("  --no-proxy          关闭内置代理,如需点对网则需要配置网卡NAT转发");
    println!("  --first-latency     优先低延迟的通道,默认情况优先使用p2p通道");
    println!("  --use-channel <p2p> 使用通道 relay/p2p/all,默认两者都使用");
    #[cfg(not(feature = "vn-link-model"))]
    println!("  --nic <tun0>        指定虚拟网卡名称");
    println!("  --packet-loss <0>   模拟丢包,取值0~1之间的小数,程序会按设定的概率主动丢包,可用于模拟弱网");
    println!(
        "  --packet-delay <0>  模拟延迟,整数,单位毫秒(ms),程序会按设定的值延迟发包,可用于模拟弱网"
    );
    println!("  --dns <host:port>   DNS服务器地址,可使用多个dns,不指定时使用系统解析");

    #[cfg(feature = "port_mapping")]
    println!("  --mapping <mapping> 端口映射,例如 --mapping udp:0.0.0.0:80-domain:80 映射目标是本地路由能访问的设备");

    #[cfg(all(feature = "lz4", feature = "zstd"))]
    println!("  --compressor <lz4>  启用压缩,可选值lz4/zstd<,level>,level为压缩级别,例如 --compressor lz4 或--compressor zstd,10");
    #[cfg(feature = "lz4")]
    #[cfg(not(feature = "zstd"))]
    println!("  --compressor <lz4>  启用压缩,可选值lz4,例如 --compressor lz4");
    #[cfg(feature = "zstd")]
    #[cfg(not(feature = "lz4"))]
    println!("  --compressor <zstd>  启用压缩,可选值zstd<,level>,level为压缩级别,例如 --compressor zstd,10");

    #[cfg(not(feature = "integrated_tun"))]
    println!(
        "  --vnt-mapping <x>   {}",
        green(
            "vnt地址映射,例如 --vnt-mapping tcp:80-10.26.0.10:80 映射目标是vnt网络或其子网中的设备"
                .to_string()
        )
    );
    println!();
    #[cfg(feature = "command")]
    {
        // #[cfg(not(feature = "integrated_tun"))]
        // println!(
        //     "  --add               {}",
        //     yellow("后台运行时,添加VNT地址映射 用法同'--vnt-mapping'".to_string())
        // );
        println!(
            "  --list              {}",
            yellow("后台运行时,查看其他设备列表".to_string())
        );
        println!(
            "  --all               {}",
            yellow("后台运行时,查看其他设备完整信息".to_string())
        );
        println!(
            "  --info              {}",
            yellow("后台运行时,查看当前设备信息".to_string())
        );
        println!(
            "  --route             {}",
            yellow("后台运行时,查看数据转发路径".to_string())
        );
        println!(
            "  --stop              {}",
            yellow("停止后台运行".to_string())
        );
    }
    println!("  -h, --help          帮助");
}

fn green(str: String) -> impl std::fmt::Display {
    style(str).green()
}

#[cfg(feature = "command")]
fn yellow(str: String) -> impl std::fmt::Display {
    style(str).yellow()
}
