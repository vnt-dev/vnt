use std::net::ToSocketAddrs;
use std::str::FromStr;
#[cfg(not(feature = "mini"))]
use console::style;
use getopts::Options;
use tokio::io::{AsyncBufReadExt, BufReader};
use common::args_parse::ips_parse;
use switch::core::{Config, SwitchUtil};
use switch::handle::registration_handler::ReqEnum;

mod command;
mod console_out;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.long_only(false);
    opts.optopt("k", "", &format!("{}", green("使用相同的token,就能组建一个局域网络".to_string())), "<token>");
    opts.optopt("n", "", "给设备一个名字", "<name>");
    opts.optopt("d", "", "设备唯一标识符,凭id分配ip", "<id>");
    #[cfg(not(feature = "mini"))]
    opts.optflag("c", "", "关闭交互式命令");
    opts.optopt("s", "", "注册和中继服务器地址", "<server>");
    opts.optopt("e", "", "NAT探测服务器地址,使用逗号分隔", "<addr1,addr2>");
    opts.optflag("a", "", "使用tap模式,默认使用tun模式");
    opts.optmulti("i", "", "配置点对网(IP代理)时使用,--in-ip 192.168.10.0/24,10.26.0.3，表示允许接收网段192.168.10.0/24的数据并转发到10.26.0.3", "<in-ip>");
    opts.optmulti("o", "", "配置点对网时使用,--out-ip 192.168.10.0/24,192.168.1.10，表示允许目标为192.168.10.0/24的数据从网卡192.168.1.10转发出去", "<out-ip>");
    opts.optopt("w", "", "使用该密码生成的密钥对客户端数据进行加密,并且服务端无法解密,使用相同密码的客户端才能通信", "<password>");
    opts.optflag("m", "", "模拟组播,默认情况下组播数据会被当作广播发送,开启后会模拟真实组播的数据发送");
    opts.optopt("u", "", "虚拟网卡mtu值", "<mtu>");
    //"后台运行时,查看其他设备列表"
    opts.optflag("", "list", &format!("{}", yellow("后台运行时,查看其他设备列表".to_string())));
    opts.optflag("", "all", &format!("{}", yellow("后台运行时,查看其他设备完整信息".to_string())));
    opts.optflag("", "info", &format!("{}", yellow("后台运行时,查看当前设备信息".to_string())));
    opts.optflag("", "route", &format!("{}", yellow("后台运行时,查看数据转发路径".to_string())));
    opts.optflag("", "stop", &format!("{}", yellow("停止后台运行".to_string())));
    opts.optflag("h", "help", "帮助");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => {
            print_usage(&program, opts);
            println!("{}", f.to_string());
            return;
        }
    };
    if matches.opt_present("list") {
        command::command(command::CommandEnum::List);
        return;
    } else if matches.opt_present("info") {
        command::command(command::CommandEnum::Info);
        return;
    } else if matches.opt_present("stop") {
        command::command(command::CommandEnum::Stop);
        return;
    } else if matches.opt_present("route") {
        command::command(command::CommandEnum::Route);
        return;
    } else if matches.opt_present("all") {
        command::command(command::CommandEnum::All);
        return;
    }
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if !matches.opt_present("k") {
        print_usage(&program, opts);
        println!("parameter -k not found .");
        return;
    }
    let tap = matches.opt_present("a");
    let token: String = matches.opt_get("k").unwrap().unwrap();
    let device_id = matches.opt_get_default("d", String::new()).unwrap();
    #[cfg(not(feature = "mini"))]
        let device_id = if device_id.is_empty() {
        common::identifier::get_unique_identifier().unwrap_or(String::new())
    } else {
        device_id
    };
    if device_id.is_empty() {
        print_usage(&program, opts);
        println!("parameter -d not found .");
        return;
    }
    let name = matches.opt_get_default("n", os_info::get().to_string()).unwrap();
    let server_address_str = matches.opt_get_default("s", "nat1.wherewego.top:29871".to_string()).unwrap();
    let server_address = server_address_str.to_socket_addrs().unwrap().next().unwrap();
    let nat_test_server = matches.opt_get_default("e",
                                                  "nat1.wherewego.top:35061,nat1.wherewego.top:35062,nat2.wherewego.top:35061,nat2.wherewego.top:35062".to_string()).unwrap();

    let nat_test_server = nat_test_server.split(",").flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();

    let in_ip = matches.opt_strs("i");
    let in_ip = match ips_parse(&in_ip) {
        Ok(in_ip) => { in_ip }
        Err(e) => {
            print_usage(&program, opts);
            println!();
            println!("-i {}", e);
            return;
        }
    };
    let out_ip = matches.opt_strs("o");
    let out_ip = match ips_parse(&out_ip) {
        Ok(out_ip) => { out_ip }
        Err(e) => {
            print_usage(&program, opts);
            println!();
            println!("-o {}", e);
            return;
        }
    };
    let password: Option<String> = matches.opt_get("w").unwrap();
    let simulate_multicast = matches.opt_present("m");
    #[cfg(feature = "mini")]
        let unused_cmd = true;
    #[cfg(not(feature = "mini"))]
        let unused_cmd = matches.opt_present("c");
    let mtu: Option<String> = matches.opt_get("u").unwrap();
    let mtu = if let Some(mtu) = mtu {
        match u16::from_str(&mtu) {
            Ok(mtu) => {
                Some(mtu)
            }
            Err(e) => {
                print_usage(&program, opts);
                println!();
                println!("-u {}", e);
                return;
            }
        }
    } else {
        None
    };
    let config = Config::new(tap,
                             token, device_id, name,
                             server_address, server_address_str,
                             nat_test_server, in_ip,
                             out_ip, password, simulate_multicast, mtu);
    let mut switch_util = SwitchUtil::new(config).await.unwrap();
    let response = loop {
        match switch_util.connect().await {
            Ok(response) => {
                break response;
            }
            Err(e) => {
                match e {
                    ReqEnum::TokenError => {
                        println!("token error");
                    }
                    ReqEnum::AddressExhausted => {
                        println!("address exhausted");
                    }
                    ReqEnum::Timeout => {
                        println!("timeout...");
                        continue;
                    }
                    ReqEnum::ServerError(str) => {
                        println!("error:{}", str);
                    }
                    ReqEnum::Other(str) => {
                        println!("error:{}", str);
                    }
                }
                return;
            }
        }
    };
    println!(" ====== Connect Successfully ====== ");
    println!("virtual_gateway:{}", response.virtual_gateway);
    println!("virtual_ip:{}", green(response.virtual_ip.to_string()));
    let driver_info = switch_util.create_iface().unwrap();
    println!(" ====== Create Network Interface Successfully ====== ");
    println!("name:{}", driver_info.name);
    println!("version:{}", driver_info.version);
    let mut switch = match switch_util.build().await {
        Ok(switch) => {
            switch
        }
        Err(e) => {
            println!("error:{}", e);
            return;
        }
    };
    println!(" ====== Start Successfully ====== ");
    let switch_s = switch.clone();
    tokio::spawn(async {
        if let Err(e) = command::server::CommandServer::new().start(switch_s).await {
            println!("command error :{}", e);
        }
    });
    if unused_cmd {
        switch.wait_stop().await;
    } else {
        #[cfg(not(feature = "mini"))]
        {
            let stdin = tokio::io::stdin();
            let mut cmd = String::new();
            let mut reader = BufReader::new(stdin);
            loop {
                cmd.clear();
                println!("input:list,info,route,all,stop");
                tokio::select! {
                _ = switch.wait_stop()=>{
                    break;
                }
                rs = reader.read_line(&mut cmd)=>{
                     match rs {
                        Ok(len) => {
                            if len ==0 {
                                break;
                            }
                            match cmd[..len].to_lowercase().trim() {
                                "list" => {
                                    let list = command::command_list(&switch);
                                    console_out::console_device_list(list);
                                }
                                "info"=>{
                                    let info = command::command_info(&switch);
                                    console_out::console_info(info);
                                }
                                "route" =>{
                                    let route = command::command_route(&switch);
                                    console_out::console_route_table(route);
                                }
                                "all" =>{
                                    let list = command::command_list(&switch);
                                    console_out::console_device_list_all(list);
                                }
                                "stop" =>{
                                    let _ = switch.stop();
                                    break;
                                }
                                _ => {
                                }
                            }
                            println!();
                        }
                        Err(e) => {
                            println!("input err:{}",e);
                            break;
                        }
                    }
                }
            }
            }
            switch.wait_stop().await;
        }
    }
    std::process::exit(0);
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("version:1.1.0");
    println!("{}", opts.usage(&brief));
}

fn green(str: String) -> impl std::fmt::Display {
    style(str).green()
}

fn yellow(str: String) -> impl std::fmt::Display {
    style(str).yellow()
}

