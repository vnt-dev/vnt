use std::net::{Ipv4Addr, ToSocketAddrs};
use ansi_term::Colour;
use ansi_term::Colour::{Green, Yellow};
use getopts::Options;
use tokio::io::{AsyncBufReadExt, BufReader};
use switch::core::{Config, SwitchUtil};
use switch::handle::PeerDeviceStatus;
use switch::handle::registration_handler::ReqEnum;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("", "token", "必选，使用相同的token，就能组建一个局域网络", "");
    opts.optopt("", "device-id", "必选，设备唯一标识符，凭id分配ip", "");
    opts.optopt("", "name", "必选，给设备一个名字", "");
    opts.optflag("", "unused-cmd", "关闭交互式命令");
    opts.optopt("", "server", "注册和中继服务器地址", "");
    opts.optopt("", "nat-test-server", "NAT探测服务器地址，使用逗号分隔", "");
    opts.optflag("", "tap", "使用tap模式");
    opts.optmulti("", "in-ip", "配置点对网(IP代理)时使用，--in-ip 192.168.10.0/24,10.26.0.3，表示允许接收网段192.168.10.0/24的数据并转 发到10.26.0.3", "");
    opts.optmulti("", "out-ip", "配置点对网时使用，--out-ip 192.168.10.0/24,192.168.1.10，表示允许目标为192.168.10.0/24的数据从网卡192.168.1.10转发出去", "");
    opts.optopt("", "password", "使用该密码生成的密钥对客户端数据进行加密，并且服务端无法解密。使用相同密码的客户端才能通信", "");
    opts.optflag("", "simulate-multicast", "模拟组播，默认情况下组播数据会被当作广播发送，兼容性更强，但是会造成流量浪费。开启后会模拟真实组播的数据发送");
    opts.optflag("h", "help", "帮助");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => {
            print_usage(&program, opts);
            println!();
            println!("{}", f.to_string());
            return;
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if !matches.opt_present("token") || !matches.opt_present("device-id") || !matches.opt_present("name") {
        print_usage(&program, opts);
        return;
    }
    let tap = matches.opt_present("tap");
    let token: String = matches.opt_get("token").unwrap().unwrap();
    let device_id: String = matches.opt_get("device-id").unwrap().unwrap();
    let name: String = matches.opt_get("name").unwrap().unwrap();
    let server_address = matches.opt_get_default("server", "nat1.wherewego.top:29871".to_string()).unwrap();
    let server_address = server_address.to_socket_addrs().unwrap().next().unwrap();
    let nat_test_server = matches.opt_get_default("nat-test-server",
                                                  "nat1.wherewego.top:35061,nat1.wherewego.top:35062,nat2.wherewego.top:35061,nat2.wherewego.top:35062".to_string()).unwrap();

    let nat_test_server = nat_test_server.split(",").flat_map(|a| a.to_socket_addrs()).flatten()
        .collect::<Vec<_>>();

    let in_ip = matches.opt_strs("in-ip");
    let in_ip = match ips_parse(&in_ip) {
        Ok(in_ip) => { in_ip }
        Err(e) => {
            print_usage(&program, opts);
            println!();
            println!("--in-ip {}", e);
            return;
        }
    };
    let out_ip = matches.opt_strs("out-ip");
    let out_ip = match ips_parse(&out_ip) {
        Ok(out_ip) => { out_ip }
        Err(e) => {
            print_usage(&program, opts);
            println!();
            println!("--out-ip {}", e);
            return;
        }
    };
    let password: Option<String> = matches.opt_get("password").unwrap();
    let simulate_multicast = matches.opt_present("simulate-multicast");
    let unused_cmd = matches.opt_present("unused-cmd");
    let config = Config::new(tap,
                             token, device_id, name,
                             server_address,
                             nat_test_server, in_ip,
                             out_ip, password, simulate_multicast, );
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
    println!("virtual_ip:{}", Green.paint(response.virtual_ip.to_string()));
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
    if unused_cmd {
        switch.wait_stop().await;
    } else {
        let stdin = tokio::io::stdin();
        let mut cmd = String::new();
        let mut reader = BufReader::new(stdin);
        loop {
            cmd.clear();
            println!("input:list,exit");
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
                            match cmd[..len].trim() {
                                "list" => {
                                    let mut list =  switch.device_list();
                                    if list.is_empty(){
                                        println!("No other devices found");
                                        continue;
                                    }
                                    list.sort_by_key(|v|{(v.virtual_ip,v.status)});
                                    for x in list {
                                        match x.status {
                                            PeerDeviceStatus::Online => {
                                                println!(" {}",Green.paint(x.virtual_ip.to_string()));
                                                println!("   name:{}",x.name);
                                                println!("   status:Online");
                                                if let Some(route) = switch.route(&x.virtual_ip){
                                                    if route.is_p2p() {
                                                        println!("   connect:{}",Green.paint("p2p"));
                                                    }else {
                                                        println!("   connect:{}",Yellow.paint("relay"));
                                                    }
                                                    println!("   rt:{}",route.rt);
                                                    println!("   ->:{}",route.addr);
                                                }
                                            }
                                            PeerDeviceStatus::Offline => {
                                                println!(" {}",x.virtual_ip);
                                                println!("   name:{}",x.name);
                                                println!("   status:{}",Colour::RGB(150,150,150).paint("Offline"));
                                            }
                                        }
                                    }
                                    println!();
                                }
                                "exit" =>{
                                    let _ = switch.stop();
                                    break;
                                }
                                _ => {
                                }
                            }

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

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    println!("version:1.0.7");
    print!("{}", opts.usage(&brief));
}

fn ips_parse(ips: &Vec<String>) -> Result<Vec<(u32, u32, Ipv4Addr)>, String> {
    let mut in_ips_c = vec![];
    for x in ips {
        let mut split = x.split(",");
        let net = if let Some(net) = split.next() {
            net
        } else {
            return Err("参数错误".to_string());
        };
        let ip = if let Some(ip) = split.next() {
            ip
        } else {
            return Err("参数错误".to_string());
        };
        let ip = if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            ip
        } else {
            return Err("参数错误".to_string());
        };
        let mut split = net.split("/");
        let dest = if let Some(dest) = split.next() {
            dest
        } else {
            return Err("参数错误".to_string());
        };
        let mask = if let Some(mask) = split.next() {
            mask
        } else {
            return Err("参数错误".to_string());
        };
        let dest = if let Ok(dest) = dest.parse::<Ipv4Addr>() {
            dest
        } else {
            return Err("参数错误".to_string());
        };
        let mask = if let Ok(m) = mask.parse::<u32>() {
            let mut mask = 0 as u32;
            for i in 0..m {
                mask = mask | (1 << (31 - i));
            }
            mask
        } else {
            return Err("参数错误".to_string());
        };
        in_ips_c.push((u32::from_be_bytes(dest.octets()), mask, ip));
    }
    Ok(in_ips_c)
}
