use std::net::Ipv4Addr;

pub fn ips_parse(ips: &Vec<String>,in_ip:bool) -> Result<Vec<(u32, u32, Ipv4Addr)>, String> {
    let mut in_ips_c = vec![];
    for x in ips {
        let mut split = x.split(",");
        let net = if let Some(net) = split.next() {
            net
        } else {
            return Err("ipv4/mask,ipv4".to_string());
        };
        let ip = if let Some(ip) = split.next() {
            ip
        } else {
            if in_ip{
                return Err("ipv4/mask,ipv4".to_string());
            }
            "0.0.0.0"
        };
        let ip = if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            ip
        } else {
            return Err("not ipv4".to_string());
        };
        let mut split = net.split("/");
        let dest = if let Some(dest) = split.next() {
            dest
        } else {
            return Err("no ipv4/mask".to_string());
        };
        let mask = if let Some(mask) = split.next() {
            mask
        } else {
            return Err("no netmask".to_string());
        };
        let dest = if let Ok(dest) = dest.parse::<Ipv4Addr>() {
            dest
        } else {
            return Err("not ipv4".to_string());
        };
        let mask = if let Ok(m) = mask.parse::<u32>() {
            let mut mask = 0 as u32;
            for i in 0..m {
                mask = mask | (1 << (31 - i));
            }
            mask
        } else {
            return Err("not netmask".to_string());
        };
        in_ips_c.push((u32::from_be_bytes(dest.octets()), mask, ip));
    }
    Ok(in_ips_c)
}