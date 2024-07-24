use std::net::Ipv4Addr;

pub fn ips_parse(ips: &Vec<String>) -> Result<Vec<(u32, u32, Ipv4Addr)>, String> {
    let mut in_ips_c = vec![];
    for x in ips {
        let mut split = x.split(",");
        let net = if let Some(net) = split.next() {
            net
        } else {
            return Err(format!("ipv4/mask,ipv4 {:?}", x));
        };
        let ip = if let Some(ip) = split.next() {
            ip
        } else {
            return Err(format!("ipv4/mask,ipv4 {:?}", x));
        };
        let ip = if let Ok(ip) = ip.parse::<Ipv4Addr>() {
            ip
        } else {
            return Err(format!("not ipv4 {:?}", ip));
        };
        let mut split = net.split("/");
        let dest = if let Some(dest) = split.next() {
            dest
        } else {
            return Err(format!("no ipv4/mask {:?}", net));
        };
        let mask = if let Some(mask) = split.next() {
            mask
        } else {
            return Err(format!("no netmask {:?}", net));
        };
        let dest = if let Ok(dest) = dest.parse::<Ipv4Addr>() {
            dest
        } else {
            return Err(format!("not ipv4 {:?}", dest));
        };
        let mask = to_ip(mask)?;
        in_ips_c.push((u32::from_be_bytes(dest.octets()), mask, ip));
    }
    Ok(in_ips_c)
}

pub fn out_ips_parse(ips: &Vec<String>) -> Result<Vec<(u32, u32)>, String> {
    let mut in_ips_c = vec![];
    for x in ips {
        let mut split = x.split("/");
        let dest = if let Some(dest) = split.next() {
            dest
        } else {
            return Err(format!("no ipv4/mask {:?}", x));
        };
        let mask = if let Some(mask) = split.next() {
            mask
        } else {
            return Err(format!("no netmask {:?}", x));
        };
        let dest = if let Ok(dest) = dest.parse::<Ipv4Addr>() {
            dest
        } else {
            return Err(format!("not ipv4 {:?}", dest));
        };
        let mask = to_ip(mask)?;
        in_ips_c.push((u32::from_be_bytes(dest.octets()), mask));
    }
    Ok(in_ips_c)
}

pub fn to_ip(mask: &str) -> Result<u32, String> {
    if let Ok(m) = mask.parse::<u32>() {
        if m > 32 {
            return Err("not netmask".to_string());
        }
        let mut mask = 0u32;
        for i in 0..m {
            mask = mask | (1 << (31 - i));
        }
        Ok(mask)
    } else {
        Err("not netmask".to_string())
    }
}
