use std::{io, thread};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::xfer::DnsRequestOptions;

/// 解析记录优先级
pub enum RecordPriority{
    Ipv4,
    Ipv6,
}
impl FromStr for RecordPriority {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(RecordPriority::Ipv4),
            "ipv6" => Ok(RecordPriority::Ipv6),
            _ => Err(format!("not match '{}', enum: ipv4/ipv6", s)),
        }
    }
}
impl Default for RecordPriority {
    fn default() -> Self {
        RecordPriority::Ipv6
    }
}
pub fn dns_query_all(
    domain: &str,
    name_servers: Vec<SocketAddr>,
) -> anyhow::Result<Vec<SocketAddr>> {
    match SocketAddr::from_str(domain) {
        Ok(addr) => {
            return Ok(vec![addr]);
        }
        Err(_) => {
            if name_servers.is_empty() {
                Err(anyhow::anyhow!("name server is none"))?
            }
            let mut err: Option<anyhow::Error> = None;
            for name_server in name_servers {
                if let Some(domain) = domain.strip_prefix("txt:") {
                    return txt_dns(domain, name_server);
                }
                let end_index = domain
                    .rfind(":")
                    .with_context(|| format!("{:?} not port", domain))?;
                let host = &domain[..end_index];
                let port = u16::from_str(&domain[end_index + 1..])
                    .with_context(|| format!("{:?} not port", domain))?;
                let th1 = {
                    let host = host.to_string();
                    thread::spawn(move || a_dns(host, name_server))
                };
                let th2 = {
                    let host = host.to_string();
                    thread::spawn(move || aaaa_dns(host, name_server))
                };
                let mut addr = Vec::new();
                match th1.join().unwrap() {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        err.replace(anyhow::anyhow!("{}",e));
                    }
                }
                match th2.join().unwrap() {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        if addr.is_empty() {
                            if let Some(err) = &mut err {
                                *err = anyhow::anyhow!("{},{}",err,e);
                            } else {
                                err.replace(anyhow::anyhow!("{}",e));
                            }
                            continue;
                        }
                    }
                }
                if addr.is_empty() {
                    continue;
                }
                return Ok(addr);
            }
            if let Some(e) = err {
                Err(e)
            } else {
                Err(anyhow::anyhow!("dns query failed"))
            }
        }
    }
}

pub fn dns_query(domain: &str, name_server: SocketAddr) -> anyhow::Result<Vec<SocketAddr>> {
    dns_query_all(domain, vec![name_server])
}

fn query(
    udp: &UdpSocket,
    domain: &str,
    name_server: SocketAddr,
    record_type: RecordType,
) -> anyhow::Result<Message> {
    let name = Name::from_str(domain).context("domain error")?;
    let query = Query::query(name.clone(), record_type);
    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    let request = build_message(query, options);

    let request = request.to_vec()?;
    udp.connect(name_server)
        .with_context(|| format!("name server {:?} error ", name_server));
    let mut count = 0;
    let mut buf = [0; 65536];
    let len = loop {
        udp.send(&request)?;

        match udp.recv(&mut buf) {
            Ok(len) => {
                break len;
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock {
                    count += 1;
                    if count < 3 {
                        continue;
                    }
                }
                Err(e).with_context(|| format!("name server {:?} recv error ", name_server))?
            }
        };
    };

    let message = Message::from_vec(&buf[..len])
        .with_context(|| format!("name server {:?} data error ", name_server))?;
    if message.answers().is_empty() {
        Err(anyhow::anyhow!("{:?} no {} record", domain, record_type))?
    }
    Ok(message)
}

pub fn txt_dns(domain: &str, name_server: SocketAddr) -> anyhow::Result<Vec<SocketAddr>> {
    let udp = bind_udp(name_server.is_ipv4())?;
    let message = query(&udp, domain, name_server, RecordType::TXT)?;
    let mut rs = Vec::new();
    for record in message.answers() {
        let txt = record
            .data()
            .context("data none")?
            .as_txt()
            .context("record type txt is none")?;
        let addr = SocketAddr::from_str(&txt.to_string())?;
        rs.push(addr);
    }
    Ok(rs)
}

fn bind_udp(is_ipv4: bool) -> io::Result<UdpSocket> {
    let udp = if is_ipv4 {
        UdpSocket::bind("0.0.0.0:0")?
    } else {
        UdpSocket::bind("[::]:0")?
    };
    udp.set_read_timeout(Some(Duration::from_millis(800)))?;
    Ok(udp)
}

pub fn a_dns(domain: String, name_server: SocketAddr) -> anyhow::Result<Vec<Ipv4Addr>> {
    let udp = bind_udp(name_server.is_ipv4())?;
    let message = query(&udp, &domain, name_server, RecordType::A)?;
    let mut rs = Vec::new();
    for record in message.answers() {
        let a = record
            .data()
            .context("data none")?
            .as_a()
            .context("record type A is none")?;
        rs.push(a.0);
    }
    Ok(rs)
}

pub fn aaaa_dns(domain: String, name_server: SocketAddr) -> anyhow::Result<Vec<Ipv6Addr>> {
    let udp = bind_udp(name_server.is_ipv4())?;
    let message = query(&udp, &domain, name_server, RecordType::AAAA)?;
    let mut rs = Vec::new();
    for record in message.answers() {
        let a = record
            .data()
            .context("data none")?
            .as_aaaa()
            .context("record type AAAA is none")?;
        rs.push(a.0);
    }
    Ok(rs)
}

pub const MAX_PAYLOAD_LEN: u16 = 1232;

fn build_message(query: Query, options: DnsRequestOptions) -> Message {
    // build the message
    let mut message: Message = Message::new();
    message
        .add_query(query)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(options.recursion_desired);
    // Extended dns
    if options.use_edns {
        message
            .extensions_mut()
            .get_or_insert_with(Edns::new)
            .set_max_payload(MAX_PAYLOAD_LEN)
            .set_version(0);
    }
    message
}
