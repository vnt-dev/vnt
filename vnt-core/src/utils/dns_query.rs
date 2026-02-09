use anyhow::{Context, anyhow};
use dns_parser::{Builder, Packet, QueryClass, QueryType, RData, ResponseCode};
use rand::seq::SliceRandom;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use tokio::net::UdpSocket;

use rust_p2p_core::socket::LocalInterface;

pub async fn dns_query_txt(
    domain: &str,
    mut name_servers: Vec<String>,
    default_interface: &Option<LocalInterface>,
) -> io::Result<Vec<String>> {
    let mut err: Option<io::Error> = None;
    if name_servers.is_empty() {
        name_servers.push("223.5.5.5:53".into());
        name_servers.push("114.114.114.114:53".into());
    }
    for name_server in name_servers {
        match txt_dns(domain, name_server, default_interface).await {
            Ok(addr) => {
                if !addr.is_empty() {
                    return Ok(addr);
                }
            }
            Err(e) => {
                err.replace(e);
            }
        }
        continue;
    }
    if let Some(e) = err {
        Err(e)
    } else {
        Err(io::Error::other(format!("DNS query failed {domain:?}")))
    }
}
pub async fn dns_query_one(
    domain: &str,
    name_servers: &Vec<String>,
    default_interface: &Option<LocalInterface>,
) -> anyhow::Result<SocketAddr> {
    let mut vec = dns_query_all(domain, name_servers, default_interface).await?;
    vec.shuffle(&mut rand::rng());
    vec.pop().context("DNS query failed")
}
pub async fn dns_query_all(
    domain: &str,
    name_servers: &Vec<String>,
    default_interface: &Option<LocalInterface>,
) -> anyhow::Result<Vec<SocketAddr>> {
    match SocketAddr::from_str(domain) {
        Ok(addr) => Ok(vec![addr]),
        Err(_) => {
            if name_servers.is_empty() {
                let addrs: Vec<SocketAddr> = tokio::net::lookup_host(domain)
                    .await
                    .map_err(|e| io::Error::other(format!("DNS query failed: {domain:?},{e:?}")))?
                    .collect();
                return Ok(addrs);
            }

            let mut err: Option<io::Error> = None;
            for name_server in name_servers {
                let end_index = domain
                    .rfind(':')
                    .ok_or_else(|| io::Error::other(format!("not port: {domain:?}")))?;
                let host = &domain[..end_index];
                let port = u16::from_str(&domain[end_index + 1..])
                    .map_err(|_| io::Error::other(format!("not port: {domain:?}")))?;
                let th1 = {
                    let host = host.to_string();
                    let name_server = name_server.clone();
                    let default_interface = default_interface.clone();
                    tokio::spawn(a_dns(host, name_server, default_interface.clone()))
                };
                let th2 = {
                    let host = host.to_string();
                    let name_server = name_server.clone();
                    let default_interface = default_interface.clone();
                    tokio::spawn(aaaa_dns(host, name_server, default_interface.clone()))
                };
                let mut addr = Vec::new();
                match th1.await? {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        err.replace(e);
                    }
                }
                match th2.await? {
                    Ok(rs) => {
                        for ip in rs {
                            addr.push(SocketAddr::new(ip.into(), port));
                        }
                    }
                    Err(e) => {
                        if addr.is_empty() {
                            err.replace(e);
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
                Err(e.into())
            } else {
                Err(anyhow!("DNS query failed {domain:?}"))
            }
        }
    }
}

async fn query<'a>(
    udp: &UdpSocket,
    domain: &str,
    name_server: SocketAddr,
    record_type: QueryType,
    buf: &'a mut [u8],
) -> io::Result<Packet<'a>> {
    let mut builder = Builder::new_query(1, true);
    builder.add_question(domain, false, record_type, QueryClass::IN);
    let packet = builder.build().unwrap();

    udp.connect(name_server).await?;
    let mut count = 0;
    let len = loop {
        udp.send(&packet).await?;

        match tokio::time::timeout(Duration::from_secs(3), udp.recv(buf)).await {
            Ok(len) => {
                break len?;
            }
            Err(_) => {
                count += 1;
                if count < 3 {
                    continue;
                }
                Err(io::Error::other(format!("DNS {name_server:?} recv error ")))?
            }
        };
    };

    let pkt = Packet::parse(&buf[..len]).map_err(|e| {
        io::Error::other(format!(
            "domain {domain:?} DNS {name_server:?} data error: {e}"
        ))
    })?;
    if pkt.header.response_code != ResponseCode::NoError {
        return Err(io::Error::other(format!(
            "response_code {} DNS {:?} domain {:?}",
            pkt.header.response_code, name_server, domain
        )));
    }
    if pkt.answers.is_empty() {
        return Err(io::Error::other(format!(
            "No records received DNS {name_server:?} domain {domain:?}"
        )));
    }

    Ok(pkt)
}

pub async fn txt_dns(
    domain: &str,
    name_server: String,
    default_interface: &Option<LocalInterface>,
) -> io::Result<Vec<String>> {
    let name_server: SocketAddr = name_server
        .parse()
        .map_err(|e| io::Error::other(format!("dns {name_server} is error :{e:?}")))?;
    let udp = bind_udp(name_server, default_interface)?;
    let mut buf = vec![0u8; 65536];
    let message = query(&udp, domain, name_server, QueryType::TXT, &mut buf).await?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::TXT(txt) = record.data {
            for x in txt.iter() {
                let txt = std::str::from_utf8(x)
                    .map_err(|_| io::Error::other("record type txt is not string"))?;
                rs.push(txt.to_string());
            }
        }
    }
    Ok(rs)
}

fn bind_udp(
    name_server: SocketAddr,
    default_interface: &Option<LocalInterface>,
) -> io::Result<UdpSocket> {
    let addr: SocketAddr = if name_server.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .expect("valid IPv4 socket address literal")
    } else {
        "[::]:0".parse().expect("valid IPv6 socket address literal")
    };
    let socket = rust_p2p_core::socket::bind_udp(addr, default_interface.as_ref())?;
    UdpSocket::from_std(socket.into())
}

pub async fn a_dns(
    domain: String,
    name_server: String,
    default_interface: Option<LocalInterface>,
) -> io::Result<Vec<Ipv4Addr>> {
    let name_server: SocketAddr = name_server
        .parse()
        .map_err(|e| io::Error::other(format!("dns {name_server} is error :{e:?}")))?;
    let udp = bind_udp(name_server, &default_interface)?;
    let mut buf = vec![0u8; 65536];
    let message = query(&udp, &domain, name_server, QueryType::A, &mut buf).await?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::A(a) = record.data {
            rs.push(a.0);
        }
    }
    Ok(rs)
}

pub async fn aaaa_dns(
    domain: String,
    name_server: String,
    default_interface: Option<LocalInterface>,
) -> io::Result<Vec<Ipv6Addr>> {
    let name_server: SocketAddr = name_server
        .parse()
        .map_err(|e| io::Error::other(format!("dns {name_server} is error :{e:?}")))?;
    let udp = bind_udp(name_server, &default_interface)?;
    let mut buf = vec![0u8; 65536];
    let message = query(&udp, &domain, name_server, QueryType::AAAA, &mut buf).await?;
    let mut rs = Vec::new();
    for record in message.answers {
        if let RData::AAAA(a) = record.data {
            rs.push(a.0);
        }
    }
    Ok(rs)
}
