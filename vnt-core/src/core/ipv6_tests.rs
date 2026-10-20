//! Real encrypted transports with in-memory virtual-device channels; no OS adapter required.
use super::*;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use crate::utils::task_control::TaskGroupManager;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::time::Duration;

#[cfg(windows)]
static DEVICE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn ipv6(source: Ipv4Addr, destination: std::net::Ipv6Addr) -> TransmissionBytes {
    let mut data = TransmissionBytes::with_capacity(HEAD_LENGTH + 14, 1600);
    let mut bytes = vec![0u8; 1280];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&1240u16.to_be_bytes());
    bytes[6] = 17;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&crate::virtual_ipv6::address(source).octets());
    bytes[24..40].copy_from_slice(&destination.octets());
    bytes[40..].fill(0xab);
    data.put(&bytes).unwrap();
    data
}

async fn exercise_ipv6_transports(features: bool) {
    let modes = [
        DeviceMode::Tun,
        DeviceMode::Tun,
        DeviceMode::Tap,
        DeviceMode::Tap,
    ];
    let sockets = (0..4)
        .map(|_| {
            loop {
                let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()) {
                    break (udp, tcp);
                }
            }
        })
        .collect::<Vec<_>>();
    let ports = sockets
        .iter()
        .map(|(udp, _)| udp.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    drop(sockets);
    let mut managers = Vec::new();
    let mut guards = Vec::new();
    let mut receivers = Vec::new();
    for (index, mode) in modes.into_iter().enumerate() {
        let config = Config {
            network_code: format!("ipv6-test-{}", ports[0]),
            device_id: format!("ipv6-{index}"),
            device_name: format!("ipv6-{index}"),
            ip: Some(format!("10.26.0.{}/24", index + 2).parse().unwrap()),
            device_mode: mode,
            password: features.then(|| "ipv6-test-password".to_string()),
            compress: features,
            fec: features,
            no_punch: true,
            no_broadcast: true,
            tunnel_addr: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, ports[index]))],
            peer_address: ports
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != index)
                .map(|(_, port)| format!("tcp://127.0.0.1:{port}").parse().unwrap())
                .collect(),
            ..Config::default()
        };
        let owner = TaskGroupManager::new();
        let (group, guard) = owner.create_task().unwrap();
        let (routes, routes_rx) = tokio::sync::watch::channel(vec![]);
        let mut manager = NetworkManager::create_network(
            Box::new(config),
            group,
            Arc::new(InstanceLog::new("ipv6-test")),
            routes,
        )
        .await
        .unwrap();
        manager.current_network().await.unwrap();
        receivers.push(manager.tun_receiver.take().unwrap().receiver);
        managers.push(manager);
        guards.push((owner, guard, routes_rx));
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if managers.iter().enumerate().all(|(i, manager)| {
                (0..4).filter(|j| *j != i).all(|j| {
                    manager
                        .vnt_api()
                        .find_route(&Ipv4Addr::new(10, 26, 0, j as u8 + 2))
                        .is_some()
                })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("loopback direct routes");

    // Force both raw IPv6 and Ethernet traffic through a third node, while
    // other pairs continue to exercise their direct routes.
    for (source, rule) in [(0, "10.26.0.5,10.26.0.3"), (3, "10.26.0.2,10.26.0.3")] {
        let mut policy = (**managers[source].runtime_policy.load()).clone();
        policy.turn = Arc::new(vec![rule.parse().unwrap()]);
        managers[source].runtime_policy.store(policy);
    }

    // TAP learns each TUN's MAC from an actual NS/NA exchange, as an OS would.
    // The other TAP also sees the flooded NS and learns the requesting TAP's MAC.
    for source in [2, 3] {
        for dest in [0, 1] {
            let source_net = managers[source].current_network().await.unwrap();
            let dest_net = managers[dest].current_network().await.unwrap();
            let mut ns = crate::ethernet::tests::ipv6_ns(dest_net.ip, false, false);
            ns[6..12].copy_from_slice(&crate::ethernet::mac_from_ip(source_net.ip).octets());
            let mut frame = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + ns.len());
            frame.put(&ns).unwrap();
            managers[source]
                .enhanced_outbound
                .as_ref()
                .unwrap()
                .ethernet_outbound(frame)
                .await;
            let reply = tokio::time::timeout(Duration::from_secs(3), receivers[source].recv())
                .await
                .unwrap()
                .unwrap();
            let info = crate::ethernet::parse_frame(&reply).unwrap();
            assert_eq!(info.source, crate::ethernet::mac_from_ip(dest_net.ip));
            assert_eq!(reply[info.payload_offset + 40], 136);
            let other = if source == 2 { 3 } else { 2 };
            let request = tokio::time::timeout(Duration::from_secs(3), receivers[other].recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(request.as_ref(), ns);
        }
    }

    for source in 0..4 {
        for dest in 0..4 {
            if source == dest {
                continue;
            }
            let net = managers[source].current_network().await.unwrap();
            let packet = ipv6(
                net.ip,
                crate::virtual_ipv6::address(Ipv4Addr::new(10, 26, 0, dest as u8 + 2)),
            );
            let expected = packet.as_ref().to_vec();
            let outbound = managers[source].enhanced_outbound.as_ref().unwrap();
            if modes[source] == DeviceMode::Tap {
                let target_net = managers[dest].current_network().await.unwrap();
                outbound
                    .ethernet_outbound(
                        crate::ethernet::wrap_ipv6(packet, net.ip, &target_net).unwrap(),
                    )
                    .await;
            } else {
                outbound.ip_outbound(packet).await;
            }
            let received = tokio::time::timeout(Duration::from_secs(3), receivers[dest].recv())
                .await
                .unwrap()
                .unwrap();
            let received = if modes[dest] == DeviceMode::Tap {
                crate::ethernet::strip_ip(received).unwrap()
            } else {
                received
            };
            assert_eq!(
                received.as_ref(),
                expected,
                "{source}->{dest}, features={features}"
            );
        }
    }

    // Arbitrary IPv6 addresses remain transparent between TAP endpoints.
    let source_net = managers[2].current_network().await.unwrap();
    let dest_net = managers[3].current_network().await.unwrap();
    let arbitrary = ipv6(source_net.ip, "2001:db8::1234".parse().unwrap());
    let expected = arbitrary.as_ref().to_vec();
    managers[2]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ethernet_outbound(crate::ethernet::wrap_ipv6(arbitrary, source_net.ip, &dest_net).unwrap())
        .await;
    let received = tokio::time::timeout(Duration::from_secs(3), receivers[3].recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        crate::ethernet::strip_ip(received).unwrap().as_ref(),
        expected
    );

    // A TAP can host any IPv6, including a derived-looking address whose suffix
    // names a different node. The destination MAC, not that suffix, owns the frame.
    let misleading = ipv6(
        source_net.ip,
        crate::virtual_ipv6::address(Ipv4Addr::new(10, 26, 0, 2)),
    );
    let expected = misleading.as_ref().to_vec();
    managers[2]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ethernet_outbound(
            crate::ethernet::wrap_ipv6(misleading, source_net.ip, &dest_net).unwrap(),
        )
        .await;
    let received = tokio::time::timeout(Duration::from_secs(3), receivers[3].recv())
        .await
        .expect("TAP destination MAC must override the IPv6 suffix")
        .unwrap();
    assert_eq!(
        crate::ethernet::strip_ip(received).unwrap().as_ref(),
        expected
    );
    assert!(
        receivers[0].try_recv().is_err(),
        "IPv6 suffix must not redirect a TAP frame to a TUN node"
    );

    // Unknown unicast is flooded. A TUN must still apply the destination MAC
    // filter rather than consume a frame addressed to some other L2 device.
    let unknown = ipv6(
        source_net.ip,
        crate::virtual_ipv6::address(Ipv4Addr::new(10, 26, 0, 2)),
    );
    let mut frame = crate::ethernet::wrap_ipv6(unknown, source_net.ip, &dest_net).unwrap();
    frame[..6].copy_from_slice(&[2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let expected = frame.as_ref().to_vec();
    managers[2]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ethernet_outbound(frame)
        .await;
    let flooded = tokio::time::timeout(Duration::from_secs(3), receivers[3].recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(flooded.as_ref(), expected);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receivers[0].recv())
            .await
            .is_err()
    );

    let ns = crate::ethernet::tests::ipv6_ns(Ipv4Addr::new(10, 26, 0, 2), false, true);
    let mut frame = TransmissionBytes::with_capacity(HEAD_LENGTH, HEAD_LENGTH + ns.len());
    frame.put(&ns).unwrap();
    managers[2]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ethernet_outbound(frame)
        .await;
    let reply = tokio::time::timeout(Duration::from_secs(3), receivers[2].recv())
        .await
        .unwrap()
        .unwrap();
    let info = crate::ethernet::parse_frame(&reply).unwrap();
    assert_eq!(info.payload_offset, 18);
    assert_eq!(reply[info.payload_offset + 40], 136);
    assert!(receivers[0].try_recv().is_err());
    // Other TAPs also receive the flooded solicitation; clear it before the data multicast checks.
    let _ = tokio::time::timeout(Duration::from_secs(3), receivers[3].recv())
        .await
        .unwrap();

    let net = managers[0].current_network().await.unwrap();
    let multicast = "ff02::1234".parse().unwrap();
    managers[0]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ip_outbound(ipv6(net.ip, multicast))
        .await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), receivers[1].recv())
            .await
            .is_err()
    );
    let mut policy = (**managers[0].runtime_policy.load()).clone();
    policy.no_broadcast = false;
    managers[0].runtime_policy.store(policy);
    managers[0]
        .enhanced_outbound
        .as_ref()
        .unwrap()
        .ip_outbound(ipv6(net.ip, multicast))
        .await;
    for dest in 1..4 {
        let received = tokio::time::timeout(Duration::from_secs(3), receivers[dest].recv())
            .await
            .unwrap()
            .unwrap();
        let received = if modes[dest] == DeviceMode::Tap {
            crate::ethernet::strip_ip(received).unwrap()
        } else {
            received
        };
        assert_eq!(
            crate::virtual_ipv6::packet(&received)
                .unwrap()
                .get_destination(),
            multicast
        );
    }
    for manager in managers {
        manager.stop().await;
    }
    drop(guards);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_tun_tap_plain_transports() {
    exercise_ipv6_transports(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipv6_tun_tap_encrypted_compressed_fec_transports() {
    exercise_ipv6_transports(true).await;
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Creates a temporary Wintun adapter; requires administrator and wintun.dll"]
async fn ipv6_windows_device_lifecycle() {
    let _device_test = DEVICE_TEST_LOCK.lock().await;
    let owner = TaskGroupManager::new();
    let (group, _guard) = owner.create_task().unwrap();
    let (routes, _routes_rx) = tokio::sync::watch::channel(vec![]);
    let config = Config {
        network_code: "ipv6-device-test".into(),
        device_id: "ipv6-device-test".into(),
        ip: Some("10.251.254.2/24".parse().unwrap()),
        device_mode: DeviceMode::Tun,
        tun_name: Some(format!("vnt-ipv6-test-{}", std::process::id())),
        no_punch: true,
        tunnel_addr: vec!["127.0.0.1:0".parse().unwrap()],
        ..Config::default()
    };
    let mut manager = NetworkManager::create_network(
        Box::new(config),
        group,
        Arc::new(InstanceLog::new("ipv6-device-test")),
        routes,
    )
    .await
    .unwrap();
    manager.start_device().await.unwrap();
    let index = manager.device_io_manager.device_if_index().await.unwrap();
    let addresses = || {
        getifaddrs::getifaddrs()
            .unwrap()
            .filter(|i| i.index == Some(index))
            .filter_map(|i| i.address.ip_addr())
            .collect::<Vec<_>>()
    };
    let old = Ipv4Addr::new(10, 251, 254, 2);
    let new = Ipv4Addr::new(10, 251, 254, 3);
    assert!(addresses().contains(&crate::virtual_ipv6::address(old).into()));
    manager
        .device_io_manager
        .set_network(old, 24)
        .await
        .unwrap();
    manager
        .device_io_manager
        .set_network(new, 24)
        .await
        .unwrap();
    assert!(addresses().contains(&crate::virtual_ipv6::address(new).into()));
    assert!(!addresses().contains(&crate::virtual_ipv6::address(old).into()));
    let configured = route_manager::RouteManager::new().unwrap().list().unwrap();
    assert!(
        configured
            .iter()
            .any(|route| route.destination() == crate::virtual_ipv6::PREFIX
                && route.prefix() == 96
                && route.if_index() == Some(index))
    );
    manager.stop().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while getifaddrs::getifaddrs()
            .unwrap()
            .any(|i| i.index == Some(index))
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("temporary adapter removed");
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Creates a temporary Wintun adapter and runs ping.exe; requires administrator and wintun.dll"]
async fn ipv6_windows_kernel_ping_and_udp() {
    let _device_test = DEVICE_TEST_LOCK.lock().await;
    use pnet_packet::{
        Packet,
        icmpv6::{Icmpv6Packet, checksum},
        udp::UdpPacket,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut managers = Vec::new();
    let mut guards = Vec::new();
    for i in 0..2 {
        let owner = TaskGroupManager::new();
        let (group, guard) = owner.create_task().unwrap();
        let (routes, routes_rx) = tokio::sync::watch::channel(vec![]);
        let config = Config {
            network_code: format!("ipv6-kernel-{port}"),
            device_id: format!("ipv6-kernel-{i}"),
            ip: Some(format!("10.251.253.{}/24", i + 2).parse().unwrap()),
            device_mode: DeviceMode::Tun,
            tun_name: Some(format!("vnt-ipv6-kernel-{}", std::process::id())),
            no_punch: true,
            password: Some("ipv6-kernel-password".into()),
            compress: true,
            fec: true,
            tunnel_addr: vec![SocketAddr::from((
                Ipv4Addr::LOCALHOST,
                if i == 0 { port } else { 0 },
            ))],
            peer_address: if i == 1 {
                vec![format!("tcp://127.0.0.1:{port}").parse().unwrap()]
            } else {
                vec![]
            },
            ..Config::default()
        };
        let manager = NetworkManager::create_network(
            Box::new(config),
            group,
            Arc::new(InstanceLog::new("ipv6-kernel")),
            routes,
        )
        .await
        .unwrap();
        manager.current_network().await.unwrap();
        managers.push(manager);
        guards.push((owner, guard, routes_rx));
    }
    let local = crate::virtual_ipv6::address(Ipv4Addr::new(10, 251, 253, 2));
    let peer = crate::virtual_ipv6::address(Ipv4Addr::new(10, 251, 253, 3));
    tokio::time::timeout(Duration::from_secs(15), async {
        while managers[0]
            .vnt_api()
            .find_route(&Ipv4Addr::new(10, 251, 253, 3))
            .is_none()
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    let mut receiver = managers[1].tun_receiver.take().unwrap().receiver;
    let outbound = managers[1].enhanced_outbound.as_ref().unwrap().clone();
    // The peer deliberately has no OS interface. Echo at its in-memory device boundary.
    let echo = tokio::spawn(async move {
        while let Some(mut data) = receiver.recv().await {
            let Some(ip) = crate::virtual_ipv6::packet(&data) else {
                continue;
            };
            if ip.get_destination() != peer {
                continue;
            }
            let protocol = ip.get_next_header().0;
            let length = 40 + usize::from(ip.get_payload_length());
            if protocol == 58 && data.get(40) == Some(&128) {
                data[40] = 129;
                data[42..44].fill(0);
                let sum = checksum(
                    &Icmpv6Packet::new(&data[40..length]).unwrap(),
                    &peer,
                    &local,
                );
                data[42..44].copy_from_slice(&sum.to_be_bytes());
            } else if protocol == 17 && length >= 48 {
                let source = [data[40], data[41]];
                let dest = [data[42], data[43]];
                data[40..42].copy_from_slice(&dest);
                data[42..44].copy_from_slice(&source);
                data[46..48].fill(0);
                let udp = UdpPacket::new(&data[40..length]).unwrap();
                assert_eq!(udp.packet().len(), length - 40);
                let sum = pnet_packet::udp::ipv6_checksum(&udp, &peer, &local);
                data[46..48].copy_from_slice(&sum.to_be_bytes());
            } else {
                continue;
            }
            data[8..24].copy_from_slice(&peer.octets());
            data[24..40].copy_from_slice(&local.octets());
            outbound.ip_outbound(data).await;
        }
    });
    managers[0].start_device().await.unwrap();
    // Allow Windows DAD to finish before binding to the newly added address.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let result = tokio::process::Command::new("ping.exe")
        .args([
            "-6",
            "-n",
            "1",
            "-w",
            "3000",
            "-l",
            "1200",
            &peer.to_string(),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let socket = tokio::net::UdpSocket::bind((local, 0)).await.unwrap();
    socket
        .send_to(b"virtual-ipv6-udp", (peer, 23456))
        .await
        .unwrap();
    let mut bytes = [0u8; 64];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(&bytes[..length], b"virtual-ipv6-udp");
    assert_eq!(source.ip(), peer);
    drop(socket);
    echo.abort();
    let _ = echo.await;
    for manager in managers {
        manager.stop().await;
    }
    drop(guards);
}
