use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use rustp2p_core::route_table::{Protocol, RouteKey};
use std::net::{Ipv4Addr, SocketAddr};
use vnt_core::internal_bench::{Route, RouteTable};

fn peer_ip(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, 1 + (index / 254) as u8, 0, 1 + (index % 254) as u8)
}

fn route_key(index: usize) -> RouteKey {
    RouteKey::new(
        Protocol::UDP,
        SocketAddr::from(([127, 0, 0, 1], 10_000 + index as u16)),
        SocketAddr::from(([127, 0, 0, 1], 20_000 + index as u16)),
    )
}

fn direct_table(count: usize) -> (RouteTable, Vec<(Ipv4Addr, RouteKey)>) {
    let table = RouteTable::new();
    let peers = (0..count)
        .map(|index| (peer_ip(index), route_key(index)))
        .collect::<Vec<_>>();
    for (peer, key) in &peers {
        table.add_owner_route(*peer, *key);
    }
    (table, peers)
}

fn route_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("route_lookup");
    group.throughput(Throughput::Elements(1));

    for count in [1usize, 64, 512] {
        let (known_table, peers) = direct_table(count);
        let known = peers[count - 1].0;
        group.bench_with_input(BenchmarkId::new("known", count), &count, |b, _| {
            b.iter(|| known_table.get_route_by_id(black_box(&known)))
        });

        let missing = Ipv4Addr::new(172, 31, 255, 254);
        group.bench_with_input(BenchmarkId::new("candidate", count), &count, |b, _| {
            b.iter(|| known_table.direct_candidate(black_box(missing), None))
        });

        let (relay_table, relay_peers) = direct_table(count);
        let target = Ipv4Addr::new(172, 31, 0, 1);
        for (_, key) in relay_peers.iter().take(5) {
            relay_table.add_gossip_relay_route(target, Route::from_default_rt(*key, 2));
        }
        let ingress = relay_peers[0].1;
        group.bench_with_input(BenchmarkId::new("exclude", count), &count, |b, _| {
            b.iter(|| relay_table.get_route_by_id_excluding(black_box(&target), Some(&ingress)))
        });

        let (suppressed_table, suppressed_peers) = direct_table(count.max(2));
        for (_, key) in suppressed_peers.iter().take(5) {
            suppressed_table.add_gossip_relay_route(target, Route::from_default_rt(*key, 2));
        }
        suppressed_table.suppress_path(target, suppressed_peers[0].0);
        group.bench_with_input(BenchmarkId::new("suppressed", count), &count, |b, _| {
            b.iter(|| suppressed_table.get_route_by_id(black_box(&target)))
        });
    }
    group.finish();
}

criterion_group!(benches, route_lookup);
criterion_main!(benches);
