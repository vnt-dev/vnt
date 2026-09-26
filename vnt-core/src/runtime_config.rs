use crate::compression::PacketCompression;
use crate::context::config::{Config, PeerAddress, PunchRule, TurnRule};
use crate::fec::FecEncoder;
use crate::nat::{AllowSubnetExternalRoute, SubnetMappingTable};
use arc_swap::ArcSwap;
use std::sync::Arc;

/// Immutable packet-processing policy. Each packet handler loads this once so
/// one packet cannot observe fields from two configuration revisions.
#[derive(Clone)]
pub(crate) struct RuntimePolicy {
    pub turn: Arc<Vec<TurnRule>>,
    pub punch_model: Arc<Vec<PunchRule>>,
    pub peer_address: Arc<Vec<PeerAddress>>,
    pub packet_compression: PacketCompression,
    pub subnet_mapping: SubnetMappingTable,
    pub relay_subnets: AllowSubnetExternalRoute,
    pub fec_encoder: Option<FecEncoder>,
    pub auto_sync_subnet: bool,
    pub no_broadcast: bool,
    pub allow_ikev2: bool,
    pub allow_wireguard: bool,
    pub allow_mapping: bool,
    pub no_punch: bool,
    pub no_nat: bool,
    pub rtx: bool,
    pub udp_stun: Arc<Vec<String>>,
    pub tcp_stun: Arc<Vec<String>>,
}

impl RuntimePolicy {
    pub fn from_config_with_handles(
        config: &Config,
        fec_encoder: Option<FecEncoder>,
        subnet_mapping: SubnetMappingTable,
        _allow_subnet: AllowSubnetExternalRoute,
        relay_subnets: AllowSubnetExternalRoute,
    ) -> Self {
        Self {
            turn: Arc::new(config.turn.clone()),
            punch_model: Arc::new(config.punch_model.clone()),
            peer_address: Arc::new(config.peer_address.clone()),
            packet_compression: PacketCompression::new(config.compress),
            subnet_mapping,
            relay_subnets,
            fec_encoder,
            auto_sync_subnet: config.auto_sync_subnet,
            no_broadcast: config.no_broadcast,
            allow_ikev2: config.allow_ikev2,
            allow_wireguard: config.allow_wireguard,
            allow_mapping: config.allow_port_mapping,
            no_punch: config.no_punch,
            no_nat: config.no_nat,
            rtx: config.rtx,
            udp_stun: Arc::new(config.udp_stun.clone()),
            tcp_stun: Arc::new(config.tcp_stun.clone()),
        }
    }
}

#[derive(Clone)]
pub(crate) struct RuntimePolicyStore {
    policy: Arc<ArcSwap<RuntimePolicy>>,
    peer_revision: Arc<tokio::sync::watch::Sender<u64>>,
    stun_revision: Arc<tokio::sync::watch::Sender<u64>>,
    punch_revision: Arc<tokio::sync::watch::Sender<u64>>,
}

impl RuntimePolicyStore {
    pub fn new(policy: RuntimePolicy) -> Self {
        let (peer_revision, _) = tokio::sync::watch::channel(0);
        let (stun_revision, _) = tokio::sync::watch::channel(0);
        let (punch_revision, _) = tokio::sync::watch::channel(0);
        Self {
            policy: Arc::new(ArcSwap::from_pointee(policy)),
            peer_revision: Arc::new(peer_revision),
            stun_revision: Arc::new(stun_revision),
            punch_revision: Arc::new(punch_revision),
        }
    }

    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<RuntimePolicy>> {
        self.policy.load()
    }

    pub fn store(&self, policy: RuntimePolicy) {
        let current = self.policy.load();
        let peer_changed = current.peer_address != policy.peer_address;
        let stun_changed =
            current.udp_stun != policy.udp_stun || current.tcp_stun != policy.tcp_stun;
        let punch_changed = current.no_punch != policy.no_punch;
        drop(current);
        self.policy.store(Arc::new(policy));
        if peer_changed {
            self.peer_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
        if stun_changed {
            self.stun_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
        if punch_changed {
            self.punch_revision
                .send_modify(|revision| *revision = revision.wrapping_add(1));
        }
    }

    pub fn subscribe_peer(&self) -> tokio::sync::watch::Receiver<u64> {
        self.peer_revision.subscribe()
    }

    pub fn subscribe_stun(&self) -> tokio::sync::watch::Receiver<u64> {
        self.stun_revision.subscribe()
    }

    pub fn subscribe_punch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.punch_revision.subscribe()
    }
}
