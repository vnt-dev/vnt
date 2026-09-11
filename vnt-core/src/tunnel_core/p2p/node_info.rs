use ipnet::Ipv4Net;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeInfo {
    pub ip: Ipv4Addr,
    pub name: String,
    pub version: String,
    pub advertised_subnets: Vec<Ipv4Net>,
}

#[derive(Clone, Default)]
pub(crate) struct NodeInfoMap {
    inner: Arc<RwLock<HashMap<Ipv4Addr, NodeInfo>>>,
}

impl NodeInfoMap {
    /// Inserts the latest identity for one virtual IP and reports whether the
    /// effective identity changed.
    pub fn upsert(&self, node: NodeInfo) -> bool {
        let mut guard = self.inner.write();
        if guard.get(&node.ip) == Some(&node) {
            return false;
        }
        guard.insert(node.ip, node);
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get(&self, ip: &Ipv4Addr) -> Option<NodeInfo> {
        self.inner.read().get(ip).cloned()
    }

    pub fn list(&self) -> Vec<NodeInfo> {
        self.inner.read().values().cloned().collect()
    }

    pub fn remove(&self, ip: &Ipv4Addr) -> Option<NodeInfo> {
        self.inner.write().remove(ip)
    }

    pub fn clear(&self) {
        self.inner.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeInfo {
        NodeInfo {
            ip: Ipv4Addr::new(10, 26, 0, 2),
            name: name.to_string(),
            version: "2".to_string(),
            advertised_subnets: Vec::new(),
        }
    }

    #[test]
    fn latest_node_identity_replaces_the_previous_value() {
        let nodes = NodeInfoMap::default();
        assert!(nodes.upsert(node("before")));
        assert!(!nodes.upsert(node("before")));
        assert!(nodes.upsert(node("after")));
        assert_eq!(nodes.get(&Ipv4Addr::new(10, 26, 0, 2)), Some(node("after")));
    }

    #[test]
    fn remove_and_clear_release_node_identities() {
        let nodes = NodeInfoMap::default();
        let info = node("peer");
        nodes.upsert(info.clone());
        assert_eq!(nodes.remove(&info.ip), Some(info.clone()));
        assert!(nodes.get(&info.ip).is_none());

        nodes.upsert(info.clone());
        nodes.clear();
        assert!(nodes.list().is_empty());
    }
}
