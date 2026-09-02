#![cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]

use crate::nat::NetInput;
use crate::utils::task_control::TaskGroup;
use route_manager::{Route, RouteManager};
use std::time::Duration;

pub(crate) fn start(
    task_group: &TaskGroup,
    mut desired: tokio::sync::watch::Receiver<Vec<NetInput>>,
    if_index: u32,
) {
    task_group.spawn(async move {
        let mut reconciler = match RouteReconciler::new(if_index) {
            Ok(reconciler) => reconciler,
            Err(error) => {
                log::error!("create subnet route manager failed: {error:?}");
                return;
            }
        };
        let mut retry = tokio::time::interval(Duration::from_secs(5));
        loop {
            reconciler.reconcile(desired.borrow_and_update().clone());
            tokio::select! {
                changed = desired.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                _ = retry.tick() => {}
            }
        }
    });
}

trait RouteBackend {
    fn add(&mut self, route: &Route) -> std::io::Result<()>;
    fn delete(&mut self, route: &Route) -> std::io::Result<()>;
}

struct SystemRouteBackend(RouteManager);

impl RouteBackend for SystemRouteBackend {
    fn add(&mut self, route: &Route) -> std::io::Result<()> {
        self.0.add(route)
    }

    fn delete(&mut self, route: &Route) -> std::io::Result<()> {
        self.0.delete(route)
    }
}

struct RouteReconciler<B: RouteBackend> {
    backend: B,
    if_index: u32,
    installed: Vec<NetInput>,
}

impl RouteReconciler<SystemRouteBackend> {
    fn new(if_index: u32) -> std::io::Result<Self> {
        Ok(Self {
            backend: SystemRouteBackend(RouteManager::new()?),
            if_index,
            installed: Vec::new(),
        })
    }
}

impl<B: RouteBackend> RouteReconciler<B> {
    fn route(&self, input: &NetInput) -> Route {
        Route::new(input.net.network().into(), input.net.prefix_len())
            .with_gateway(input.target_ip.into())
            .with_if_index(self.if_index)
    }

    fn reconcile(&mut self, desired: Vec<NetInput>) {
        let stale = self
            .installed
            .iter()
            .filter(|route| !desired.contains(route))
            .cloned()
            .collect::<Vec<_>>();
        for input in stale {
            let route = self.route(&input);
            match self.backend.delete(&route) {
                Ok(()) => {
                    self.installed.retain(|installed| installed != &input);
                    log::info!("delete route [{route}] successful");
                }
                Err(error) => log::warn!("delete route [{route}] error: {error:?}"),
            }
        }

        for input in desired {
            if self.installed.contains(&input) {
                continue;
            }
            let route = self.route(&input);
            match self.backend.add(&route) {
                Ok(()) => {
                    self.installed.push(input);
                    log::info!("add route [{route}] successful");
                }
                Err(error) => log::warn!("add route [{route}] error: {error:?}"),
            }
        }
    }
}

impl<B: RouteBackend> Drop for RouteReconciler<B> {
    fn drop(&mut self) {
        let installed = std::mem::take(&mut self.installed);
        for input in installed {
            let route = self.route(&input);
            if let Err(error) = self.backend.delete(&route) {
                log::warn!("cleanup route [{route}] error: {error:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::Ipv4Net;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct MockBackend {
        events: Arc<Mutex<Vec<String>>>,
        fail_next_add: bool,
    }

    impl RouteBackend for MockBackend {
        fn add(&mut self, route: &Route) -> std::io::Result<()> {
            self.events.lock().unwrap().push(format!("add {route}"));
            if std::mem::take(&mut self.fail_next_add) {
                Err(std::io::Error::other("simulated add failure"))
            } else {
                Ok(())
            }
        }

        fn delete(&mut self, route: &Route) -> std::io::Result<()> {
            self.events.lock().unwrap().push(format!("delete {route}"));
            Ok(())
        }
    }

    fn input(net: &str, target: [u8; 4]) -> NetInput {
        NetInput {
            net: net.parse::<Ipv4Net>().unwrap(),
            target_ip: Ipv4Addr::from(target),
        }
    }

    #[test]
    fn failed_add_is_retried_and_snapshot_replacement_deletes_stale_route() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let backend = MockBackend {
            events: events.clone(),
            fail_next_add: true,
        };
        let mut reconciler = RouteReconciler {
            backend,
            if_index: 7,
            installed: Vec::new(),
        };
        let old = input("192.168.0.0/24", [10, 26, 0, 2]);
        let new = input("172.16.0.0/16", [10, 26, 0, 3]);

        reconciler.reconcile(vec![old.clone()]);
        assert!(reconciler.installed.is_empty());
        reconciler.reconcile(vec![old.clone()]);
        assert_eq!(reconciler.installed, vec![old]);
        reconciler.reconcile(vec![new.clone()]);
        assert_eq!(reconciler.installed, vec![new]);

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 4);
        assert!(events[0].starts_with("add "));
        assert!(events[1].starts_with("add "));
        assert!(events[2].starts_with("delete "));
        assert!(events[3].starts_with("add "));
    }

    #[test]
    fn drop_cleans_installed_routes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        {
            let mut reconciler = RouteReconciler {
                backend: MockBackend {
                    events: events.clone(),
                    fail_next_add: false,
                },
                if_index: 9,
                installed: Vec::new(),
            };
            reconciler.reconcile(vec![input("192.168.1.0/24", [10, 26, 0, 2])]);
        }
        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].starts_with("add "));
        assert!(events[1].starts_with("delete "));
    }
}
