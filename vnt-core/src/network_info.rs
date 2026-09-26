use crate::api::VntApi;
use crate::context::NetworkAddr;
use crate::context::config::{Config, DeviceMode};
use crate::core::NetworkManager;
use crate::log_manager::InstanceLog;
use crate::managed_config::{Subscription, SubscriptionListener};
use crate::nat::NetInput;
use crate::utils::task_control::{TaskGroupGuard, TaskGroupManager};
use anyhow::Context;
use std::sync::Arc;
use tokio::sync::watch;

/// The latest complete runtime snapshot exposed to callers.
///
/// `config` is the complete effective configuration (subscription-managed
/// identity and server-managed fields layered on the local settings).
/// `routes` is the complete effective inbound route set. It is not a delta
/// and not limited to one route source.
#[derive(Clone, Debug)]
pub struct RuntimeChange {
    pub config: Config,
    pub routes: Vec<NetInput>,
}

/// 以订阅信封 `base` 中**实际出现**的字段覆盖 `local`，得到完整有效配置。
///
/// 身份字段（network_code/device_id/device_name）与受管 IP 始终以信封为准
/// （它们由订阅链路决定）；流量服务器列表非空时以信封为准（管理端可热切换
/// 中继）；其余字段按 `present` 逐键覆盖——服务端设置了某个字段，该字段就
/// 由服务端说话，信封没提的字段保持客户端本地配置。这样管理端下发的策略类
/// 配置（compress/turn/punch_model/stun…）与重建类配置（密码/出口网卡/
/// 设备模式/映射表…）都能真正到达客户端。
pub fn merge_present_config(
    mut local: Config,
    base: &Config,
    present: &std::collections::HashSet<String>,
) -> Config {
    local.network_code = base.network_code.clone();
    local.device_id = base.device_id.clone();
    local.device_name = base.device_name.clone();
    local.ip = base.ip;
    if !base.server_addr.is_empty() {
        local.server_addr = base.server_addr.clone();
    }
    macro_rules! overlay {
        ($key:literal, $field:ident) => {
            if present.contains($key) {
                local.$field = base.$field.clone();
            }
        };
    }
    // 网卡类（桌面热应用 / 移动重建）
    overlay!("mtu", mtu);
    overlay!("tun_name", tun_name);
    // 策略类（apply_policy_change 热应用）
    overlay!("peer_address", peer_address);
    overlay!("turn", turn);
    overlay!("punch_model", punch_model);
    overlay!("compress", compress);
    overlay!("rtx", rtx);
    overlay!("fec", fec);
    overlay!("no_punch", no_punch);
    overlay!("no_nat", no_nat);
    overlay!("no_broadcast", no_broadcast);
    overlay!("auto_sync_subnet", auto_sync_subnet);
    overlay!("allow_port_mapping", allow_port_mapping);
    overlay!("allow_ikev2", allow_ikev2);
    overlay!("allow_wireguard", allow_wireguard);
    overlay!("udp_stun", udp_stun);
    overlay!("tcp_stun", tcp_stun);
    // 网络类（虚拟地址之外的入站路由配置）
    overlay!("input", input);
    // 重建类（触发实例重建后生效）
    overlay!("password", password);
    overlay!("cert_mode", cert_mode);
    overlay!("outbound_interface", outbound_interface);
    overlay!("tunnel_addr", tunnel_addr);
    overlay!("tunnel_port", tunnel_port);
    overlay!("device_mode", device_mode);
    overlay!("port_mapping", port_mapping);
    overlay!("subnet_mapping", subnet_mapping);
    overlay!("output", output);
    local
}

/// 一次运行期变化应用的结果。
#[derive(Clone, Debug)]
pub enum ChangeOutcome {
    /// 已应用（或无需应用）
    Applied,
    /// 快照包含只能重建组网实例生效的字段，且未获得重建所需的 TUN fd；
    /// 宿主应用新建 VPN 接口后携带 fd 再次调用同一快照
    Rebuild,
    /// 快照包含网卡相关变更但未携带新的 TUN fd（移动平台）
    NeedFd(String),
}

/// 一次运行期事件。
#[derive(Clone, Debug)]
pub enum RuntimeEvent {
    /// 组网实例已停止（重建换代或自行退出）
    InstanceStopped,
    /// 收到新的完整快照
    Changed(Box<RuntimeChange>),
}

/// 一次快照相对当前组网实例需要的处理方式，
/// [`RuntimeChangeManager::inspect_change`] 的返回。
///
/// 移动平台宿主凭本结构决定是否重建 VPN 接口：桌面平台的同类变更由
/// apply 内部热应用，无需宿主参与。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChangePlan {
    /// 网卡相关信息变化（虚拟 IP/网段/MTU/路由/网卡名），宿主必须重建
    /// VPN 接口并携带新的 TUN fd 应用。无设备模式或桌面平台恒为 false。
    pub vpn_rebuild: bool,
    /// 快照包含只能重建组网实例生效的字段（密码/出口网卡等）。宿主无需
    /// 额外操作：组网实例由 native 内部重建，订阅连接保持不断；有设备时
    /// 随 `vpn_rebuild` 一并提供新的 TUN fd。
    pub instance_rebuild: bool,
}

/// 运行期配置管理器。
///
/// 订阅/本地配置的唯一来源，`NetworkManager` 的创建者与生命周期管理者。
/// 前端只持有本结构：创建即启动首个组网实例；运行期事件经
/// [`RuntimeChangeManager::next_event`] 获取，经
/// [`RuntimeChangeManager::apply_change`] 应用；不可增量应用的变更由
/// [`RuntimeChangeManager::rebuild`] 重建组网实例——重建过程中订阅
/// 连接与路由通道保持不断。
pub struct RuntimeChangeManager {
    local_config: Config,
    subscription_listener: Option<SubscriptionListener>,
    routes_tx: watch::Sender<Vec<NetInput>>,
    routes_rx: watch::Receiver<Vec<NetInput>>,
    groups: TaskGroupManager,
    log: Arc<InstanceLog>,
    instance: Option<ManagedInstance>,
}

struct ManagedInstance {
    manager: NetworkManager,
    /// drop 时停止整个实例任务组，必须随实例一起持有
    _guard: TaskGroupGuard,
}

impl RuntimeChangeManager {
    /// 创建管理器并启动首个组网实例。订阅模式会等待服务端首份配置；
    /// 虚拟网卡不在此启动（桌面平台随后调用 `start_device`，移动平台由
    /// 宿主持有 TUN fd 后调用 `start_device_fd`）。
    pub async fn new(
        local_config: Config,
        subscription: Option<Subscription>,
        log: Arc<InstanceLog>,
    ) -> anyhow::Result<Self> {
        let (routes_tx, routes_rx) = watch::channel(Vec::new());
        let subscription_listener = subscription.map(SubscriptionListener::new);
        let mut manager = Self {
            local_config,
            subscription_listener,
            routes_tx,
            routes_rx,
            groups: TaskGroupManager::new(),
            log,
            instance: None,
        };
        let config = manager.effective_config().await?;
        manager.start_instance(config).await?;
        Ok(manager)
    }

    /// 当前订阅信封携带的受管身份（network_code, device_id）。非阻塞：
    /// 非订阅模式或首份信封尚未到达时返回 None。订阅链接本身不携带身份，
    /// 上层（如 Web 状态接口）经此读取服务端下发的值。
    pub fn managed_identity(&self) -> Option<(String, String)> {
        let envelope = self.subscription_listener.as_ref()?.current_config_now()?;
        Some((envelope.config.network_code, envelope.config.device_id))
    }

    /// 当前有效配置（订阅模式下为服务端下发与本地设置的合并）。
    pub async fn current_config(&mut self) -> anyhow::Result<Config> {
        self.effective_config().await
    }

    /// 等待注册完成并启动虚拟网卡，返回网段信息。桌面平台使用。
    pub async fn start_device(&mut self) -> anyhow::Result<NetworkAddr> {
        self.start_device_impl(
            #[cfg(unix)]
            None,
            #[cfg(not(unix))]
            (),
        )
        .await
    }

    /// unix 专用：等待注册完成并启动虚拟网卡，可传入宿主提供的 TUN fd
    /// （移动平台 VpnService 场景）。
    #[cfg(unix)]
    pub async fn start_device_fd(
        &mut self,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<NetworkAddr> {
        self.start_device_impl(tun_fd).await
    }

    async fn start_device_impl(
        &mut self,
        #[cfg(unix)] tun_fd: Option<std::os::fd::OwnedFd>,
        #[cfg(not(unix))] _tun_fd: (),
    ) -> anyhow::Result<NetworkAddr> {
        let manager = self.with_manager()?;
        let network = manager.current_network().await?;
        if manager.device_mode().has_device() {
            #[cfg(unix)]
            manager.start_device_fd(tun_fd).await?;
            #[cfg(not(unix))]
            manager.start_device().await?;
        } else {
            manager.apply_initial_network_info().await?;
        }
        // 网卡创建成功（首次启动与实例重建后的新网卡）：通告宿主
        manager.notify_device_applied().await;
        Ok(network)
    }

    /// 应用一次完整快照。桌面平台使用（内部按需重建实例）。
    pub async fn apply_change(&mut self, change: &RuntimeChange) -> anyhow::Result<ChangeOutcome> {
        self.apply_change_impl(
            change,
            #[cfg(unix)]
            None,
            #[cfg(not(unix))]
            (),
        )
        .await
    }

    /// unix 专用：应用一次完整快照，可携带宿主新建的 TUN fd（移动平台）。
    #[cfg(unix)]
    pub async fn apply_change_fd(
        &mut self,
        change: &RuntimeChange,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<ChangeOutcome> {
        self.apply_change_impl(change, tun_fd).await
    }

    /// 重建组网实例：停止当前实例并以最新有效配置新建，随后等待注册并
    /// 启动虚拟网卡。订阅连接与路由通道在重建过程中保持不断。桌面平台
    /// 使用。
    pub async fn rebuild(&mut self) -> anyhow::Result<()> {
        self.rebuild_impl(
            #[cfg(unix)]
            None,
            #[cfg(not(unix))]
            (),
        )
        .await
    }

    /// unix 专用：重建组网实例，可传入宿主新建的 TUN fd（移动平台）。
    #[cfg(unix)]
    pub async fn rebuild_fd(&mut self, tun_fd: Option<std::os::fd::OwnedFd>) -> anyhow::Result<()> {
        self.rebuild_impl(tun_fd).await
    }

    /// 实例任务组句柄的克隆。停止它即可让当前实例停机（监测方的
    /// `wait_all_stopped` 随即唤醒并走清理路径），用于不能长时间持有
    /// 管理器锁的停止流程——监测循环在 `next_event` 等待期间持有锁。
    pub fn task_groups(&self) -> TaskGroupManager {
        self.groups.clone()
    }

    /// 停止组网实例与订阅连接。
    pub async fn stop(&mut self) {
        if let Some(instance) = self.instance.take() {
            instance.manager.stop().await;
        }
        self.groups.stop_and_wait().await;
        // 订阅连接随 SubscriptionListener 的 Drop 断开
        self.subscription_listener = None;
    }

    /// 当前组网实例的查询 API（实例未启动时为 None）。
    pub fn api(&self) -> Option<VntApi> {
        self.instance
            .as_ref()
            .map(|instance| instance.manager.vnt_api())
    }

    /// 等待当前组网实例停止。没有实例时永久等待（实例只能由
    /// [`RuntimeChangeManager::rebuild`] 替换，不会消失）。
    pub async fn wait_instance_stopped(&mut self) {
        match self.instance.as_mut() {
            Some(instance) => instance.manager.wait_all_stopped().await,
            None => std::future::pending().await,
        }
    }

    /// 当前组网实例的网段信息（未注册完成时等待注册结果）。
    pub async fn current_network(&self) -> anyhow::Result<NetworkAddr> {
        self.instance
            .as_ref()
            .context("组网实例未启动")?
            .manager
            .current_network()
            .await
    }

    /// 当前虚拟网卡模式。
    pub fn device_mode(&self) -> DeviceMode {
        self.instance
            .as_ref()
            .map(|instance| instance.manager.device_mode())
            .unwrap_or_else(|| self.local_config.device_mode)
    }

    fn with_manager(&mut self) -> anyhow::Result<&mut NetworkManager> {
        self.instance
            .as_mut()
            .map(|instance| &mut instance.manager)
            .context("组网实例未启动")
    }

    /// 有效配置：订阅信封（出现的键）与本地设置的合并。
    async fn effective_config(&mut self) -> anyhow::Result<Config> {
        match self.subscription_listener.as_mut() {
            Some(listener) => {
                let envelope = listener.current_config().await?;
                Ok(merge_present_config(
                    self.local_config.clone(),
                    &envelope.config,
                    &envelope.present,
                ))
            }
            None => Ok(self.local_config.clone()),
        }
    }

    /// 启动一个组网实例（不含虚拟网卡启动）。
    async fn start_instance(&mut self, config: Config) -> anyhow::Result<()> {
        let (task_group, guard) = self.groups.create_task().context("创建任务组失败")?;
        let started = NetworkManager::create_network(
            Box::new(config),
            task_group,
            self.log.clone(),
            self.routes_tx.clone(),
        )
        .await;
        match started {
            Ok(manager) => {
                self.instance = Some(ManagedInstance {
                    manager,
                    _guard: guard,
                });
                Ok(())
            }
            Err(error) => {
                drop(guard);
                Err(error)
            }
        }
    }

    async fn apply_change_impl(
        &mut self,
        change: &RuntimeChange,
        #[cfg(unix)] tun_fd: Option<std::os::fd::OwnedFd>,
        #[cfg(not(unix))] _tun_fd: (),
    ) -> anyhow::Result<ChangeOutcome> {
        // MTU 低于 P2P 栈下限的配置会让后续实例创建失败，直接拒绝本次应用
        if let Some(mtu) = change.config.mtu
            && mtu < crate::core::MIN_MTU
        {
            anyhow::bail!(
                "快照 MTU {mtu} 低于下限 {}，已拒绝应用",
                crate::core::MIN_MTU
            );
        }
        if self.with_manager()?.needs_instance_rebuild(change) {
            // 重建需要新的虚拟网卡 fd（有设备的平台）；桌面平台无此要求
            let needs_fd = self.with_manager()?.device_mode().has_device();
            #[cfg(unix)]
            let has_fd = tun_fd.is_some();
            #[cfg(not(unix))]
            let has_fd = true;
            if needs_fd && !has_fd {
                return Ok(ChangeOutcome::Rebuild);
            }
            self.rebuild_impl(
                #[cfg(unix)]
                tun_fd,
                #[cfg(not(unix))]
                _tun_fd,
            )
            .await?;
            return Ok(ChangeOutcome::Applied);
        }
        // 先取日志句柄，避免与 instance 的借用冲突
        let log = self.log.clone();
        let manager = self.with_manager()?;
        if manager.needs_policy_change(change) {
            manager.apply_policy_change(change);
            log.info("已应用策略类配置变更");
        }
        if manager.needs_server_change(change) {
            manager.apply_server_change(change).await?;
            log.info("已应用服务端地址变更");
        }
        // 网卡是否被（重新）应用：桌面看网络变更/网卡重启，移动看 fd 换卡；
        // 无设备模式下两者都不会真正触碰网卡，由 helper 内部过滤
        let mut device_applied = false;
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        {
            if manager.needs_network_change(change) {
                manager.apply_network_change(change).await?;
                device_applied = true;
                log.info(format!(
                    "已应用网络变更（虚拟 IP/路由，入栈路由 {} 条）",
                    change.routes.len()
                ));
            }
            if manager.needs_device_restart(change) {
                manager.restart_device(change).await?;
                device_applied = true;
                log.info("已重启虚拟网卡");
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        {
            if manager.needs_vpn_rebuild(change) {
                #[cfg(unix)]
                let Some(tun_fd) = tun_fd else {
                    return Ok(ChangeOutcome::NeedFd(
                        "网卡相关变更需要传入新的 TUN fd".to_string(),
                    ));
                };
                manager.apply_mobile_change_fd(change, Some(tun_fd)).await?;
                device_applied = true;
                log.info("已按快照重建 VPN 接口（虚拟 IP/MTU/路由）");
            } else {
                // 宿主可能随实例重建一并更换接口：携带的 fd 直接交给
                // apply_mobile_change_fd 采用，避免旧 fd 被宿主关闭后失效
                manager.apply_mobile_change_fd(change, tun_fd).await?;
                log.info("已提交运行期快照（无网卡相关变更）");
            }
        }
        // 一次快照应用完成后统一通告：网卡被（重新）应用时触发事件脚本
        if device_applied {
            manager.notify_device_applied().await;
        }
        Ok(ChangeOutcome::Applied)
    }

    async fn rebuild_impl(
        &mut self,
        #[cfg(unix)] tun_fd: Option<std::os::fd::OwnedFd>,
        #[cfg(not(unix))] _tun_fd: (),
    ) -> anyhow::Result<()> {
        let config = self.effective_config().await?;
        if let Some(instance) = self.instance.take() {
            instance.manager.stop().await;
        }
        // 等待旧实例任务组完全停止并释放槽位，再创建新的一代
        self.groups.stop_and_wait().await;
        self.log.info("重建组网实例");
        self.start_instance(config).await?;
        self.start_device_impl(
            #[cfg(unix)]
            tun_fd,
            #[cfg(not(unix))]
            _tun_fd,
        )
        .await?;
        Ok(())
    }

    /// 等待下一次运行期事件：组网实例停止或新的完整快照。前端的主循环
    /// 应优先使用本方法（同时覆盖两种事件，且不与 manager 的其它借用冲突）。
    pub async fn next_event(&mut self) -> anyhow::Result<RuntimeEvent> {
        // 字段级分离借用：instance 与 (subscription_listener, routes_rx,
        // local_config) 不相交，两个等待 future 可以同时存在
        let instance = &mut self.instance;
        let subscription_listener = &mut self.subscription_listener;
        let routes_rx = &mut self.routes_rx;
        let local_config = &self.local_config;
        let stopped = async {
            match instance.as_mut() {
                Some(instance) => instance.manager.wait_all_stopped().await,
                None => std::future::pending().await,
            }
        };
        let changed = Self::changed_with(subscription_listener, routes_rx, local_config);
        tokio::select! {
            _ = stopped => Ok(RuntimeEvent::InstanceStopped),
            result = changed => result.map(|change| RuntimeEvent::Changed(Box::new(change))),
        }
    }

    /// Waits until the latest complete snapshot changes.
    pub async fn changed(&mut self) -> anyhow::Result<RuntimeChange> {
        Self::changed_with(
            &mut self.subscription_listener,
            &mut self.routes_rx,
            &self.local_config,
        )
        .await
    }

    /// 预览一次快照需要的处理方式，不应用任何变更。移动平台宿主在
    /// [`RuntimeChangeManager::next_event`] 收到 `Changed` 后据此决定是否
    /// 重建 VPN 接口：`vpn_rebuild`/`instance_rebuild` 为 true 时用快照
    /// 参数新建接口并携带新 fd 调用 [`RuntimeChangeManager::apply_change_fd`]，
    /// 否则调用 [`RuntimeChangeManager::apply_change`] 原地应用。
    ///
    /// 标志只描述“相对当前实例”的判断，与应用之间状态若发生变化，以
    /// apply 内部的重新判断为准。
    pub fn inspect_change(&self, change: &RuntimeChange) -> ChangePlan {
        let Some(instance) = self.instance.as_ref() else {
            return ChangePlan::default();
        };
        let manager = &instance.manager;
        let instance_rebuild = manager.needs_instance_rebuild(change);
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        let vpn_rebuild = false;
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        let vpn_rebuild = manager.needs_vpn_rebuild(change);
        ChangePlan {
            vpn_rebuild,
            instance_rebuild,
        }
    }

    /// `changed` 的字段参数形式，供 `next_event` 在分离借用下复用。
    pub(crate) async fn changed_with(
        subscription_listener: &mut Option<SubscriptionListener>,
        routes_rx: &mut watch::Receiver<Vec<NetInput>>,
        local_config: &Config,
    ) -> anyhow::Result<RuntimeChange> {
        let (base, present) = match subscription_listener.as_mut() {
            Some(listener) => tokio::select! {
                result = listener.changed() => {
                    let envelope = result?;
                    (envelope.config, envelope.present)
                }
                result = routes_rx.changed() => {
                    result.context("route source closed")?;
                    let envelope = listener.current_config().await?;
                    (envelope.config, envelope.present)
                }
            },
            None => {
                routes_rx.changed().await.context("route source closed")?;
                (local_config.clone(), std::collections::HashSet::new())
            }
        };
        Ok(RuntimeChange {
            config: merge_present_config(local_config.clone(), &base, &present),
            routes: routes_rx.borrow_and_update().clone(),
        })
    }
}
#[cfg(test)]
mod merge_present_tests {
    use super::merge_present_config;
    use crate::context::config::Config;
    use std::collections::HashSet;

    fn present(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    fn base_config() -> Config {
        Config {
            network_code: "managed-net".to_string(),
            device_id: "managed-dev".to_string(),
            device_name: "managed-name".to_string(),
            ..Config::default()
        }
    }

    #[test]
    fn identity_and_ip_always_come_from_the_envelope() {
        let local = Config {
            network_code: "local-net".to_string(),
            device_id: "local-dev".to_string(),
            device_name: "local-name".to_string(),
            ..Config::default()
        };
        let base = base_config();
        let merged = merge_present_config(local, &base, &present(&[]));
        assert_eq!(merged.network_code, "managed-net");
        assert_eq!(merged.device_id, "managed-dev");
        assert_eq!(merged.device_name, "managed-name");
    }

    #[test]
    fn only_keys_present_in_the_envelope_override_local() {
        let local = Config {
            compress: false,
            no_punch: true,
            password: Some("local-pass".to_string()),
            ..Config::default()
        };
        let mut base = base_config();
        base.compress = true;
        base.password = Some("managed-pass".to_string());
        // 信封只设置了 compress：no_punch 与 password 保持本地值
        let merged = merge_present_config(local.clone(), &base, &present(&["compress"]));
        assert!(merged.compress);
        assert!(merged.no_punch);
        assert_eq!(merged.password.as_deref(), Some("local-pass"));

        // 信封同时设置 password：重建类字段同样覆盖本地
        let merged = merge_present_config(local, &base, &present(&["compress", "password"]));
        assert!(merged.compress);
        assert_eq!(merged.password.as_deref(), Some("managed-pass"));
    }

    #[test]
    fn non_empty_server_list_from_the_envelope_wins() {
        let local = Config {
            server_addr: vec!["tcp://127.0.0.1:29872".parse().unwrap()],
            ..Config::default()
        };
        let mut base = base_config();
        base.server_addr = vec![
            "tcp://127.0.0.1:29872".parse().unwrap(),
            "tcp://127.0.0.1:29873".parse().unwrap(),
        ];
        let merged = merge_present_config(local, &base, &present(&[]));
        assert_eq!(merged.server_addr.len(), 2);
    }
}
