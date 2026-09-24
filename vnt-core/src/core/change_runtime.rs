//! [`NetworkManager`] 的运行期变更应用：虚拟 IP/网段/入站路由的应用、
//! 虚拟网卡任务重启与服务端地址增删、策略类配置热更新，以及
//! "能否增量应用"的判断方法。
//!
//! 每类配置一个独立的 apply 方法，方法内部各自完成"比较 → 提交对应
//! 字段 → 执行变更动作"：配置先行（动作失败时配置已是新值，不回滚，
//! 错误上抛由调用方记录），可单独调用；组合多项变更时按以下顺序
//! （理由见各方法文档）：
//!
//! 1. [`NetworkManager::needs_instance_rebuild`] 为 true：停止实例并重建，
//!    不要调用任何 apply 方法（等价于所有服务端连接全部重启）。
//! 2. [`NetworkManager::apply_policy_change`]：先提交策略字段，让后续新建
//!    的服务端连接携带最新的注册宣告字段。
//! 3. [`NetworkManager::apply_server_change`]：依赖第 2 步已提交的配置。
//! 4. [`NetworkManager::needs_network_change`] 为 true 时调用
//!    `apply_network_change`：与第 2、3 步无依赖；桌面平台的 MTU 也在
//!    这一步热更新（tun-rs 支持动态修改，无需重建设备）。
//! 5. [`NetworkManager::needs_device_restart`] 为 true 时最后调用
//!    `restart_device`：其内部会按快照重新应用地址与路由，覆盖第 4 步
//!    的结果。
//!
//! 平台划分：`apply_network_change` / `restart_device` 仅桌面平台
//! （非 Android/iOS/tvOS）提供；移动平台改用
//! [`NetworkManager::apply_mobile_change_fd`]——它同时承担变更应用与
//! fd 型虚拟网卡重建（携带宿主新建的 TUN fd）。

use super::{DEFAULT_MTU, NetworkManager, ServerLinks};
use crate::event_script::EventScriptType;
#[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
use crate::context::config::DeviceMode;
use crate::context::{NetworkAddr, NetworkRoute};
use crate::network_info::RuntimeChange;
use crate::runtime_config::RuntimePolicy;
#[cfg(not(target_os = "android"))]
use crate::tun::DeviceConfig;
use crate::tunnel_core::server::connection_manager::{
    InboundHandlerConfig, NewServerLink, create_server_manager,
};
use crate::tunnel_core::server::transport::config::ProtocolAddress;
use anyhow::{Context, bail};
use crate::context::config::Config;

impl NetworkManager {
    /// 判断一次运行期快照是否包含需要改动网络的字段：虚拟 IP/网段
    /// （`config.ip`）相对当前注册地址变化，配置的入站路由表（`input`）
    /// 变化，或入站路由快照相对已应用路由变化。仅身份等非路由字段变化
    /// 时返回 false，调用方可以整体跳过应用。
    pub fn needs_network_change(&self, change: &RuntimeChange) -> bool {
        let (_, address) = self.runtime_address(change.config.ip);
        let structural_change = address.is_some()
            || change.config.input != self.config.input
            || normalized_routes(self.app_state.subnet_route.applied_routes())
                != normalized_routes(change.routes.clone());
        // 桌面平台 MTU 可热更新（tun-rs set_mtu），纳入网络变更判断；
        // 移动平台 MTU 由宿主的 VPN 接口决定，归 needs_device_restart 覆盖
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        let mtu_change = change.config.mtu.is_some() && change.config.mtu != self.config.mtu;
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        let mtu_change = false;
        // Windows/Linux/FreeBSD 支持网卡名热变更（tun-rs set_name）；
        // 恢复默认名（None）无法热应用，归 needs_device_restart 走重建
        #[cfg(any(windows, target_os = "linux", target_os = "freebsd"))]
        let name_change =
            change.config.tun_name.is_some() && change.config.tun_name != self.config.tun_name;
        #[cfg(not(any(windows, target_os = "linux", target_os = "freebsd")))]
        let name_change = false;
        structural_change || mtu_change || name_change
    }

    /// 判断快照是否包含只能通过重建实例生效的字段：password/cert_mode、
    /// 托管身份（network_code/device_id/device_name/managed）、绑定出口
    /// 网卡（outbound_interface）、本地隧道监听（tunnel_addr/tunnel_port）、
    /// device_mode、port_mapping、subnet_mapping、output、event_script。
    ///
    /// 这些字段烘焙在长期存活对象中（加密与 QUIC 证书、连接参数、监听
    /// socket、设备分支、映射表），没有运行期应用路径。为 true 时调用方
    /// 应停止当前实例并重建（等价于所有服务端连接全部重启），不要调用
    /// 任何 apply 方法。
    pub fn needs_instance_rebuild(&self, change: &RuntimeChange) -> bool {
        instance_rebuild_fields_differ(&self.config, &change.config)
    }

    /// 判断快照中的服务端地址列表相对当前连接是否变化。
    ///
    /// 应用顺序：无前置依赖；建议在 [`NetworkManager::apply_policy_change`]
    /// 之后调用，使新增连接携带最新的注册宣告字段（allow_ikev2 等）。
    pub fn needs_server_change(&self, change: &RuntimeChange) -> bool {
        server_fields_differ(&self.config, &change.config)
    }

    /// 判断快照的策略类字段是否变化（可通过 apply_policy_change 热应用）：
    /// turn/punch_model/peer_address/compress/rtx/fec/no_punch/no_nat/
    /// no_broadcast/auto_sync_subnet/allow_port_mapping/allow_ikev2/
    /// allow_wireguard/udp_stun/tcp_stun。
    pub fn needs_policy_change(&self, change: &RuntimeChange) -> bool {
        policy_fields_differ(&self.config, &change.config)
    }

    /// 判断快照是否要求重建虚拟网卡任务：Windows/Linux/FreeBSD 的 MTU 与
    /// 网卡名均可热更新（仅恢复默认名需要重建）；macOS 网卡名变化需要重建；
    /// 移动平台的 MTU 与网卡名都要求重建。
    ///
    /// 应用顺序：应在所有其他 apply 方法之后最后调用
    /// [`NetworkManager::restart_device`]——其内部会按快照重新应用虚拟
    /// 地址与路由，覆盖 apply_network_change 的结果。
    pub fn needs_device_restart(&self, change: &RuntimeChange) -> bool {
        // 需要重建虚拟网卡任务的字段随平台热更新能力变化：
        // - Windows/Linux/FreeBSD：MTU 与网卡名均可热变更，仅“恢复默认
        //   名”（tun_name 置空）无法热应用，需要重建；
        // - macOS 等桌面平台：不支持热改名，网卡名变化需要重建；
        // - 移动平台：MTU 与网卡名都由宿主 VPN 接口决定，都需重建
        #[cfg(any(windows, target_os = "linux", target_os = "freebsd"))]
        {
            change.config.tun_name.is_none() && self.config.tun_name.is_some()
        }
        #[cfg(all(
            not(any(windows, target_os = "linux", target_os = "freebsd")),
            not(any(target_os = "android", target_os = "ios", target_os = "tvos"))
        ))]
        {
            self.config.tun_name != change.config.tun_name
        }
        #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
        {
            device_restart_fields_differ(&self.config, &change.config)
        }
    }

    /// 热应用策略类配置：turn/punch_model/peer_address/compress/rtx/fec/
    /// no_punch/no_nat/no_broadcast/auto_sync_subnet/allow_port_mapping/
    /// allow_ikev2/allow_wireguard/udp_stun/tcp_stun。
    ///
    /// 通过 [`RuntimePolicyStore::store`] 整体换策略快照，各组件逐包读取
    /// 立即生效；peer/stun/no_punch 变化会唤醒对端探测、NAT 检测与打洞
    /// 循环。提交后把变更字段写入实例配置。返回是否发生了应用。
    ///
    /// 边界：subnet_mapping/output 的句柄不可通过本方法变更（它们的差异
    /// 属于 [`NetworkManager::needs_instance_rebuild`]）；allow_ikev2/
    /// allow_wireguard 的中继行为立即生效，但已建连服务器的注册宣告侧
    /// 要等下次重连或重建实例才更新。
    ///
    /// 应用顺序：必须在 [`NetworkManager::apply_server_change`] **之前**
    /// 调用——后者新建的服务端连接从已提交的实例配置读取注册宣告字段。
    pub fn apply_policy_change(&mut self, change: &RuntimeChange) -> bool {
        if !policy_fields_differ(&self.config, &change.config) {
            return false;
        }
        // subnet_mapping/output 的句柄从当前策略沿用：它们的差异属于
        // needs_instance_rebuild，不会走到这里
        let (subnet_mapping, relay_subnets) = {
            let current = self.runtime_policy.load();
            (
                current.subnet_mapping.clone(),
                current.relay_subnets.clone(),
            )
        };
        let policy = RuntimePolicy::from_config_with_handles(
            &change.config,
            change.config.fec.then_some(self.fec_encoder.clone()),
            subnet_mapping,
            relay_subnets.clone(),
            relay_subnets,
        );
        self.runtime_policy.store(policy);
        self.config.turn = change.config.turn.clone();
        self.config.punch_model = change.config.punch_model.clone();
        self.config.peer_address = change.config.peer_address.clone();
        self.config.compress = change.config.compress;
        self.config.rtx = change.config.rtx;
        self.config.fec = change.config.fec;
        self.config.no_punch = change.config.no_punch;
        self.config.no_nat = change.config.no_nat;
        self.config.no_broadcast = change.config.no_broadcast;
        self.config.auto_sync_subnet = change.config.auto_sync_subnet;
        self.config.allow_port_mapping = change.config.allow_port_mapping;
        self.config.allow_ikev2 = change.config.allow_ikev2;
        self.config.allow_wireguard = change.config.allow_wireguard;
        self.config.udp_stun = change.config.udp_stun.clone();
        self.config.tcp_stun = change.config.tcp_stun.clone();
        true
    }

    /// 应用一次完整运行期快照中的网络状态：虚拟 IP/网段（设备虚拟地址）、
    /// 完整入站路由（系统路由 + 转发路由表），并把配置中影响路由的字段
    /// （`ip`、`input`）提交到实例。非安卓平台使用。
    ///
    /// 相同地址的 set_network 是 no-op，系统路由按完整快照对账。执行顺序：
    /// 先提交配置（路由快照、`ip`/`input`、MTU/网卡名与共享网络地址，配置
    /// 即新值），再执行变更动作（虚拟网卡、系统路由与服务端通告）；动作
    /// 失败不回滚，错误上抛由调用方记录。快照未携带虚拟 IP（`config.ip`
    /// 为空）时保持当前地址，只应用路由。
    ///
    /// 应用顺序：与 apply_policy_change / apply_server_change 无依赖；
    /// 若 [`NetworkManager::needs_device_restart`] 也为真，本方法的结果会
    /// 被 `restart_device` 覆盖，可直接只调用后者。
    /// 虚拟网卡被（重新）应用后触发事件脚本：热更新、重启网卡任务或换卡
    /// 重建之后调用，把当前生效的网卡状态通告宿主。无设备模式没有网卡可
    /// 应用，直接跳过。
    pub(crate) async fn notify_device_applied(&self) {
        if !self.device_mode().has_device() {
            return;
        }
        let Some(network) = self.app_state.network.get() else {
            return;
        };
        let mut params = vec![
            ("ip", network.ip.to_string()),
            ("prefix-length", network.prefix_len.to_string()),
            (
                "gateway",
                network
                    .gateway
                    .map(|gateway| gateway.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("broadcast", network.broadcast.to_string()),
            ("mtu", self.config.mtu.unwrap_or(DEFAULT_MTU).to_string()),
        ];
        if let Some(tun_name) = &self.config.tun_name {
            params.push(("tun-name", tun_name.clone()));
        }
        self.event_script
            .notify(EventScriptType::DeviceApplied, &params)
            .await;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    pub async fn apply_network_change(&mut self, change: &RuntimeChange) -> anyhow::Result<()> {
        let previous = self.app_state.network.get();
        let (desired, _) = self.runtime_address(change.config.ip);
        // 先提交配置：MTU/网卡名、路由快照与 `ip`/`input`，随后同步共享
        // 网络地址（配置即新值）
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
        if change.config.mtu != self.config.mtu {
            self.config.mtu = change.config.mtu;
        }
        #[cfg(any(windows, target_os = "linux", target_os = "freebsd"))]
        if change.config.tun_name != self.config.tun_name {
            self.config.tun_name = change.config.tun_name.clone();
        }
        self.commit_runtime_snapshot(change);
        if let Some(address) = desired {
            // 网关是注册时确定的虚拟网络属性，不随快照重算，沿用当前注册值
            let gateway = previous.and_then(|network| network.gateway);
            self.app_state
                .network
                .set(NetworkAddr { gateway, ..address });
        }
        // 变更动作：应用到虚拟网卡与系统路由（失败上抛，不回滚配置）
        if self.device_mode().has_device() {
            if let Some(address) = desired {
                self.device_io_manager
                    .set_network(address.ip, address.prefix_len)
                    .await?;
            }
            self.device_io_manager
                .apply_system_routes(change.routes.clone())
                .await?;
            // MTU 热更新：桌面平台 tun-rs 支持动态修改，无需重建设备
            let mtu = change.config.mtu.or(self.config.mtu).unwrap_or(DEFAULT_MTU);
            self.device_io_manager.set_mtu(mtu).await?;
            // 网卡名热更新：Windows/Linux/FreeBSD 由 tun-rs 支持，无需重建
            #[cfg(any(windows, target_os = "linux", target_os = "freebsd"))]
            if let Some(tun_name) = &change.config.tun_name {
                self.device_io_manager.set_tun_name(tun_name).await?;
            }
        }
        if let Some(address) = desired {
            // 同步注册 IP，并快速注册到所有已连接服务端（连接不断、无
            // 周期性重注册，服务端映射靠这条通告收敛）
            self.ip_update.announce_ip(address.ip).await;
        }
        Ok(())
    }

    /// 桌面平台专用：重启虚拟网卡任务。先停止当前任务，再按快照参数重建
    /// 虚拟网卡并启动新任务，最后把快照的虚拟 IP/网段与完整入站路由应用
    /// 到新设备。快照未携带虚拟 IP 时沿用当前注册地址。mtu/tun_name 在
    /// 重启动作前先提交到实例配置（配置即新值）。
    ///
    /// 应用顺序：**最后调用**——当 [`NetworkManager::needs_device_restart`]
    /// 为真时使用；其内部会按快照重新应用虚拟地址与路由，覆盖
    /// apply_network_change 已应用的结果。
    ///
    /// Android/iOS/tvOS 不提供本方法：移动平台使用
    /// [`NetworkManager::apply_mobile_change_fd`] 应用变更（必要时重建
    /// fd 型虚拟网卡）。
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    pub async fn restart_device(&mut self, change: &RuntimeChange) -> anyhow::Result<()> {
        let config = self.restart_device_config(change)?;
        self.restart_device_with(change, config).await
    }

    /// 桌面 unix 专用变体：携带宿主新建的 TUN fd 时直接以该 fd 构建新
    /// 虚拟网卡，不经过系统设备创建流程。
    #[cfg(all(unix, not(any(target_os = "android", target_os = "ios", target_os = "tvos"))))]
    pub async fn restart_device_fd(
        &mut self,
        change: &RuntimeChange,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<()> {
        let mut config = self.restart_device_config(change)?;
        if let Some(tun_fd) = tun_fd {
            config = config.set_tun_fd(tun_fd);
        }
        self.restart_device_with(change, config).await
    }

    /// 依据快照与实例配置构建重启用的设备配置（模式、MTU、TAP MAC、名称）。
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    fn restart_device_config(&self, change: &RuntimeChange) -> anyhow::Result<DeviceConfig> {
        let (desired, _) = self.runtime_address(change.config.ip);
        let address = desired.or(self.app_state.network.get());
        let mut config = DeviceConfig::default()
            .set_device_mode(self.config.device_mode)
            .set_mtu(change.config.mtu.or(self.config.mtu).unwrap_or(DEFAULT_MTU));
        if self.config.device_mode == DeviceMode::Tap {
            let ip = address
                .map(|network| network.ip)
                .context("网络尚未注册，无法确定 TAP 网卡 MAC")?;
            config = config.set_mac_addr(crate::ethernet::mac_from_ip(ip).octets());
        }
        if let Some(tun_name) = change.config.tun_name.clone() {
            config = config.set_tun_name(tun_name);
        }
        Ok(config)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "tvos")))]
    async fn restart_device_with(
        &mut self,
        change: &RuntimeChange,
        config: DeviceConfig,
    ) -> anyhow::Result<()> {
        if !self.device_mode().has_device() {
            bail!("当前为无虚拟网卡模式，没有可重启的虚拟网卡任务");
        }
        if self.tun_receiver.is_some() || self.enhanced_outbound.is_some() {
            bail!("虚拟网卡尚未启动");
        }
        let (desired, _) = self.runtime_address(change.config.ip);
        let address = desired.or(self.app_state.network.get());
        // 先把设备字段提交到实例配置（配置即新值），再关闭当前虚拟网卡
        // 任务并启动新任务，随后把地址与路由应用到新设备；动作失败不回滚
        self.config.mtu = change.config.mtu;
        self.config.tun_name = change.config.tun_name.clone();
        self.device_io_manager.restart_task(config).await?;
        if let Some(address) = &address {
            self.device_io_manager
                .set_network(address.ip, address.prefix_len)
                .await?;
        }
        #[cfg(not(any(target_os = "ios", target_os = "tvos")))]
        self.apply_network_change(change).await?;
        Ok(())
    }

    /// 全平台通用：应用服务端地址变更。
    ///
    /// 先把快照中的服务端地址列表提交到实例配置（配置即新值），再执行
    /// 连接增删动作：快照与当前连接对比分为删除、新增、未变三类——已
    /// 删除地址的连接任务先停止并从出站/RPC 登记中摘除；新增地址创建
    /// 新的连接任务（进入常规注册重连流程）；未变地址保持原 server_id
    /// 与连接完全不动。最后统一刷新服务端信息集合与出站表。动作失败
    /// 不回滚，错误上抛由调用方记录。
    ///
    /// 应用顺序：建议在 [`NetworkManager::apply_policy_change`] **之后**
    /// 调用（新建连接读取已提交实例配置中的注册宣告字段）；与网络变更
    /// （apply_network_change）和设备重启相互独立。
    pub async fn apply_server_change(&mut self, change: &RuntimeChange) -> anyhow::Result<()> {
        let new_addresses = change.config.server_addr.clone();
        if new_addresses == self.config.server_addr {
            return Ok(());
        }
        if self.server_task_group.is_stopped() {
            bail!("服务端连接任务已停止，无法应用地址变更");
        }
        self.config.server_addr = new_addresses.clone();
        // 阶段一（持锁、无 await）：差分出删除与新增，摘除删除项的登记，
        // 并为新增地址预先构建连接构件
        let (removals, created) = {
            let mut links = self.server_links.lock();
            let removals = links.registry.plan_removals(&new_addresses);
            let added: Vec<ProtocolAddress> = new_addresses
                .iter()
                .filter(|address| !links.registry.is_known(address))
                .cloned()
                .collect();
            let created: Vec<(u32, ProtocolAddress, NewServerLink)> = added
                .into_iter()
                .map(|address| {
                    let server_id = links.registry.next_id();
                    // 单地址配置，让 to_connect_config 以该地址构建连接参数
                    let mut connect_config = (*self.config).clone();
                    connect_config.server_addr = vec![address.clone()];
                    let link = create_server_manager(
                        server_id,
                        &connect_config,
                        links.default_interface.clone(),
                        links.identity.clone(),
                        links.client_instance_id.clone(),
                        links.network.clone(),
                    );
                    (server_id, address, link)
                })
                .collect();
            (removals, created)
        };
        // 阶段二（无锁）：停止已删除地址的连接任务
        for (server_id, address, task) in removals {
            if let Some(task) = task {
                task.stop().await;
            }
            log::info!("已停止服务端连接任务: {server_id} {address}");
        }
        // 阶段三（持锁、无 await）：启动新增连接任务并登记，统一发布
        let mut links = self.server_links.lock();
        for (server_id, address, link) in created {
            let NewServerLink {
                manager,
                sender,
                notifier,
                subscription_verified,
            } = link;
            let task = manager.data_handle_task(
                &self.server_task_group,
                self.server_handler_config(&links),
                false,
            );
            links
                .registry
                .add(server_id, address.clone(), sender, notifier, subscription_verified, task);
            log::info!("已为新增服务端创建连接任务: {server_id} {address}");
        }
        self.app_state
            .server_info_collection
            .update_server(links.registry.id_address_pairs());
        self.server_rpc.update_server_links(links.registry.publish());
        Ok(())
    }

    /// 组装服务端数据任务的处理配置，内容与初始注册时一致。
    fn server_handler_config(&self, links: &ServerLinks) -> Box<InboundHandlerConfig> {
        Box::new(InboundHandlerConfig {
            network_route: NetworkRoute::new(
                self.app_state.network.clone(),
                self.app_state.subnet_route.clone(),
            ),
            server_info: self.app_state.server_info_collection.clone(),
            nat_info: self.app_state.nat_info.clone(),
            peer_map: self.app_state.peer_map.clone(),
            punch_backoff: self.app_state.punch_backoff.clone(),
            puncher: links.puncher.clone(),
            packet_crypto: links.packet_crypto.clone(),
            enhanced_inbound: links.enhanced_inbound.clone(),
            fec_decoder: links.fec_decoder.clone(),
            policy: links.policy.clone(),
            basic_outbound: links.basic_outbound.clone(),
            app_state: self.app_state.clone(),
        })
    }

    /// Android/iOS/tvOS 专用：应用一次完整运行期快照，额外携带宿主新建
    /// 的 TUN fd。移动平台没有 restart_device，本方法同时承担变更应用与
    /// fd 型虚拟网卡重建。
    ///
    /// 设备模式：携带 fd 时以快照参数整体重建 fd 型虚拟网卡（地址/MTU 以
    /// 快照为准，快照未携带则沿用当前值）：Android 走
    /// replace_android_virtual_device（同步注册地址，IP 变化时发送
    /// fast_reg）；iOS/tvOS 经 restart_task 重建后设置地址。未携带 fd 时
    /// 网卡相关变更无法应用（返回错误，调用方据此让宿主重建接口后重试），
    /// 仅提交与网卡无关的快照；无设备模式只做地址登记。执行顺序：先提交
    /// 路由快照、`ip`/`input`、共享地址与设备字段（`mtu`、`tun_name`，
    /// 配置即新值），再执行 fd 重建动作；动作失败不回滚，错误上抛由
    /// 调用方记录。
    ///
    /// 应用顺序：与 apply_policy_change / apply_server_change 无依赖；
    /// 是否需要新 fd 由 [`NetworkManager::needs_vpn_rebuild`] 判断。
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    pub async fn apply_mobile_change_fd(
        &mut self,
        change: &RuntimeChange,
        tun_fd: Option<std::os::fd::OwnedFd>,
    ) -> anyhow::Result<()> {
        let (desired, address) = self.runtime_address(change.config.ip);
        if !self.device_mode().has_device() {
            // 无虚拟网卡：先提交配置（地址登记与快照），再执行通告动作
            // （策略/服务器变更已由调用方应用）
            if let Some(address) = address {
                self.app_state.network.set(address);
            }
            self.commit_runtime_snapshot(change);
            if let Some(address) = address {
                // 地址变化同样要通告：服务端映射不依赖本机网卡存在
                self.ip_update.announce_ip(address.ip).await;
            }
            return Ok(());
        }
        let Some(tun_fd) = tun_fd else {
            // 设备模式：VpnService 接口的地址/MTU/路由在 establish 时确定，
            // 网卡相关变更必须由宿主整体重建；没有新 fd 时仅允许与网卡无关的
            // 变更（已由调用方先行应用），这里只提交快照
            if self.needs_vpn_rebuild(change) {
                bail!("虚拟 IP/网段/MTU/路由/网卡名变更需要传入新的 TUN fd 以重建 VPN 接口");
            }
            self.commit_runtime_snapshot(change);
            return Ok(());
        };
        // 设备模式 + 新 fd：先提交配置（共享地址、路由快照与设备字段，
        // 配置即新值），再执行 fd 重建动作；动作失败不回滚
        let mut network = desired
            .or(self.app_state.network.get())
            .context("网络尚未注册，无法重建虚拟网卡")?;
        // 网关是注册时确定的虚拟网络属性，不随快照重算，沿用当前注册值
        network.gateway = self.app_state.network.get().and_then(|value| value.gateway);
        let mtu = change.config.mtu.or(self.config.mtu).unwrap_or(DEFAULT_MTU);
        let (ip, prefix_len) = (network.ip, network.prefix_len);
        let ip_changed = self
            .app_state
            .network
            .get()
            .map(|current| current.ip != network.ip)
            .unwrap_or(true);
        // 写入共享网络地址（重注册据此声称同一 IP）
        self.app_state.network.set(network);
        self.commit_runtime_snapshot(change);
        self.config.mtu = change.config.mtu;
        self.config.tun_name = change.config.tun_name.clone();
        #[cfg(target_os = "android")]
        {
            self.device_io_manager
                .replace_task_fd(tun_fd, ip, prefix_len, mtu)
                .await?;
        }
        #[cfg(any(target_os = "ios", target_os = "tvos"))]
        {
            let mut config = DeviceConfig::default()
                .set_device_mode(self.config.device_mode)
                .set_mtu(mtu)
                .set_tun_fd(tun_fd);
            if let Some(tun_name) = change.config.tun_name.clone() {
                config = config.set_tun_name(tun_name);
            }
            self.device_io_manager.restart_task(config).await?;
            self.device_io_manager.set_network(ip, prefix_len).await?;
        }
        // IP 实际变化时向所有已连接服务端发送快速注册
        if ip_changed {
            self.ip_update.announce_ip(ip).await;
        }
        Ok(())
    }

    /// 移动平台：快照是否包含需要宿主重建 VPN 接口的变更。VpnService 的
    /// 地址/MTU/路由在 establish 时确定，虚拟 IP/网段、MTU、路由、网卡名
    /// 任何一项变化都需要新接口（即调用方需要传入新的 TUN fd）。
    ///
    /// 无设备模式（device_mode=no）没有 VPN 接口可重建，网卡类变更随
    /// 快照直接提交，恒为 false。
    #[cfg(any(target_os = "android", target_os = "ios", target_os = "tvos"))]
    pub fn needs_vpn_rebuild(&self, change: &RuntimeChange) -> bool {
        if !self.device_mode().has_device() {
            return false;
        }
        let (_, address) = self.runtime_address(change.config.ip);
        address.is_some()
            || (change.config.mtu.is_some() && change.config.mtu != self.config.mtu)
            || change.config.tun_name != self.config.tun_name
            || normalized_routes(self.app_state.subnet_route.applied_routes())
                != normalized_routes(change.routes.clone())
    }

    /// 依据快照中的虚拟 IP 推导目标网络地址，并返回“仅在实际变化时保留”
    /// 的地址值。变化判断只看 ip 与前缀长度；虚拟网关是注册时确定的虚拟
    /// 网络属性，不参与网卡变更判断，也不随快照重算（沿用注册值）。
    fn runtime_address(
        &self,
        ip: Option<crate::context::config::VirtualIp>,
    ) -> (Option<NetworkAddr>, Option<NetworkAddr>) {
        let previous = self.app_state.network.get();
        let desired = ip.map(|ip| {
            let net = ip.network();
            NetworkAddr {
                ip: ip.ip(),
                gateway: None,
                prefix_len: ip.prefix_len(),
                broadcast: net.broadcast(),
            }
        });
        let changed = match (&desired, previous) {
            (Some(desired), Some(previous)) => {
                desired.ip != previous.ip || desired.prefix_len != previous.prefix_len
            }
            (Some(_), None) => true,
            (None, _) => false,
        };
        let address = desired.filter(|_| changed);
        (desired, address)
    }

    /// 提交路由快照，并把配置中影响路由的字段（`ip`、`input`）应用到实例。
    fn commit_runtime_snapshot(&mut self, change: &RuntimeChange) {
        self.app_state.subnet_route.apply_routes(change.routes.clone());
        if change.config.ip != self.config.ip || change.config.input != self.config.input {
            self.config.ip = change.config.ip;
            self.config.input = change.config.input.clone();
            self.app_state
                .subnet_route
                .set_route_table(change.config.input.clone());
            self.app_state.set_config(self.config.clone());
        }
    }
}

/// 便于集合比较的路由规范化（排序去重；仅用于比较，不代表应用顺序）。
fn normalized_routes(mut routes: Vec<crate::nat::NetInput>) -> Vec<crate::nat::NetInput> {
    routes.sort_by_key(|route| {
        (
            u32::from(route.net.network()),
            route.net.prefix_len(),
            u32::from(route.target_ip),
        )
    });
    routes.dedup();
    routes
}

/// 服务端地址差分：可通过 apply_server_change 热应用（增删连接）。
fn server_fields_differ(current: &Config, target: &Config) -> bool {
    current.server_addr != target.server_addr
}

/// 策略类字段差分：可通过 apply_policy_change 热应用的字段集合。
fn policy_fields_differ(current: &Config, target: &Config) -> bool {
    current.turn != target.turn
        || current.punch_model != target.punch_model
        || current.peer_address != target.peer_address
        || current.compress != target.compress
        || current.rtx != target.rtx
        || current.fec != target.fec
        || current.no_punch != target.no_punch
        || current.no_nat != target.no_nat
        || current.no_broadcast != target.no_broadcast
        || current.auto_sync_subnet != target.auto_sync_subnet
        || current.allow_port_mapping != target.allow_port_mapping
        || current.allow_ikev2 != target.allow_ikev2
        || current.allow_wireguard != target.allow_wireguard
        || current.udp_stun != target.udp_stun
        || current.tcp_stun != target.tcp_stun
}

/// 重建实例字段差分：没有运行期应用路径、必须重建 NetworkManager 的字段集合。
fn instance_rebuild_fields_differ(current: &Config, target: &Config) -> bool {
    current.password != target.password
        || current.cert_mode != target.cert_mode
        || current.network_code != target.network_code
        || current.device_id != target.device_id
        || current.device_name != target.device_name
        || current.managed != target.managed
        || current.outbound_interface != target.outbound_interface
        || current.tunnel_addr != target.tunnel_addr
        || current.tunnel_port != target.tunnel_port
        || current.device_mode != target.device_mode
        || current.port_mapping != target.port_mapping
        || current.subnet_mapping != target.subnet_mapping
        || current.output != target.output
        || current.event_script != target.event_script
}

/// 设备重建字段差分：重启虚拟网卡任务（或宿主重建 fd 接口）才能生效的
/// 字段集合。桌面平台的 MTU 已支持热更新，不参与本差分；该函数目前仅
/// 移动平台调用。
#[cfg_attr(
    not(any(target_os = "android", target_os = "ios", target_os = "tvos")),
    allow(dead_code)
)]
fn device_restart_fields_differ(current: &Config, target: &Config) -> bool {
    current.mtu != target.mtu || current.tun_name != target.tun_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_field_changes_are_detected() {
        let current = Config::default();
        assert!(!policy_fields_differ(&current, &current));

        let mut target = current.clone();
        target.no_punch = true;
        assert!(policy_fields_differ(&current, &target));

        let mut target = current.clone();
        target.compress = true;
        assert!(policy_fields_differ(&current, &target));

        let mut target = current.clone();
        target.udp_stun = vec!["stun:127.0.0.1:3478".to_string()];
        assert!(policy_fields_differ(&current, &target));

        let mut target = current.clone();
        target.turn = vec!["10.26.0.0/24,10.26.0.1".parse().unwrap()];
        assert!(policy_fields_differ(&current, &target));
    }

    #[test]
    fn rebuild_field_changes_are_detected() {
        let current = Config::default();
        assert!(!instance_rebuild_fields_differ(&current, &current));

        let mut target = current.clone();
        target.password = Some("changed".to_string());
        assert!(instance_rebuild_fields_differ(&current, &target));

        let mut target = current.clone();
        target.outbound_interface = Some("eth1".to_string());
        assert!(instance_rebuild_fields_differ(&current, &target));

        let mut target = current.clone();
        target.tunnel_addr = vec!["127.0.0.1:9999".parse().unwrap()];
        assert!(instance_rebuild_fields_differ(&current, &target));

        let mut target = current.clone();
        target.managed = Some(crate::context::config::ManagedRegistration::new(
            vec![1; 32],
            "network".to_string(),
            "device".to_string(),
            vec![2; 32],
            0,
        ));
        assert!(instance_rebuild_fields_differ(&current, &target));
    }

    #[test]
    fn device_restart_field_changes_are_detected() {
        let current = Config::default();
        assert!(!device_restart_fields_differ(&current, &current));

        let mut target = current.clone();
        target.mtu = Some(1400);
        assert!(device_restart_fields_differ(&current, &target));

        let mut target = current.clone();
        target.tun_name = Some("vnt1".to_string());
        assert!(device_restart_fields_differ(&current, &target));

        // policy 维度的变化不触发设备重启
        let mut target = current.clone();
        target.no_punch = true;
        assert!(!device_restart_fields_differ(&current, &target));
    }
}
