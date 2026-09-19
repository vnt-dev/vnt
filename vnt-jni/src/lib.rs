use anyhow::Context;
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(target_os = "android")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;
use tokio::runtime::Runtime;
use vnt_core::api::VntApi;
use vnt_core::context::config::{Config, DeviceMode, PeerAddress, PunchRule, TurnRule, VirtualIp};
use vnt_core::core::{NetworkManager, RegisterResponse};
use vnt_core::managed_config::Subscription;
use vnt_core::nat::{NetInput, SubnetMapping};
use vnt_core::port_mapping::PortMapping;
use vnt_core::protocol::control_message::{
    SubscriptionConfigAck, SubscriptionConfigApplyStatus, SubscriptionConfigEnvelope,
};
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_core::utils::task_control::{TaskGroupGuard, TaskGroupManager};

/// 全局状态管理
struct GlobalState {
    /// Tokio运行时（Arc包装以便多线程访问）
    runtime: Arc<Runtime>,
    /// 网络管理器实例
    network_managers: HashMap<i64, Arc<Mutex<Option<NetworkManager>>>>,
    /// API实例
    vnt_apis: HashMap<i64, VntApi>,
    /// 任务组管理器
    task_group_managers: HashMap<i64, TaskGroupManager>,
    /// 任务组守卫（drop 时会停止任务组，必须持有到 nativeStop）
    task_group_guards: HashMap<i64, TaskGroupGuard>,
    /// 下一个实例ID
    next_id: i64,
}

impl GlobalState {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            runtime: Arc::new(Runtime::new()?),
            network_managers: HashMap::new(),
            vnt_apis: HashMap::new(),
            task_group_managers: HashMap::new(),
            task_group_guards: HashMap::new(),
            next_id: 1,
        })
    }
}

lazy_static::lazy_static! {
    static ref GLOBAL_STATE: Mutex<Option<GlobalState>> = Mutex::new(None);
}

/// 从 panic payload 中提取错误消息
fn panic_message(e: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = e.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = e.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// 捕获闭包内的 panic，转为 Err(消息)，防止 panic 跨 FFI unwind 导致宿主 abort
fn catch_jni_panic<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce() -> T,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(panic_message)
}

fn encryption_state(local_key: Option<&str>, peer_key: Option<&str>) -> i32 {
    match (local_key, peer_key) {
        (Some(local), Some(peer)) if local == peer => 1,
        (None, None) => 2,
        (Some(_), None) => 3,
        (None, Some(_)) => 4,
        (Some(_), Some(_)) => 5,
    }
}

/// JNI 导出函数的 panic 防护：panic 时向 JVM 抛出异常并返回默认值
macro_rules! jni_guard {
    ($env:ident, $default_ret:expr, { $($body:tt)* }) => {{
        match catch_jni_panic(|| {
            $($body)*
        }) {
            Ok(v) => v,
            Err(msg) => {
                let _ = $env.throw(format!("VNT native panic: {}", msg));
                $default_ret
            }
        }
    }};
}

/// 初始化JNI模块
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntManager_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
    jni_guard!(env, 0, {
        let mut state = GLOBAL_STATE.lock();
        if state.is_some() {
            return 1; // 已经初始化
        }

        match GlobalState::new() {
            Ok(global_state) => {
                *state = Some(global_state);
                1
            }
            Err(e) => {
                let _ = env.throw(format!("Failed to initialize VNT: {:?}", e));
                0
            }
        }
    })
}

/// 销毁JNI模块
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntManager_nativeDestroy(_env: JNIEnv, _class: JClass) {
    let _ = catch_jni_panic(|| {
        let mut state = GLOBAL_STATE.lock();
        *state = None;
    });
}

/// 创建网络实例
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntManager_nativeCreateNetwork<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jlong {
    jni_guard!(env, -1, {
        let result: anyhow::Result<i64> = (|| {
            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;

            // 解析配置JSON
            let config_str: String = env.get_string(&config_json)?.into();
            let config = parse_config_from_json(&config_str)?;

            // 创建任务组
            let task_group_manager = TaskGroupManager::new();
            let (task_group, task_group_guard) = task_group_manager
                .create_task()
                .context("create task group")?;

            // 获取runtime的clone
            let runtime = state.runtime.clone();

            // 创建网络管理器
            let network_manager = runtime.block_on(async {
                NetworkManager::create_network(Box::new(config), task_group).await
            })?;

            // 分配ID
            let id = state.next_id;
            state.next_id += 1;

            // 保存实例（task_group_guard 必须随实例一直持有，drop 会停止整个任务组）
            state
                .network_managers
                .insert(id, Arc::new(Mutex::new(Some(network_manager))));
            state.task_group_managers.insert(id, task_group_manager);
            state.task_group_guards.insert(id, task_group_guard);

            Ok(id)
        })();

        match result {
            Ok(id) => id,
            Err(e) => {
                let _ = env.throw(format!("Failed to create network: {:?}", e));
                -1
            }
        }
    })
}

/// 注册网络
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeRegister<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let (network_manager_arc, runtime) = {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;

                let network_manager_arc = state
                    .network_managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();

                let runtime = state.runtime.clone();
                (network_manager_arc, runtime)
            };

            let response = {
                let mut manager_lock = network_manager_arc.lock();
                let manager = manager_lock
                    .as_mut()
                    .context("Network manager already destroyed")?;

                runtime.block_on(async { manager.register().await })?
            };

            match response {
                RegisterResponse::Success(network_addr) => {
                    let response_json = serde_json::json!({
                        "success": true,
                        "ip": network_addr.ip.to_string(),
                        "prefix_len": network_addr.prefix_len,
                        "gateway": network_addr.gateway.map(|gateway| gateway.to_string()),
                        "broadcast": network_addr.broadcast.to_string(),
                    });
                    Ok(response_json.to_string())
                }
                RegisterResponse::Failed(error_msg) => {
                    let response_json = serde_json::json!({
                        "success": false,
                        "error": error_msg.message,
                    });
                    Ok(response_json.to_string())
                }
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to register: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 启动TUN设备（Android使用，需要传入fd）
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeStartTun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    tun_fd: jint,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<()> = (|| {
            let (network_manager_arc, runtime) = {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;

                let network_manager_arc = state
                    .network_managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();

                let runtime = state.runtime.clone();
                (network_manager_arc, runtime)
            };

            let mut manager_lock = network_manager_arc.lock();
            let manager = manager_lock
                .as_mut()
                .context("Network manager already destroyed")?;

            #[cfg(unix)]
            {
                let tun_fd = if tun_fd < 0 { None } else { Some(tun_fd) };
                runtime.block_on(async { manager.start_device_fd(tun_fd).await })?;
            }

            #[cfg(not(unix))]
            {
                let _ = tun_fd; // 避免未使用警告
                runtime.block_on(async { manager.start_device().await })?;
            }

            Ok(())
        })();

        match result {
            Ok(_) => 1,
            Err(e) => {
                let _ = env.throw(format!("Failed to start TUN: {:?}", e));
                0
            }
        }
    })
}

/// 设置网络IP（非Android系统）
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeSetNetworkIp<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    ip: JString<'local>,
    prefix_len: jint,
) -> jboolean {
    #[cfg(target_os = "android")]
    {
        let _ = (handle, ip, prefix_len);
        let _ = env.throw("set_network_ip is not supported on Android");
        0
    }
    #[cfg(not(target_os = "android"))]
    {
        jni_guard!(env, 0, {
            let result: anyhow::Result<()> = (|| {
                let (network_manager_arc, runtime) = {
                    let mut global_state = GLOBAL_STATE.lock();
                    let state = global_state.as_mut().context("VNT not initialized")?;

                    let network_manager_arc = state
                        .network_managers
                        .get(&handle)
                        .context("Invalid handle")?
                        .clone();

                    let runtime = state.runtime.clone();
                    (network_manager_arc, runtime)
                };

                let ip_str: String = env.get_string(&ip)?.into();
                let ip_addr: Ipv4Addr = ip_str.parse().context("Invalid IP address")?;
                let manager_lock = network_manager_arc.lock();
                let manager = manager_lock
                    .as_ref()
                    .context("Network manager already destroyed")?;
                runtime.block_on(async {
                    manager
                        .set_device_network_ip(ip_addr, prefix_len as u8)
                        .await
                })?;
                Ok(())
            })();

            match result {
                Ok(_) => 1,
                Err(e) => {
                    let _ = env.throw(format!("Failed to set network IP: {:?}", e));
                    0
                }
            }
        })
    }
}

/// 获取VntApi实例
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeGetApi(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
    jni_guard!(env, -1, {
        let result: anyhow::Result<i64> = (|| {
            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;

            let network_manager_arc = state
                .network_managers
                .get(&handle)
                .context("Invalid handle")?
                .clone();

            let api = {
                let manager_lock = network_manager_arc.lock();
                let manager = manager_lock
                    .as_ref()
                    .context("Network manager already destroyed")?;
                manager.vnt_api()
            };

            state.vnt_apis.insert(handle, api);
            Ok(handle)
        })();

        match result {
            Ok(id) => id,
            Err(e) => {
                let _ = env.throw(format!("Failed to get API: {:?}", e));
                -1
            }
        }
    })
}

/// 检查是否为无TUN模式
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeIsNoTun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<bool> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let network_manager_arc = state
                .network_managers
                .get(&handle)
                .context("Invalid handle")?
                .clone();

            let manager_lock = network_manager_arc.lock();
            let manager = manager_lock
                .as_ref()
                .context("Network manager already destroyed")?;

            Ok(manager.device_mode() == DeviceMode::No)
        })();

        match result {
            Ok(is_no_device) => {
                if is_no_device {
                    1
                } else {
                    0
                }
            }
            Err(e) => {
                let _ = env.throw(format!("Failed to check device mode: {:?}", e));
                0
            }
        }
    })
}

/// 关闭网络
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<()> = (|| {
            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;

            // 停止任务组
            if let Some(task_group_manager) = state.task_group_managers.get(&handle) {
                task_group_manager.stop();
            }

            // 移除网络管理器
            state.network_managers.remove(&handle);
            state.vnt_apis.remove(&handle);
            state.task_group_managers.remove(&handle);
            // 最后释放守卫（drop 时会停止任务组）
            state.task_group_guards.remove(&handle);

            Ok(())
        })();

        match result {
            Ok(_) => 1,
            Err(e) => {
                let _ = env.throw(format!("Failed to stop network: {:?}", e));
                0
            }
        }
    })
}

// ==================== VntApi 接口 ====================

/// 获取客户端列表
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetClientList<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let (api, runtime) = {
                let global_state = GLOBAL_STATE.lock();
                let state = global_state.as_ref().context("VNT not initialized")?;
                (
                    state
                        .vnt_apis
                        .get(&api_handle)
                        .context("Invalid API handle")?
                        .clone(),
                    state.runtime.clone(),
                )
            };

            let local_clients: HashMap<_, _> = api
                .client_ips()
                .into_iter()
                .map(|client| (client.ip, (client.online, client.client_type)))
                .collect();
            let server_clients: HashMap<_, _> = runtime
                .block_on(api.server_rpc().client_list())
                .map(|response| {
                    response
                        .list
                        .into_iter()
                        .map(|client| (Ipv4Addr::from(client.ip), client))
                        .collect()
                })
                .unwrap_or_default();
            let local_key = api.get_config().and_then(|config| config.key_sign());
            let gossip_clients: HashMap<_, _> = api
                .gossip_node_list()
                .into_iter()
                .map(|node| (node.ip, node))
                .collect();
            let mut ips: Vec<_> = local_clients
                .keys()
                .chain(server_clients.keys())
                .chain(gossip_clients.keys())
                .copied()
                .collect();
            ips.sort_unstable();
            ips.dedup();

            let json_array: Vec<_> = ips
                .into_iter()
                .map(|ip| {
                    let server_client = server_clients.get(&ip);
                    let gossip_client = gossip_clients.get(&ip);
                    let route = api.find_route(&ip);
                    let has_route = route.is_some();
                    let direct = route
                        .as_ref()
                        .map(|route| route.metric() == 1)
                        .unwrap_or(false);
                    let route_protocol = route
                        .as_ref()
                        .map(|route| route.route_key().protocol().to_string());
                    let route_metric = route.as_ref().map(|route| route.metric());
                    let rtt = route.as_ref().map(|route| route.rtt());
                    let online = local_clients.get(&ip).map(|value| value.0).unwrap_or(false)
                        || server_client.map(|client| client.online).unwrap_or(false)
                        || has_route;
                    let packet_loss = api.packet_loss_info(&ip).map(|info| {
                        serde_json::json!({
                            "sent": info.sent,
                            "received": info.received,
                            "loss_rate": info.loss_rate,
                        })
                    });
                    let traffic = api.traffic_info(&ip).map(|info| {
                        serde_json::json!({
                            "tx_bytes": info.tx_bytes,
                            "rx_bytes": info.rx_bytes,
                        })
                    });
                    serde_json::json!({
                        "ip": ip.to_string(),
                        "name": server_client
                            .map(|client| client.name.as_str())
                            .filter(|name| !name.is_empty())
                            .or_else(|| gossip_client.map(|client| client.name.as_str()))
                            .unwrap_or(""),
                        "version": server_client
                            .map(|client| client.version.as_str())
                            .filter(|version| !version.is_empty())
                            .or_else(|| gossip_client.map(|client| client.version.as_str()))
                            .unwrap_or(""),
                        "advertised_subnets": gossip_client
                            .map(|client| client.advertised_subnets.iter().map(ToString::to_string).collect::<Vec<_>>())
                            .unwrap_or_default(),
                        "client_type": server_client
                            .map(|client| match client.client_type {
                                1 => "IKEV2",
                                2 => "WIREGUARD",
                                _ => "VNT",
                            })
                            .or_else(|| local_clients.get(&ip).map(|value| match value.1 {
                                vnt_core::protocol::control_message::ClientType::Ikev2 => "IKEV2",
                                vnt_core::protocol::control_message::ClientType::Wireguard => "WIREGUARD",
                                vnt_core::protocol::control_message::ClientType::Vnt => "VNT",
                            }))
                            .unwrap_or("VNT"),
                        "online": online,
                        "direct": direct,
                        "route_protocol": route_protocol,
                        "route_metric": route_metric,
                        "rtt": rtt,
                        "key_equal": server_client
                            .map(|client| if client.client_type != 0 {
                                0
                            } else {
                                encryption_state(local_key.as_deref(), client.key_sign.as_deref())
                            })
                            .unwrap_or(0),
                        "packet_loss": packet_loss,
                        "traffic": traffic,
                    })
                })
                .collect();
            Ok(serde_json::to_string(&json_array)?)
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get client list: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取网络配置信息
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetNetwork<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            if let Some(network) = api.network() {
                let json = serde_json::json!({
                    "ip": network.ip.to_string(),
                    "prefix_len": network.prefix_len,
                    "gateway": network.gateway.map(|gateway| gateway.to_string()),
                    "broadcast": network.broadcast.to_string(),
                });
                Ok(json.to_string())
            } else {
                Ok("null".to_string())
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get network info: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取NAT信息
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetNatInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            if let Some(nat_info) = api.nat_info() {
                let json = serde_json::json!({
                    "nat_type": format!("{:?}", nat_info.nat_type),
                    "public_ips": nat_info.public_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                    "ipv6": nat_info.ipv6.map(|ip| ip.to_string()),
                });
                Ok(json.to_string())
            } else {
                Ok("null".to_string())
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get NAT info: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取实际绑定的 P2P 隧道监听地址
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetTunnelListenAddresses<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;
            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let addrs: Vec<String> = api
                .p2p_listen_addrs()
                .into_iter()
                .map(|listener| listener.addr.to_string())
                .collect();
            Ok(serde_json::to_string(&addrs)?)
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get tunnel listen addresses: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取服务器节点列表
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetServerList<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let servers = api.server_node_list();
            let json_array: Vec<_> = servers
                .into_iter()
                .map(|server| {
                    serde_json::json!({
                        "server_id": server.server_id,
                        "server_addr": server.server_addr.to_string(),
                        "connected": server.connected,
                        "rtt": server.rtt,
                        "data_version": server.data_version,
                        "server_version": server.server_version,
                    })
                })
                .collect();
            Ok(serde_json::to_string(&json_array)?)
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get server list: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取路由表
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetRouteTable<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let route_table = api.route_table();
            let json_data: Vec<_> = route_table
                .into_iter()
                .map(|(ip, routes)| {
                    let routes_json: Vec<_> = routes
                        .into_iter()
                        .map(|route| {
                            serde_json::json!({
                                "route_key": route.route_key().to_string(),
                                "protocol": route.route_key().protocol().to_string(),
                                "metric": route.metric(),
                                "rtt": route.rtt(),
                            })
                        })
                        .collect();
                    serde_json::json!({
                        "ip": ip.to_string(),
                        "routes": routes_json,
                    })
                })
                .collect();

            Ok(serde_json::to_string(&json_data)?)
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get route table: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 检查目标IP是否直连
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeIsDirect<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<bool> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let ip_str: String = env.get_string(&ip)?.into();
            let ip_addr: Ipv4Addr = ip_str.parse().context("Invalid IP address")?;

            Ok(api.is_direct(&ip_addr))
        })();

        match result {
            Ok(is_direct) => {
                if is_direct {
                    1
                } else {
                    0
                }
            }
            Err(e) => {
                let _ = env.throw(format!("Failed to check direct: {:?}", e));
                0
            }
        }
    })
}

/// 获取对端NAT信息
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetPeerNatInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let ip_str: String = env.get_string(&ip)?.into();
            let ip_addr: Ipv4Addr = ip_str.parse().context("Invalid IP address")?;

            if let Some(nat_info) = api.peer_nat_info(&ip_addr) {
                let json = serde_json::json!({
                    "nat_type": format!("{:?}", nat_info.nat_type),
                    "public_ips": nat_info.public_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
                    "ipv6": nat_info.ipv6.map(|ip| ip.to_string()),
                });
                Ok(json.to_string())
            } else {
                Ok("null".to_string())
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get peer NAT info: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取丢包信息
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetPacketLoss<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let ip_str: String = env.get_string(&ip)?.into();
            let ip_addr: Ipv4Addr = ip_str.parse().context("Invalid IP address")?;

            if let Some(loss_info) = api.packet_loss_info(&ip_addr) {
                let json = serde_json::json!({
                    "ip": loss_info.ip.to_string(),
                    "sent": loss_info.sent,
                    "received": loss_info.received,
                    "loss_rate": loss_info.loss_rate,
                });
                Ok(json.to_string())
            } else {
                Ok("null".to_string())
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get packet loss: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取流量信息
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetTrafficInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;

            let api = state
                .vnt_apis
                .get(&api_handle)
                .context("Invalid API handle")?;

            let ip_str: String = env.get_string(&ip)?.into();
            let ip_addr: Ipv4Addr = ip_str.parse().context("Invalid IP address")?;

            if let Some(traffic_info) = api.traffic_info(&ip_addr) {
                let json = serde_json::json!({
                    "ip": traffic_info.ip.to_string(),
                    "tx_bytes": traffic_info.tx_bytes,
                    "rx_bytes": traffic_info.rx_bytes,
                });
                Ok(json.to_string())
            } else {
                Ok("null".to_string())
            }
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get traffic info: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

// ==================== 辅助函数 ====================

/// 解析订阅链接并通过 VNTS TLS 控制连接取得最新配置。返回 JSON，凭据不会
/// 出现在返回值或日志中；Java 层保留原订阅链接并在创建实例时传回。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntManager_nativeFetchSubscriptionConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    subscription: JString<'local>,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let link_value: String = env.get_string(&subscription)?.into();
            let link = Subscription::parse(&link_value)?;
            let runtime = GLOBAL_STATE
                .lock()
                .as_ref()
                .context("VNT not initialized")?
                .runtime
                .clone();
            let envelope = runtime.block_on(link.fetch())?;
            let mut config: toml::Value = toml::from_str(&envelope.toml)?;
            let config_table = config
                .as_table_mut()
                .context("subscription config root must be a TOML table")?;
            config_table.insert(
                "ip".to_string(),
                toml::Value::String(format!(
                    "{}/{}",
                    envelope.managed_ip, envelope.managed_prefix_len
                )),
            );
            config_table.insert(
                "device_name".to_string(),
                toml::Value::String(envelope.managed_device_name.clone()),
            );
            Ok(serde_json::json!({
                "revision": envelope.revision,
                "config": config,
                "server": link.server,
                "certMode": link.cert_mode,
                "networkCode": link.network_code,
                "deviceId": link.device_id,
                "managedIp": envelope.managed_ip,
                "managedPrefixLen": envelope.managed_prefix_len,
                "managedDeviceName": envelope.managed_device_name,
            })
            .to_string())
        })();
        match result {
            Ok(value) => match env.new_string(value) {
                Ok(value) => value.into_raw(),
                Err(error) => {
                    let _ = env.throw(format!("Failed to allocate result: {error}"));
                    std::ptr::null_mut()
                }
            },
            Err(error) => {
                let _ = env.throw(format!("Failed to fetch subscription config: {error:#}"));
                std::ptr::null_mut()
            }
        }
    })
}

fn subscription_update_json(value: SubscriptionConfigEnvelope) -> anyhow::Result<String> {
    let mut config = toml::from_str::<toml::Value>(&value.toml)?;
    let config_table = config
        .as_table_mut()
        .context("subscription config root must be a TOML table")?;
    config_table.insert(
        "ip".to_string(),
        toml::Value::String(format!("{}/{}", value.managed_ip, value.managed_prefix_len)),
    );
    config_table.insert(
        "device_name".to_string(),
        toml::Value::String(value.managed_device_name.clone()),
    );
    Ok(serde_json::json!({
        "revision": value.revision,
        "configToml": value.toml,
        "config": config,
        "sourceServerId": value.source_server_id,
        "contentSha256": hex::encode(value.content_sha256),
        "managedIp": value.managed_ip,
        "managedPrefixLen": value.managed_prefix_len,
        "managedDeviceName": value.managed_device_name,
        "serverVerified": true,
    })
    .to_string())
}

fn subscription_update_result<'local>(
    env: &mut JNIEnv<'local>,
    result: anyhow::Result<Option<String>>,
) -> jstring {
    match result {
        Ok(Some(value)) => env
            .new_string(value)
            .map(|value| value.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Ok(None) => std::ptr::null_mut(),
        Err(error) => {
            let _ = env.throw(format!("Failed to read subscription update: {error:#}"));
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeTakeSubscriptionConfigUpdate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<Option<String>> = (|| {
            let state = GLOBAL_STATE.lock();
            let api = state
                .as_ref()
                .context("VNT not initialized")?
                .vnt_apis
                .get(&handle)
                .context("Invalid API handle")?;
            let update = api
                .take_subscription_config_updates()
                .into_iter()
                .max_by_key(|value| value.revision);
            update.map(subscription_update_json).transpose()
        })();
        subscription_update_result(&mut env, result)
    })
}

/// Blocks until a verified managed configuration arrives or the instance stops.
/// The global JNI registry lock is deliberately released before awaiting.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeWaitSubscriptionConfigUpdate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<Option<String>> = (|| {
            let (api, runtime) = {
                let state = GLOBAL_STATE.lock();
                let state = state.as_ref().context("VNT not initialized")?;
                (
                    state
                        .vnt_apis
                        .get(&handle)
                        .context("Invalid API handle")?
                        .clone(),
                    state.runtime.clone(),
                )
            };
            let update = runtime
                .block_on(api.next_subscription_config_updates())
                .and_then(|updates| updates.into_iter().max_by_key(|value| value.revision));
            update.map(subscription_update_json).transpose()
        })();
        subscription_update_result(&mut env, result)
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeMarkSubscriptionAppliedLocally(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    revision: jlong,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<()> = (|| {
            let api = {
                let state = GLOBAL_STATE.lock();
                state
                    .as_ref()
                    .context("VNT not initialized")?
                    .vnt_apis
                    .get(&handle)
                    .context("Invalid API handle")?
                    .clone()
            };
            api.mark_subscription_applied_locally(revision.try_into().context("invalid revision")?)
        })();
        match result {
            Ok(()) => 1,
            Err(error) => {
                let _ = env.throw(format!(
                    "Failed to mark subscription revision as applied: {error:#}"
                ));
                0
            }
        }
    })
}

/// Applies a complete candidate through the same runtime controller used by
/// CLI/Web managed updates. Identity is always restored from the running
/// instance before validation and diffing.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeReconfigure<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    config_json: JString<'local>,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let json: String = env.get_string(&config_json)?.into();
            let mut candidate = parse_config_from_json(&json)?;
            let (api, runtime) = {
                let state = GLOBAL_STATE.lock();
                let state = state.as_ref().context("VNT not initialized")?;
                (
                    state
                        .vnt_apis
                        .get(&handle)
                        .context("Invalid API handle")?
                        .clone(),
                    state.runtime.clone(),
                )
            };
            let current = api
                .get_config()
                .context("Network instance is not running")?;
            candidate.network_code = current.network_code.clone();
            candidate.device_id = current.device_id.clone();
            candidate.managed = current.managed.clone();
            Ok(
                match runtime.block_on(api.reconfigure(Box::new(candidate))) {
                    Ok(report) => serde_json::json!({ "ok": true, "report": report }).to_string(),
                    Err(error) => serde_json::json!({ "ok": false, "error": error }).to_string(),
                },
            )
        })();
        match result {
            Ok(value) => env
                .new_string(value)
                .map(|value| value.into_raw())
                .unwrap_or(std::ptr::null_mut()),
            Err(error) => {
                let _ = env.throw(format!("Failed to reconfigure VNT: {error:#}"));
                std::ptr::null_mut()
            }
        }
    })
}

#[derive(serde::Deserialize)]
struct SubscriptionAckJson {
    revision: u64,
    status: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    overridden_fields: Vec<String>,
    #[serde(default)]
    apply_mode: String,
    #[serde(default)]
    changed_fields: Vec<String>,
    #[serde(default)]
    effective_device_name: String,
    effective_ip: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    effective_prefix_len: u32,
    #[serde(default)]
    effective_output: Vec<ipnet::Ipv4Net>,
    #[serde(default)]
    allow_ikev2: bool,
    #[serde(default)]
    allow_wireguard: bool,
    #[serde(default)]
    allow_mapping: bool,
    #[serde(default)]
    effective_config_sha256: String,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntApi_nativeAckSubscriptionConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    ack_json: JString<'local>,
) -> jboolean {
    jni_guard!(env, 0, {
        let result: anyhow::Result<()> = (|| {
            let json: String = env.get_string(&ack_json)?.into();
            let ack: SubscriptionAckJson = serde_json::from_str(&json)?;
            let status = match ack.status.to_ascii_lowercase().as_str() {
                "staged" => SubscriptionConfigApplyStatus::SubscriptionConfigStaged,
                "applied" => SubscriptionConfigApplyStatus::SubscriptionConfigApplied,
                "error" => SubscriptionConfigApplyStatus::SubscriptionConfigError,
                "superseded" => SubscriptionConfigApplyStatus::SubscriptionConfigSuperseded,
                _ => anyhow::bail!("status must be staged, applied, superseded, or error"),
            };
            let (api, runtime) = {
                let state = GLOBAL_STATE.lock();
                let state = state.as_ref().context("VNT not initialized")?;
                (
                    state
                        .vnt_apis
                        .get(&handle)
                        .context("Invalid API handle")?
                        .clone(),
                    state.runtime.clone(),
                )
            };
            let mut protocol_ack =
                SubscriptionConfigAck::new(ack.revision, status, ack.error, ack.overridden_fields);
            protocol_ack.apply_mode = ack.apply_mode;
            protocol_ack.changed_fields = ack.changed_fields;
            protocol_ack.effective_device_name = ack.effective_device_name;
            protocol_ack.effective_ip = ack.effective_ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
            protocol_ack.effective_prefix_len = ack.effective_prefix_len;
            protocol_ack.effective_output = ack.effective_output;
            protocol_ack.allow_ikev2 = ack.allow_ikev2;
            protocol_ack.allow_wireguard = ack.allow_wireguard;
            protocol_ack.allow_mapping = ack.allow_mapping;
            if !ack.effective_config_sha256.is_empty() {
                protocol_ack.effective_config_sha256 =
                    hex::decode(&ack.effective_config_sha256).context("invalid config SHA-256")?;
                if protocol_ack.effective_config_sha256.len() != 32 {
                    anyhow::bail!("config SHA-256 must be 32 bytes");
                }
            }
            runtime.block_on(api.acknowledge_subscription_config(protocol_ack))?;
            Ok(())
        })();
        match result {
            Ok(()) => 1,
            Err(error) => {
                let _ = env.throw(format!(
                    "Failed to acknowledge subscription config: {error:#}"
                ));
                0
            }
        }
    })
}

/// 从JSON字符串解析配置
fn parse_config_from_json(json_str: &str) -> anyhow::Result<Config> {
    #[derive(serde::Deserialize)]
    struct ConfigJson {
        #[serde(default)]
        server: Vec<String>,
        #[serde(default)]
        peer_address: Vec<String>,
        #[serde(default)]
        turn: Vec<String>,
        #[serde(default)]
        punch_model: Vec<String>,
        #[serde(default)]
        network_code: String,
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        device_name: Option<String>,
        #[serde(default)]
        tun_name: Option<String>,
        #[serde(default)]
        outbound_interface: Option<String>,
        #[serde(default)]
        ip: Option<VirtualIp>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        cert_mode: Option<String>,
        #[serde(default)]
        no_punch: bool,
        #[serde(default)]
        no_broadcast: bool,
        #[serde(default)]
        allow_ikev2: bool,
        #[serde(default)]
        allow_wireguard: bool,
        #[serde(default)]
        compress: bool,
        #[serde(default)]
        rtx: bool,
        #[serde(default)]
        fec: bool,
        #[serde(default)]
        input: Vec<NetInput>,
        #[serde(default)]
        subnet_mapping: Vec<SubnetMapping>,
        #[serde(default)]
        output: Vec<ipnet::Ipv4Net>,
        #[serde(default)]
        auto_sync_subnet: bool,
        #[serde(default)]
        no_nat: bool,
        #[serde(default, deserialize_with = "deserialize_device_mode")]
        device_mode: DeviceMode,
        #[serde(default)]
        mtu: Option<u16>,
        #[serde(default)]
        port_mapping: Vec<String>,
        #[serde(default)]
        allow_mapping: bool,
        #[serde(default)]
        udp_stun: Vec<String>,
        #[serde(default)]
        tcp_stun: Vec<String>,
        #[serde(default)]
        tunnel_addr: Vec<SocketAddr>,
        #[serde(default)]
        tunnel_port: Option<u16>,
        #[serde(default)]
        event_script: Option<String>,
        #[serde(default)]
        subscription: Option<String>,
        #[serde(default)]
        subscription_revision: u64,
        #[serde(default)]
        subscription_instance_id: Option<String>,
    }

    let cfg: ConfigJson = serde_json::from_str(json_str)?;
    let mut subscription = cfg
        .subscription
        .as_deref()
        .map(Subscription::parse)
        .transpose()?;
    if let (Some(link), Some(instance_id)) =
        (&mut subscription, cfg.subscription_instance_id.as_deref())
    {
        let instance_id = hex::decode(instance_id)
            .context("subscription_instance_id 必须是 64 位十六进制字符串")?;
        link.set_instance_id(instance_id)?;
    }

    let server_addrs: Vec<ProtocolAddress> = cfg
        .server
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow::anyhow!("invalid server address '{}': {}", s, e))
        })
        .collect::<anyhow::Result<_>>()?;

    let peer_address: Vec<PeerAddress> = cfg
        .peer_address
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid peer address '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let turn: Vec<TurnRule> = cfg
        .turn
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid turn rule '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let punch_model: Vec<PunchRule> = cfg
        .punch_model
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid punch_model rule '{}': {}", value, error))
        })
        .collect::<anyhow::Result<_>>()?;

    let port_mapping: Vec<PortMapping> = cfg
        .port_mapping
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow::anyhow!("invalid port_mapping '{}': {}", s, e))
        })
        .collect::<anyhow::Result<_>>()?;

    let cert_mode = match cfg.cert_mode.as_deref() {
        Some(s) => s
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid cert_mode '{}': {}", s, e))?,
        None => CertValidationMode::InsecureSkipVerification,
    };

    let device_id = match cfg.device_id {
        Some(id) => id,
        None => vnt_core::utils::device_id::get_device_id()
            .map_err(|e| anyhow::anyhow!("failed to get device_id: {}", e))?,
    };

    let device_name = cfg.device_name.unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|v| v.into_string().ok())
            .unwrap_or_default()
    });

    let mut udp_stun = cfg.udp_stun;
    for x in udp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }

    let mut tcp_stun = cfg.tcp_stun;
    for x in tcp_stun.iter_mut() {
        if !x.contains(':') {
            x.push_str(":3478");
        }
    }

    let mut config = Config {
        server_addr: server_addrs,
        peer_address,
        turn,
        punch_model,
        network_code: cfg.network_code,
        ip: cfg.ip,
        no_punch: cfg.no_punch,
        no_broadcast: cfg.no_broadcast,
        allow_ikev2: cfg.allow_ikev2,
        allow_wireguard: cfg.allow_wireguard,
        rtx: cfg.rtx,
        compress: cfg.compress,
        device_id,
        device_name,
        tun_name: cfg.tun_name,
        outbound_interface: cfg.outbound_interface,
        password: cfg.password,
        cert_mode,
        input: cfg.input,
        subnet_mapping: cfg.subnet_mapping,
        output: cfg.output,
        auto_sync_subnet: cfg.auto_sync_subnet,
        no_nat: cfg.no_nat,
        device_mode: cfg.device_mode,
        mtu: cfg.mtu,
        port_mapping,
        allow_port_mapping: cfg.allow_mapping,
        udp_stun,
        tcp_stun,
        fec: cfg.fec,
        tunnel_addr: cfg.tunnel_addr,
        tunnel_port: cfg.tunnel_port,
        event_script: cfg.event_script,
        managed: None,
    };
    if let Some(link) = subscription {
        // A managed instance is identified exclusively by its subscription
        // link. Ignore any identity supplied by the local JSON/TOML merge.
        config.network_code.clone_from(&link.network_code);
        config.device_id.clone_from(&link.device_id);
        config.managed = Some(link.registration(cfg.subscription_revision));
    }
    Ok(config)
}

fn deserialize_device_mode<'de, D>(deserializer: D) -> Result<DeviceMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    #[cfg(target_os = "android")]
    {
        // Android VPN supports only a TUN or no-device runtime.  Treat every
        // legacy/desktop-specific value (including tap) as TUN instead of
        // rejecting an otherwise valid profile.
        Ok(if value.trim().eq_ignore_ascii_case("no") {
            DeviceMode::No
        } else {
            DeviceMode::Tun
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeWaitTunRebuild<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    #[cfg(target_os = "android")]
    {
        jni_guard!(env, std::ptr::null_mut(), {
            let result: anyhow::Result<String> = (|| {
                let (coordinator, runtime) = {
                    let state = GLOBAL_STATE.lock();
                    let state = state.as_ref().context("VNT not initialized")?;
                    let manager = state
                        .network_managers
                        .get(&handle)
                        .context("Invalid handle")?
                        .clone();
                    let manager = manager.lock();
                    let manager = manager
                        .as_ref()
                        .context("Network manager already destroyed")?;
                    (manager.tun_rebuild_coordinator(), state.runtime.clone())
                };
                Ok(serde_json::to_string(
                    &runtime.block_on(coordinator.wait_next())?,
                )?)
            })();
            match result {
                Ok(request) => env
                    .new_string(request)
                    .map(|value| value.into_raw())
                    .unwrap_or_default(),
                Err(error) => {
                    let _ = env.throw(format!("Failed to wait for TUN rebuild: {error:#}"));
                    std::ptr::null_mut()
                }
            }
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = handle;
        let _ = env.throw("Android TUN rebuild is not supported on this platform");
        std::ptr::null_mut()
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeReplaceTun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    request_id: jlong,
    tun_fd: jint,
) -> jboolean {
    #[cfg(target_os = "android")]
    {
        jni_guard!(env, 0, {
            if tun_fd < 0 {
                let _ = env.throw("TUN replacement requires a detached fd");
                return 0;
            }
            // SAFETY: Java transfers a detached ParcelFileDescriptor exactly once.
            let tun_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
            let result: anyhow::Result<()> = (|| {
                let (manager, runtime) = {
                    let state = GLOBAL_STATE.lock();
                    let state = state.as_ref().context("VNT not initialized")?;
                    (
                        state
                            .network_managers
                            .get(&handle)
                            .context("Invalid handle")?
                            .clone(),
                        state.runtime.clone(),
                    )
                };
                let manager = manager.lock();
                let manager = manager
                    .as_ref()
                    .context("Network manager already destroyed")?;
                runtime.block_on(manager.replace_tun_task(request_id as u64, tun_fd))
            })();
            match result {
                Ok(()) => 1,
                Err(error) => {
                    let _ = env.throw(format!("Failed to replace TUN: {error:#}"));
                    0
                }
            }
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (handle, request_id, tun_fd);
        let _ = env.throw("Android TUN rebuild is not supported on this platform");
        0
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeRejectTunRebuild<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    request_id: jlong,
    reason: JString<'local>,
) -> jboolean {
    #[cfg(target_os = "android")]
    {
        jni_guard!(env, 0, {
            let result: anyhow::Result<()> = (|| {
                let (manager, runtime) = {
                    let state = GLOBAL_STATE.lock();
                    let state = state.as_ref().context("VNT not initialized")?;
                    (
                        state
                            .network_managers
                            .get(&handle)
                            .context("Invalid handle")?
                            .clone(),
                        state.runtime.clone(),
                    )
                };
                let reason: String = env.get_string(&reason)?.into();
                let manager = manager.lock();
                let manager = manager
                    .as_ref()
                    .context("Network manager already destroyed")?;
                runtime.block_on(manager.reject_tun_rebuild(request_id as u64, reason))
            })();
            match result {
                Ok(()) => 1,
                Err(error) => {
                    let _ = env.throw(format!("Failed to reject TUN rebuild: {error:#}"));
                    0
                }
            }
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (handle, request_id, reason);
        let _ = env.throw("Android TUN rebuild is not supported on this platform");
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIPTION: &str = "vnt2://join/1/eyJ2IjoxLCJzZXJ2ZXIiOiJ0Y3A6Ly8xMjcuMC4wLjE6Mjk4NzIiLCJjZXJ0X21vZGUiOiJzdGFuZGFyZCIsIm5ldHdvcmtfY29kZSI6Im1hbmFnZWQtbmV0IiwiZGV2aWNlX2lkIjoibWFuYWdlZC1kZXYiLCJjcmVkZW50aWFsX2tleSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ";

    #[test]
    fn subscription_identity_overrides_json_values() {
        let config = parse_config_from_json(&format!(
            r#"{{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"json-net",
                "device_id":"json-dev",
                "subscription":"{SUBSCRIPTION}"
            }}"#
        ))
        .unwrap();
        assert_eq!(config.network_code, "managed-net");
        assert_eq!(config.device_id, "managed-dev");
        let managed = config.managed.unwrap();
        assert_eq!(managed.network_code, "managed-net");
        assert_eq!(managed.device_id, "managed-dev");
    }

    #[test]
    fn catch_jni_panic_returns_value_unchanged() {
        let result = catch_jni_panic(|| 42);
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn catch_jni_panic_captures_str_message() {
        let result: Result<(), String> = catch_jni_panic(|| panic!("boom"));
        let err = result.unwrap_err();
        assert!(err.contains("boom"), "unexpected message: {}", err);
    }

    #[test]
    fn catch_jni_panic_captures_string_message() {
        let result: Result<(), String> = catch_jni_panic(|| panic!("{}", "kaboom"));
        assert_eq!(result.unwrap_err(), "kaboom");
    }

    #[test]
    fn maps_peer_encryption_states() {
        assert_eq!(encryption_state(Some("same"), Some("same")), 1);
        assert_eq!(encryption_state(None, None), 2);
        assert_eq!(encryption_state(Some("local"), None), 3);
        assert_eq!(encryption_state(None, Some("peer")), 4);
        assert_eq!(encryption_state(Some("local"), Some("peer")), 5);
    }

    #[test]
    fn parses_peer_addresses_from_json() {
        let config = parse_config_from_json(
            r#"{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"test",
                "peer_address":["127.0.0.1:30001","udp://127.0.0.1:30002","dynamic://peers.example.com"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.peer_address.len(), 3);
        assert_eq!(config.peer_address[0].to_string(), "127.0.0.1:30001");
        assert_eq!(config.peer_address[1].to_string(), "udp://127.0.0.1:30002");
        assert_eq!(
            config.peer_address[2].to_string(),
            "dynamic://peers.example.com"
        );
        assert!(!config.no_broadcast);
    }

    #[test]
    fn parses_serverless_cidr_and_plain_ip_default() {
        let config = parse_config_from_json(
            r#"{
                "server":[],
                "network_code":"test",
                "ip":"10.26.0.2/20"
            }"#,
        )
        .unwrap();
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/20");
        assert!(config.check().is_ok());

        let config = parse_config_from_json(
            r#"{
                "network_code":"test",
                "ip":"10.26.0.2"
            }"#,
        )
        .unwrap();
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/24");
    }

    #[test]
    fn rejects_serverless_json_without_virtual_ip() {
        let config = parse_config_from_json(r#"{"network_code":"test"}"#).unwrap();
        assert!(config.check().is_err());
    }

    #[test]
    fn parses_tunnel_addresses_from_json() {
        let mut config = parse_config_from_json(
            r#"{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"test",
                "tunnel_addr":["192.168.1.10:29873","[2001:db8::10]:29873"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.tunnel_addr.len(), 2);
        assert_eq!(config.tunnel_port, None);
        config.normalize().unwrap();
    }

    #[test]
    fn parses_broadcast_and_relay_switches_from_json() {
        let config = parse_config_from_json(
            r#"{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"test",
                "no_broadcast":true,
                "allow_ikev2":true,
                "allow_wireguard":true
            }"#,
        )
        .unwrap();
        assert!(config.no_broadcast);
        assert!(config.allow_ikev2);
        assert!(config.allow_wireguard);
    }

    #[test]
    fn parses_turn_rules_from_json() {
        let config = parse_config_from_json(
            r#"{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"test",
                "turn":["10.26.0.0/16,10.26.0.2","10.26.1.9,10.26.0.3"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.turn.len(), 2);
        assert_eq!(config.turn[0].to_string(), "10.26.0.0/16,10.26.0.2");
        assert_eq!(config.turn[1].to_string(), "10.26.1.9,10.26.0.3");
    }

    #[test]
    fn parses_punch_model_rules_from_json() {
        let config = parse_config_from_json(
            r#"{
                "server":["quic://127.0.0.1:29872"],
                "network_code":"test-net",
                "punch_model":["10.26.0.2,IPv4Udp","10.26.1.0/24,IPv4Tcp,IPv6Udp"]
            }"#,
        )
        .unwrap();
        assert_eq!(config.punch_model.len(), 2);
        assert_eq!(config.punch_model[0].to_string(), "10.26.0.2,IPv4Udp");
        assert_eq!(
            config.punch_model[1].to_string(),
            "10.26.1.0/24,IPv4Tcp,IPv6Udp"
        );
    }

    #[test]
    fn parses_exit_subnet_mapping_from_json() {
        let mut config = parse_config_from_json(
            r#"{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"test",
                "output":["192.168.1.0/24"],
                "subnet_mapping":["192.168.2.2/32,192.168.1.3/32"],
                "auto_sync_subnet":true
            }"#,
        )
        .unwrap();
        assert_eq!(
            config.subnet_mapping[0].to_string(),
            "192.168.2.2/32,192.168.1.3/32"
        );
        assert!(config.auto_sync_subnet);
        config.normalize().unwrap();
    }
}
