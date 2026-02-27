use anyhow::Context;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::JNIEnv;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::runtime::Runtime;
use vnt_core::api::VntApi;
use vnt_core::context::config::Config;
use vnt_core::core::{NetworkManager, RegisterResponse};
use vnt_core::nat::NetInput;
use vnt_core::port_mapping::PortMapping;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_core::utils::task_control::TaskGroupManager;

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
            next_id: 1,
        })
    }
}

lazy_static::lazy_static! {
    static ref GLOBAL_STATE: Mutex<Option<GlobalState>> = Mutex::new(None);
}

/// 初始化JNI模块
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntManager_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
) -> jboolean {
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
}

/// 销毁JNI模块
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntManager_nativeDestroy(_env: JNIEnv, _class: JClass) {
    let mut state = GLOBAL_STATE.lock();
    *state = None;
}

/// 创建网络实例
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntManager_nativeCreateNetwork<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
) -> jlong {
    let result: anyhow::Result<i64> = (|| {
        let mut global_state = GLOBAL_STATE.lock();
        let state = global_state.as_mut().context("VNT not initialized")?;

        // 解析配置JSON
        let config_str: String = env.get_string(&config_json)?.into();
        let config = parse_config_from_json(&config_str)?;

        // 创建任务组
        let task_group_manager = TaskGroupManager::new();
        let (task_group, _task_group_guard) = task_group_manager
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

        // 保存实例
        state
            .network_managers
            .insert(id, Arc::new(Mutex::new(Some(network_manager))));
        state.task_group_managers.insert(id, task_group_manager);

        Ok(id)
    })();

    match result {
        Ok(id) => id,
        Err(e) => {
            let _ = env.throw(format!("Failed to create network: {:?}", e));
            -1
        }
    }
}

/// 注册网络
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeRegister<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
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
                    "gateway": network_addr.gateway.to_string(),
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
}

/// 启动TUN设备（Android使用，需要传入fd）
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeStartTun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    tun_fd: jint,
) -> jboolean {
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
            runtime.block_on(async { manager.start_tun_fd(tun_fd).await })?;
        }

        #[cfg(not(unix))]
        {
            let _ = tun_fd; // 避免未使用警告
            runtime.block_on(async { manager.start_tun().await })?;
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
}

/// 设置网络IP（非Android系统）
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeSetNetworkIp<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    ip: JString<'local>,
    prefix_len: jint,
) -> jboolean {
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

        #[cfg(not(target_os = "android"))]
        {
            runtime
                .block_on(async { manager.set_tun_network_ip(ip_addr, prefix_len as u8).await })?;
        }

        #[cfg(target_os = "android")]
        {
            let _ = (ip_addr, prefix_len); // 避免未使用警告
            anyhow::bail!("set_network_ip is not supported on Android");
        }

        Ok(())
    })();

    match result {
        Ok(_) => 1,
        Err(e) => {
            let _ = env.throw(format!("Failed to set network IP: {:?}", e));
            0
        }
    }
}

/// 获取VntApi实例
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeGetApi(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlong {
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
}

/// 检查是否为无TUN模式
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeIsNoTun(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
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

        Ok(manager.is_no_tun())
    })();

    match result {
        Ok(is_no_tun) => {
            if is_no_tun {
                1
            } else {
                0
            }
        }
        Err(e) => {
            let _ = env.throw(format!("Failed to check no_tun: {:?}", e));
            0
        }
    }
}

/// 关闭网络
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeStop(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jboolean {
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

        Ok(())
    })();

    match result {
        Ok(_) => 1,
        Err(e) => {
            let _ = env.throw(format!("Failed to stop network: {:?}", e));
            0
        }
    }
}

// ==================== VntApi 接口 ====================

/// 获取客户端列表
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetClientList<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
    let result: anyhow::Result<String> = (|| {
        let global_state = GLOBAL_STATE.lock();
        let state = global_state.as_ref().context("VNT not initialized")?;

        let api = state
            .vnt_apis
            .get(&api_handle)
            .context("Invalid API handle")?;

        let client_ips = api.client_ips();
        let json_array: Vec<_> = client_ips
            .into_iter()
            .map(|client| {
                serde_json::json!({
                    "ip": client.ip.to_string(),
                    "online": client.online,
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
}

/// 获取网络配置信息
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetNetwork<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
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
                "gateway": network.gateway.to_string(),
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
}

/// 获取NAT信息
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetNatInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
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
}

/// 获取服务器节点列表
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetServerList<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
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
}

/// 获取路由表
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetRouteTable<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
) -> jstring {
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
}

/// 检查目标IP是否直连
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeIsDirect<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jboolean {
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
}

/// 获取对端NAT信息
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetPeerNatInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
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
}

/// 获取丢包信息
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetPacketLoss<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
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
}

/// 获取流量信息
#[no_mangle]
pub extern "system" fn Java_com_vnt_VntApi_nativeGetTrafficInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    api_handle: jlong,
    ip: JString<'local>,
) -> jstring {
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
}

// ==================== 辅助函数 ====================

/// 从JSON字符串解析配置
fn parse_config_from_json(json_str: &str) -> anyhow::Result<Config> {
    #[derive(serde::Deserialize)]
    struct ConfigJson {
        server: Vec<String>,
        network_code: String,
        #[serde(default)]
        device_id: Option<String>,
        #[serde(default)]
        device_name: Option<String>,
        #[serde(default)]
        tun_name: Option<String>,
        #[serde(default)]
        ip: Option<Ipv4Addr>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        cert_mode: Option<String>,
        #[serde(default)]
        no_punch: bool,
        #[serde(default)]
        compress: bool,
        #[serde(default)]
        rtx: bool,
        #[serde(default)]
        fec: bool,
        #[serde(default)]
        input: Vec<NetInput>,
        #[serde(default)]
        output: Vec<ipnet::Ipv4Net>,
        #[serde(default)]
        no_nat: bool,
        #[serde(default)]
        no_tun: bool,
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
        tunnel_port: Option<u16>,
    }

    let cfg: ConfigJson = serde_json::from_str(json_str)?;

    let server_addrs: Vec<ProtocolAddress> = cfg
        .server
        .iter()
        .map(|s| {
            s.parse()
                .map_err(|e| anyhow::anyhow!("invalid server address '{}': {}", s, e))
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

    Ok(Config {
        server_addr: server_addrs,
        network_code: cfg.network_code,
        ip: cfg.ip,
        no_punch: cfg.no_punch,
        rtx: cfg.rtx,
        compress: cfg.compress,
        device_id,
        device_name,
        tun_name: cfg.tun_name,
        password: cfg.password,
        cert_mode,
        input: cfg.input,
        output: cfg.output,
        no_nat: cfg.no_nat,
        no_tun: cfg.no_tun,
        mtu: cfg.mtu,
        port_mapping,
        allow_port_mapping: cfg.allow_mapping,
        udp_stun,
        tcp_stun,
        fec: cfg.fec,
        tunnel_port: cfg.tunnel_port,
    })
}
