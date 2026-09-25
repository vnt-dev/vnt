use anyhow::Context;
use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jint, jlong, jstring};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use vnt_core::api::VntApi;
use vnt_core::context::config::{Config, DeviceMode, PeerAddress, PunchRule, TurnRule, VirtualIp};
use vnt_core::log_manager::LogManager;
use vnt_core::managed_config::Subscription;
use vnt_core::nat::{NetInput, SubnetMapping};
use vnt_core::network_info::{ChangeOutcome, RuntimeChange, RuntimeChangeManager, RuntimeEvent};
use vnt_core::port_mapping::PortMapping;
use vnt_core::tls::verifier::CertValidationMode;
use vnt_core::tunnel_core::server::transport::config::ProtocolAddress;
use vnt_core::utils::task_control::TaskGroupManager;

/// 全局状态管理
struct GlobalState {
    /// Tokio运行时（Arc包装以便多线程访问）
    runtime: Arc<Runtime>,
    /// 配置管理器：订阅连接与组网实例的生命周期持有者
    managers: HashMap<i64, Arc<tokio::sync::Mutex<RuntimeChangeManager>>>,
    /// 按 handle 管理的实例任务组句柄：停止流程经它停机，避免与
    /// next_event 监听线程争抢管理器锁（见 nativeStop）
    task_groups: HashMap<i64, TaskGroupManager>,
    /// API实例
    vnt_apis: HashMap<i64, VntApi>,
    /// 按 handle 管理的实例日志（每个实例保留最近 50 条）
    logs: Arc<LogManager>,
    /// nextEvent 收到的最新快照，等待 applyRuntimeChange 消费
    pending_changes: HashMap<i64, RuntimeChange>,
    /// 下一个实例ID
    next_id: i64,
}

impl GlobalState {
    fn new() -> anyhow::Result<Self> {
        Ok(Self {
            runtime: Arc::new(Runtime::new()?),
            managers: HashMap::new(),
            task_groups: HashMap::new(),
            vnt_apis: HashMap::new(),
            logs: Arc::new(LogManager::new()),
            pending_changes: HashMap::new(),
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
        let mut created_log_id: Option<i64> = None;
        let result: anyhow::Result<i64> = (|| {
            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;
            let runtime = state.runtime.clone();

            // 提前分配句柄：实例日志从创建第一步起即可写入与查询
            let id = state.next_id;
            state.next_id += 1;
            created_log_id = Some(id);
            let instance_log = state.logs.instance(&id.to_string());

            // 解析配置JSON
            let config_str: String = env.get_string(&config_json)?.into();
            #[derive(serde::Deserialize)]
            struct SubscriptionBootstrap {
                subscription: Option<String>,
                #[serde(default)]
                subscription_instance_id: Option<String>,
            }
            let bootstrap: SubscriptionBootstrap = serde_json::from_str(&config_str)?;
            let mut subscription = bootstrap
                .subscription
                .as_deref()
                .map(Subscription::parse)
                .transpose()?;
            if let Some(link) = &mut subscription {
                // 任务级稳定实例 ID：跨进程重启保持服务端视角的身份一致
                if let Some(hex_id) = bootstrap.subscription_instance_id.as_deref() {
                    let instance_id = hex::decode(hex_id)
                        .context("subscription_instance_id 必须是 64 位十六进制字符串")?;
                    link.set_instance_id(instance_id)?;
                }
            }
            let local_config = parse_config_from_json(&config_str, subscription.is_some())?;

            // 配置管理器：订阅模式内部等待服务端首份配置并启动首个组网
            // 实例；虚拟网卡由宿主持有 fd 后经 nativeStartTun 启动
            let manager = runtime.block_on(RuntimeChangeManager::new(
                local_config,
                subscription,
                instance_log,
            ))?;
            let manager = Arc::new(tokio::sync::Mutex::new(manager));
            // 任务组句柄随管理器一并登记：停止流程经它停机，避免与
            // next_event 监听线程争抢管理器锁（见 nativeStop）
            let task_groups = runtime.block_on(async { manager.lock().await.task_groups() });
            state.managers.insert(id, manager);
            state.task_groups.insert(id, task_groups);

            Ok(id)
        })();

        match result {
            Ok(id) => id,
            Err(e) => {
                // 创建失败：清理实例日志，避免按 handle 堆积
                if let Some(id) = created_log_id
                    && let Some(state) = GLOBAL_STATE.lock().as_mut()
                {
                    state.logs.remove(&id.to_string());
                }
                let _ = env.throw(format!("Failed to create network: {:?}", e));
                -1
            }
        }
    })
}

/// 获取实例最近日志（每个实例保留最后 50 条）
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeGetLogs(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let logs = {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;
                state.logs.clone()
            };
            Ok(serde_json::to_string(&logs.logs(&handle.to_string()))?)
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let _ = env.throw(format!("Failed to get logs: {:?}", e));
                JObject::null().into_raw()
            }
        }
    })
}

/// 获取当前网络（网段信息）。create_network 已在后台连接服务器并注册：
/// 网络已配置时立即返回，否则等待注册结果。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeGetNetwork<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let (manager, runtime) = {
                let global_state = GLOBAL_STATE.lock();
                let state = global_state.as_ref().context("VNT not initialized")?;
                let manager = state
                    .managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();
                (manager, state.runtime.clone())
            };

            let network = runtime.block_on(async {
                let guard = manager.lock().await;
                guard.current_network().await
            })?;

            let response_json = serde_json::json!({
                "success": true,
                "ip": network.ip.to_string(),
                "prefix_len": network.prefix_len,
                "gateway": network.gateway.map(|gateway| gateway.to_string()),
                "broadcast": network.broadcast.to_string(),
            });
            Ok(response_json.to_string())
        })();

        match result {
            Ok(json_str) => env
                .new_string(json_str)
                .unwrap_or_else(|_| JObject::null().into())
                .into_raw(),
            Err(e) => {
                let response_json = serde_json::json!({
                    "success": false,
                    "error": format!("{e:?}"),
                });
                let json_str = response_json.to_string();
                env.new_string(json_str)
                    .unwrap_or_else(|_| JObject::null().into())
                    .into_raw()
            }
        }
    })
}

/// 启动TUN设备（Android使用，需要传入fd）
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeStartTun<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) -> jboolean {
    #[cfg(not(unix))]
    let _ = tun_fd;
    jni_guard!(env, 0, {
        let result: anyhow::Result<()> = (|| {
            let (manager, runtime) = {
                let global_state = GLOBAL_STATE.lock();
                let state = global_state.as_ref().context("VNT not initialized")?;
                let manager = state
                    .managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();
                (manager, state.runtime.clone())
            };

            #[cfg(unix)]
            let tun_fd = if tun_fd < 0 {
                None
            } else {
                // SAFETY: Java transfers a detached descriptor exactly once.
                Some(unsafe { OwnedFd::from_raw_fd(tun_fd) })
            };
            // 无设备模式下 fd 没有消费者，start_device_fd 内部会关闭它
            #[cfg(unix)]
            runtime.block_on(async {
                let mut guard = manager.lock().await;
                guard.start_device_fd(tun_fd).await
            })?;
            #[cfg(not(unix))]
            runtime.block_on(async {
                let mut guard = manager.lock().await;
                guard.start_device().await
            })?;

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

/// Blocks until the next runtime event. Mirrors
/// `RuntimeChangeManager::next_event`, the same entry the PC-side cli/web
/// loops drive: the frontend breaks out of its change loop on
/// `instance_stopped` and applies the snapshot carried by a `changed` event.
///
/// The `changed` event additionally carries the handling plan so the host
/// can decide upfront whether a new VPN interface — and therefore a new TUN
/// fd — is required:
/// - `needs_vpn_rebuild`: NIC fields (virtual IP/MTU/routes/tun name)
///   changed; the host re-establishes its VPN interface and applies the
///   same snapshot via `nativeApplyRuntimeChangeFd`.
/// - `needs_instance_rebuild`: fields that only take effect by rebuilding
///   the instance (password/outbound interface); native rebuilds the
///   instance internally and the subscription link stays up. With a device
///   the new fd is still required, so treat it like `needs_vpn_rebuild`.
///
/// Returns `{"event":"instance_stopped"}` or
/// `{"event":"changed","change":{"config":{...},"routes":[...],
/// "needs_vpn_rebuild":bool,"needs_instance_rebuild":bool}}`.
/// The snapshot is kept native-side and is consumed by
/// nativeApplyRuntimeChange/nativeApplyRuntimeChangeFd.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeNextEvent<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let result: anyhow::Result<String> = (|| {
            let (manager, runtime) = {
                let state = GLOBAL_STATE.lock();
                let state = state.as_ref().context("VNT not initialized")?;
                let manager = state
                    .managers
                    .get(&handle)
                    .context("Invalid network handle")?
                    .clone();
                (manager, state.runtime.clone())
            };
            // 同一次持锁内取事件与处理计划，避免两者之间状态变化
            let (response, pending) = runtime.block_on(async {
                let mut guard = manager.lock().await;
                match guard.next_event().await? {
                    RuntimeEvent::InstanceStopped => Ok::<_, anyhow::Error>((
                        serde_json::json!({
                            "event": "instance_stopped",
                        }),
                        None,
                    )),
                    RuntimeEvent::Changed(change) => {
                        let plan = guard.inspect_change(&change);
                        let response = serde_json::json!({
                            "event": "changed",
                            "change": {
                                "config": {
                                    "network_code": change.config.network_code,
                                    "device_id": change.config.device_id,
                                    "device_name": change.config.device_name,
                                    "ip": change.config.ip.as_ref().map(ToString::to_string),
                                    "mtu": change.config.mtu,
                                },
                                "routes": change.routes,
                                "needs_vpn_rebuild": plan.vpn_rebuild,
                                "needs_instance_rebuild": plan.instance_rebuild,
                            },
                        });
                        Ok((response, Some(*change)))
                    }
                }
            })?;
            if let Some(change) = pending {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;
                state.pending_changes.insert(handle, change);
            }
            Ok(response.to_string())
        })();
        match result {
            Ok(value) => env
                .new_string(value)
                .map(|value| value.into_raw())
                .unwrap_or_default(),
            Err(error) => {
                let _ = env.throw(format!("Failed to wait for runtime event: {error:#}"));
                std::ptr::null_mut()
            }
        }
    })
}

/// 应用 nextEvent 交付的最新快照，返回结果 JSON。`tun_fd` 为宿主新建的
/// TUN fd（None 表示未携带）：携带 fd 且有虚拟网卡时整体重建 fd 型设备；
/// 未携带 fd 时网卡相关变更无法应用（返回 need_fd/rebuild，提示宿主忽略
/// 了 nextEvent 携带的标志，应改用携带 fd 的入口）。
fn apply_pending_change(env: &mut JNIEnv, handle: jlong, tun_fd: Option<jint>) -> jstring {
    let result: anyhow::Result<String> = (|| {
        let (manager, runtime) = {
            let global_state = GLOBAL_STATE.lock();
            let state = global_state.as_ref().context("VNT not initialized")?;
            let manager = state
                .managers
                .get(&handle)
                .context("Invalid handle")?
                .clone();
            (manager, state.runtime.clone())
        };
        let change = {
            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;
            state.pending_changes.remove(&handle)
        }
        .context("没有待应用的运行期变更，请先调用 nextEvent")?;

        #[cfg(unix)]
        let tun_fd = tun_fd.map(|tun_fd| {
            // SAFETY: Java transfers a detached descriptor exactly once; this
            // native entry takes ownership from here on. 无设备模式下 fd
            // 没有消费者，由管理器内部关闭。
            unsafe { OwnedFd::from_raw_fd(tun_fd) }
        });
        #[cfg(not(unix))]
        let _ = tun_fd;
        #[cfg(unix)]
        let outcome = runtime.block_on(async {
            let mut guard = manager.lock().await;
            guard.apply_change_fd(&change, tun_fd).await
        });
        #[cfg(not(unix))]
        let outcome = runtime.block_on(async {
            let mut guard = manager.lock().await;
            guard.apply_change(&change).await
        });
        match outcome? {
            ChangeOutcome::Applied => {}
            // 宿主未按 nextEvent 的标志提供新 fd：需要先重建 VPN 接口
            ChangeOutcome::Rebuild => {
                return Ok(serde_json::json!({
                    "action": "rebuild",
                    "config_ip": change.config.ip.as_ref().map(ToString::to_string),
                })
                .to_string());
            }
            ChangeOutcome::NeedFd(error) => {
                return Ok(serde_json::json!({
                    "action": "need_fd",
                    "error": error,
                })
                .to_string());
            }
        }
        Ok(serde_json::json!({
            "action": "applied",
        })
        .to_string())
    })();
    match result {
        Ok(value) => env
            .new_string(value)
            .map(|value| value.into_raw())
            .unwrap_or_default(),
        Err(error) => {
            let _ = env.throw(format!("Failed to apply runtime change: {error:#}"));
            std::ptr::null_mut()
        }
    }
}

/// 应用 nextEvent 返回的最新快照（不携带 TUN fd）：纯策略/服务器类变更
/// 原地生效。nextEvent 的标志（needs_vpn_rebuild/needs_instance_rebuild）
/// 为 true 时说明快照需要新接口，应改用
/// [`Java_com_vnt_VntNetwork_nativeApplyRuntimeChangeFd]。
///
/// 返回 JSON：`{"action":"applied"|"need_fd"|"rebuild", ...}`。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeApplyRuntimeChange<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        apply_pending_change(&mut env, handle, None)
    })
}

/// 应用 nextEvent 返回的最新快照，携带宿主新建的 TUN fd：网卡相关信息
/// 变化或需要重建组网实例时使用。携带 fd 且有虚拟网卡时整体重建 fd 型
/// 设备（虚拟地址/MTU 以快照为准）；组网实例由 native 内部重建，订阅
/// 连接保持不断。
///
/// 返回 JSON：`{"action":"applied"|"need_fd"|"rebuild", ...}`。
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_vnt_VntNetwork_nativeApplyRuntimeChangeFd<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) -> jstring {
    jni_guard!(env, std::ptr::null_mut(), {
        let tun_fd = if tun_fd < 0 { None } else { Some(tun_fd) };
        apply_pending_change(&mut env, handle, tun_fd)
    })
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
            let (manager, runtime) = {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;
                let manager = state
                    .managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();
                (manager, state.runtime.clone())
            };

            let api = runtime.block_on(async { manager.lock().await.api() });
            let api = api.context("组网实例未启动")?;

            let mut global_state = GLOBAL_STATE.lock();
            let state = global_state.as_mut().context("VNT not initialized")?;
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
            let (manager, runtime) = {
                let global_state = GLOBAL_STATE.lock();
                let state = global_state.as_ref().context("VNT not initialized")?;
                let manager = state
                    .managers
                    .get(&handle)
                    .context("Invalid handle")?
                    .clone();
                (manager, state.runtime.clone())
            };

            Ok(runtime.block_on(async { manager.lock().await.device_mode() == DeviceMode::No }))
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
            let (manager, task_groups, runtime) = {
                let mut global_state = GLOBAL_STATE.lock();
                let state = global_state.as_mut().context("VNT not initialized")?;
                let manager = state.managers.remove(&handle);
                let task_groups = state.task_groups.remove(&handle);
                state.vnt_apis.remove(&handle);
                state.pending_changes.remove(&handle);
                state.logs.remove(&handle.to_string());
                (manager, task_groups, state.runtime.clone())
            };
            // 停止组网实例并断开订阅控制连接。
            // 不能直接 block_on(manager.lock().await.stop())：运行期监听
            // 线程在 next_event 等待期间持有管理器锁，停止流程去锁会死锁
            // （与 vnt-web stop_running_instance 同因）。改为停实例任务组：
            // 监听线程的 wait_all_stopped 随即唤醒 next_event，其退出后
            // 释放锁并 drop 管理器，订阅连接随 SubscriptionListener 的
            // Drop 断开。
            if let Some(manager) = manager {
                // 监听线程未持锁时（启动早期或已退出）从管理器现取句柄；
                // 持锁时用创建时登记的句柄，避免与它争锁
                let groups = match manager.try_lock() {
                    Ok(guard) => Some(guard.task_groups()),
                    Err(_) => task_groups,
                };
                // 释放本地引用：仅剩监听线程的引用时，其退出即 drop 管理器
                drop(manager);
                if let Some(groups) = groups {
                    let stopped = runtime.block_on(async {
                        tokio::time::timeout(Duration::from_secs(10), groups.stop_and_wait())
                            .await
                            .is_ok()
                    });
                    if !stopped {
                        // 监听线程异常驻留：不再等待，其退出后仍会
                        // drop 管理器完成清理
                        log::warn!("停止网络实例超时（handle {handle}）");
                    }
                }
            }

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
                "networkCode": envelope.network_code,
                "deviceId": envelope.device_id,
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

/// 从JSON字符串解析配置。`managed` 表示托管（订阅）模式：该模式下本地
/// `device_id` 只是占位符——`RuntimeChangeManager` 一定在等到首份订阅
/// 信封后才创建组网实例，身份由 `merge_present_config` 以信封为准覆盖，
/// 因此缺省时不允许触发任何本地 ID 生成（Android 上兜底生成需要写
/// 可执行文件目录，只读会直接失败）。
fn parse_config_from_json(json_str: &str, managed: bool) -> anyhow::Result<Config> {
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
    }

    let cfg: ConfigJson = serde_json::from_str(json_str)?;
    // 订阅链接由 nativeCreateNetwork 的 bootstrap 单独解析并下发给配置管理器；
    // 此处不再解析：链接不携带身份，本地 JSON 的 network_code/device_id 在托管
    // 模式下会被信封身份覆盖，普通模式下则原样使用

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
        // 托管模式下留空占位：首份信封到达后身份必被信封覆盖，本地值到
        // 不了任何组网实例；非托管模式仍走系统/文件兜底生成
        None if managed => String::new(),
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

    let config = Config {
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
    // 托管实例的身份只来自订阅信封（RuntimeChangeManager 合并时以信封为准），
    // 订阅链接本身不携带 network_code/device_id，本地 JSON 的同类值全部忽略
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

#[cfg(test)]
mod tests {
    use super::*;

    const SUBSCRIPTION: &str = "vnt2://join/2/eyJ2IjoyLCJzZXJ2ZXIiOiJ0Y3A6Ly8xMjcuMC4wLjE6Mjk4NzIiLCJjZXJ0X21vZGUiOiJzdGFuZGFyZCIsImpvaW5faWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJjcmVkZW50aWFsX2tleSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifQ";

    #[test]
    fn json_identity_is_used_verbatim_before_the_first_envelope() {
        // 托管模式下本地 JSON 的身份只是占位：首份订阅信封到达后由
        // merge_present_config 以信封身份覆盖，此处不再从链接注入身份
        let config = parse_config_from_json(
            &format!(
                r#"{{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"json-net",
                "device_id":"json-dev",
                "subscription":"{SUBSCRIPTION}"
            }}"#
            ),
            true,
        )
        .unwrap();
        assert_eq!(config.network_code, "json-net");
        assert_eq!(config.device_id, "json-dev");
        assert!(config.managed.is_none());
    }

    #[test]
    fn managed_json_without_device_id_uses_empty_placeholder() {
        // 托管模式缺省 device_id 时不得触发本地生成（Android 上兜底生成
        // 需要写只读的可执行文件目录，会直接失败）：身份由首份订阅信封
        // 覆盖，本地值只是占位
        let config = parse_config_from_json(
            &format!(
                r#"{{
                "server":["tcp://127.0.0.1:29872"],
                "network_code":"json-net",
                "subscription":"{SUBSCRIPTION}"
            }}"#
            ),
            true,
        )
        .unwrap();
        assert_eq!(config.device_id, "");
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
            false,
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
            false,
        )
        .unwrap();
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/20");
        assert!(config.check().is_ok());

        let config = parse_config_from_json(
            r#"{
                "network_code":"test",
                "ip":"10.26.0.2"
            }"#,
            false,
        )
        .unwrap();
        assert_eq!(config.ip.unwrap().to_string(), "10.26.0.2/24");
    }

    #[test]
    fn rejects_serverless_json_without_virtual_ip() {
        let config = parse_config_from_json(r#"{"network_code":"test"}"#, false).unwrap();
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
