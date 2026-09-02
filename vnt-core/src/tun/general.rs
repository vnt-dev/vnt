use crate::context::config::DeviceMode;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use crate::utils::task_control::{SubTask, TaskGroup};
use anyhow::{Context, bail};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::{Receiver, Sender};
use tun_rs::AsyncDevice;
use tun_rs::async_framed::{Decoder, DeviceFramedRead, DeviceFramedWrite, Encoder};
#[cfg(not(target_os = "android"))]
use tun_rs::{DeviceBuilder, Layer};

#[derive(Clone)]
pub struct DeviceIOManager {
    task_group: TaskGroup,
    device: DeviceMutex,
}
type DeviceMutex = Arc<tokio::sync::Mutex<DeviceState>>;
#[derive(Default)]
struct DeviceState {
    runtime: Option<DeviceRuntime>,
    network: Option<(Ipv4Addr, u8)>,
}
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
struct DeviceRuntime {
    task: Option<DeviceTask>,
    receiver: Arc<tokio::sync::Mutex<Receiver<TransmissionBytes>>>,
    enhanced_outbound: Arc<EnhancedOutbound>,
    device_mode: DeviceMode,
}
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
struct DeviceTask {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    device: Arc<AsyncDevice>,
    inbound_task: SubTask,
    outbound_task: SubTask,
    intentional_stop: Arc<AtomicBool>,
}
#[derive(Debug, Default)]
pub struct DeviceConfig {
    pub device_mode: DeviceMode,
    pub tun_name: Option<String>,
    #[cfg(unix)]
    pub tun_fd: Option<i32>,
    pub mtu: Option<u16>,
    pub mac_addr: Option<[u8; 6]>,
}

impl DeviceConfig {
    pub fn set_tun_name(mut self, tun_name: String) -> Self {
        self.tun_name = Some(tun_name);
        self
    }
    #[cfg(unix)]
    pub fn set_tun_fd(mut self, tun_fd: i32) -> Self {
        self.tun_fd = Some(tun_fd);
        self
    }
    pub fn set_mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }
    pub fn set_device_mode(mut self, device_mode: DeviceMode) -> Self {
        self.device_mode = device_mode;
        self
    }
    pub fn set_mac_addr(mut self, mac_addr: [u8; 6]) -> Self {
        self.mac_addr = Some(mac_addr);
        self
    }
}
#[derive(Clone)]
pub struct TunInbound {
    pub(crate) sender: Sender<TransmissionBytes>,
}

pub struct TunReceiver {
    pub(crate) receiver: Receiver<TransmissionBytes>,
}
pub fn tun_channel() -> (TunInbound, TunReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(1024);
    (TunInbound { sender }, TunReceiver { receiver })
}

impl DeviceIOManager {
    pub fn new(task_group: TaskGroup) -> DeviceIOManager {
        Self {
            task_group,
            device: Arc::new(Default::default()),
        }
    }

    pub async fn start_task(
        &self,
        device_config: DeviceConfig,
        receiver: &mut Option<TunReceiver>,
        enhanced_outbound: &mut Option<EnhancedOutbound>,
    ) -> anyhow::Result<()> {
        if receiver.is_none()
            || enhanced_outbound.is_none()
            || self.device.lock().await.runtime.is_some()
        {
            bail!("device task already started");
        }
        // 先执行可能失败的 TUN/TAP 设备创建，成功后才消费 receiver/outbound，
        // 保证失败时调用方状态完整、可以重试
        let device_mode = device_config.device_mode;
        let device = Arc::new(create_device(device_config)?);
        let Some(receiver_value) = receiver.take() else {
            bail!("device task already started");
        };
        let Some(enhanced_outbound) = enhanced_outbound.take() else {
            *receiver = Some(receiver_value);
            bail!("device task already started");
        };
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver_value.receiver));
        let enhanced_outbound = Arc::new(enhanced_outbound);
        let task = create(
            &self.task_group,
            device,
            receiver.clone(),
            enhanced_outbound.clone(),
            device_mode,
        );
        self.device.lock().await.runtime = Some(DeviceRuntime {
            task: Some(task),
            receiver,
            enhanced_outbound,
            device_mode,
        });
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    pub async fn device_if_index(&self) -> anyhow::Result<u32> {
        let guard = self.device.lock().await;
        if let Some(task) = guard
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.task.as_ref())
        {
            Ok(task.device.if_index()?)
        } else {
            bail!("device doesn't exist")
        }
    }
    #[cfg(not(target_os = "android"))]
    pub async fn set_network(&self, ip: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let mut guard = self.device.lock().await;
        let Some(task) = guard
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.task.as_ref())
        else {
            bail!("虚拟网卡尚未启动")
        };
        if let Some(v) = guard.network.as_ref()
            && v.0 == ip
            && v.1 == prefix_len
        {
            return Ok(());
        }
        task.device
            .set_network_address(ip, prefix_len, None)
            .context("设置IP失败")?;
        guard.network = Some((ip, prefix_len));
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub async fn suspend_android(&self) -> anyhow::Result<()> {
        let mut task = {
            let mut guard = self.device.lock().await;
            let runtime = guard.runtime.as_mut().context("虚拟网卡尚未启动")?;
            runtime.task.take().context("虚拟网卡已经暂停")?
        };
        task.stop_intentionally().await;
        // task 在这里释放最后一个由管理器持有的设备引用；读写任务已停止，
        // 因而旧 Android VPN fd 会在创建新 VPN 前关闭。
        drop(task);
        Ok(())
    }

    #[cfg(target_os = "android")]
    pub async fn resume_android(
        &self,
        tun_fd: std::os::fd::OwnedFd,
        ip: Ipv4Addr,
        prefix_len: u8,
    ) -> anyhow::Result<()> {
        use std::os::fd::IntoRawFd;

        if self.task_group.is_stopped() {
            bail!("网络任务已经停止");
        }
        let raw_fd = tun_fd.into_raw_fd();
        // SAFETY: JNI transfers an owned VpnService TUN fd. tun-rs takes ownership.
        let device = Arc::new(unsafe { AsyncDevice::from_fd(raw_fd) }?);
        let mut guard = self.device.lock().await;
        let runtime = guard.runtime.as_mut().context("虚拟网卡尚未启动")?;
        if runtime.task.is_some() {
            bail!("虚拟网卡尚未暂停");
        }
        let task = create(
            &self.task_group,
            device,
            runtime.receiver.clone(),
            runtime.enhanced_outbound.clone(),
            runtime.device_mode,
        );
        if !task.inbound_task.is_running() || !task.outbound_task.is_running() {
            bail!("无法启动新虚拟网卡任务");
        }
        runtime.task = Some(task);
        guard.network = Some((ip, prefix_len));
        Ok(())
    }
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl DeviceTask {
    async fn stop_intentionally(&mut self) {
        self.intentional_stop.store(true, Ordering::Release);
        tokio::join!(self.inbound_task.stop(), self.outbound_task.stop());
    }
}

fn create_device(config: DeviceConfig) -> anyhow::Result<AsyncDevice> {
    #[cfg(target_os = "android")]
    {
        let fd = config
            .tun_fd
            .context("Android requires a VpnService TUN fd")?;
        // SAFETY: The fd comes directly from ParcelFileDescriptor returned by
        // VpnService.Builder.establish and remains open for the network lifetime.
        return unsafe { Ok(AsyncDevice::from_fd(fd)?) };
    }
    #[cfg(not(target_os = "android"))]
    {
        #[cfg(unix)]
        if let Some(fd) = config.tun_fd {
            // SAFETY: Caller must ensure fd is a valid, open file descriptor for a TUN device.
            // Using an invalid fd may cause undefined behavior.
            unsafe { return Ok(AsyncDevice::from_fd(fd)?) }
        }
        let mut builder = DeviceBuilder::new();
        builder = builder.layer(match config.device_mode {
            DeviceMode::Tap => Layer::L2,
            DeviceMode::Tun => Layer::L3,
            DeviceMode::No => bail!("cannot create a device in no mode"),
        });
        if let Some(tun_name) = config.tun_name {
            builder = builder.name(tun_name);
        }
        if let Some(mtu) = config.mtu {
            builder = builder.mtu(mtu);
        }
        #[cfg(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "macos",
            target_os = "netbsd"
        ))]
        if let Some(mac_addr) = config.mac_addr {
            builder = builder.mac_addr(mac_addr);
        }
        #[cfg(windows)]
        {
            builder = builder.metric(1);
        }
        #[cfg(target_os = "linux")]
        if config.device_mode == DeviceMode::Tun {
            builder = builder.offload(true);
        }
        let dev = builder.build_async().map_err(|error| {
            let context = device_creation_error_context(config.device_mode, &error);
            anyhow::Error::new(error).context(context)
        })?;
        #[cfg(target_os = "linux")]
        {
            _ = dev.set_tx_queue_len(1000);
        }
        Ok(dev)
    }
}

fn device_creation_error_context(mode: DeviceMode, error: &io::Error) -> &'static str {
    let permission_denied = error.kind() == io::ErrorKind::PermissionDenied || {
        #[cfg(windows)]
        {
            error.raw_os_error() == Some(5)
        }
        #[cfg(not(windows))]
        {
            false
        }
    };

    if permission_denied {
        return match mode {
            DeviceMode::Tap => "创建 TAP 失败：权限不足，请尝试以管理员身份运行程序",
            DeviceMode::Tun => "创建 TUN 失败：权限不足，请尝试以管理员身份运行程序",
            DeviceMode::No => "创建虚拟网卡失败：权限不足，请尝试以管理员身份运行程序",
        };
    }

    match mode {
        DeviceMode::Tap if cfg!(windows) => {
            "创建 TAP 失败；Windows TAP 模式需要预先安装 tap-windows (tap0901) 驱动"
        }
        DeviceMode::Tap => "创建 TAP 失败",
        DeviceMode::Tun | DeviceMode::No => "创建 TUN 失败",
    }
}
fn create(
    task_group: &TaskGroup,
    device: Arc<AsyncDevice>,
    receiver: Arc<tokio::sync::Mutex<Receiver<TransmissionBytes>>>,
    enhanced_outbound: Arc<EnhancedOutbound>,
    device_mode: DeviceMode,
) -> DeviceTask {
    let mut device_framed_read = DeviceFramedRead::new(device.clone(), BytesCodec::new());
    device_framed_read.set_read_buffer_size(2048);
    let device_framed_write = DeviceFramedWrite::new(device.clone(), BytesCodec::new());
    let outbound_device = device.clone();

    // 读写两个方向独立运行；任一方向结束（出错或设备关闭）都会停止整个任务组，
    // 避免虚拟网卡失效后其他任务继续运行。
    let intentional_stop = Arc::new(AtomicBool::new(false));
    let inbound_stop = intentional_stop.clone();
    let inbound_group = task_group.clone();
    let inbound_task = task_group.spawn_restartable(async move {
        if let Err(e) = in_device_loop(receiver, device_framed_write).await {
            log::error!("in_device_loop error, stopping all tasks: {e:?}");
        } else {
            log::warn!("in_device_loop exited, stopping all tasks");
        }
        if !inbound_stop.load(Ordering::Acquire) {
            inbound_group.stop();
        }
    });
    let outbound_stop = intentional_stop.clone();
    let outbound_group = task_group.clone();
    let outbound_task = task_group.spawn_restartable(async move {
        if let Err(e) = out_device_loop(
            device_framed_read,
            outbound_device,
            enhanced_outbound,
            device_mode,
        )
        .await
        {
            log::error!("out_device_loop error, stopping all tasks: {e:?}");
        } else {
            log::warn!("out_device_loop exited, stopping all tasks");
        }
        if !outbound_stop.load(Ordering::Acquire) {
            outbound_group.stop();
        }
    });

    DeviceTask {
        device,
        inbound_task,
        outbound_task,
        intentional_stop,
    }
}

async fn in_device_loop(
    receiver: Arc<tokio::sync::Mutex<Receiver<TransmissionBytes>>>,
    mut device_framed_write: DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>>,
) -> anyhow::Result<()> {
    loop {
        let data = {
            let mut receiver = receiver.lock().await;
            receiver.recv().await
        };
        let Some(data) = data else {
            break;
        };
        match device_framed_write.send(data).await {
            Ok(_) => {}
            Err(e) => {
                log::error!("send to virtual device error: {:?}", e);
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    Ok(())
}

async fn out_device_loop(
    mut device_framed_read: DeviceFramedRead<BytesCodec, Arc<AsyncDevice>>,
    device: Arc<AsyncDevice>,
    enhanced_outbound: Arc<EnhancedOutbound>,
    device_mode: DeviceMode,
) -> anyhow::Result<()> {
    while let Some(rs) = device_framed_read.next().await {
        let bytes_mut = rs?;
        if device_mode == DeviceMode::Tap {
            if let Some(reply) = enhanced_outbound.ethernet_outbound(bytes_mut).await {
                device.send(reply.as_ref()).await?;
            }
        } else {
            enhanced_outbound.ipv4_outbound(bytes_mut).await;
        }
    }
    Ok(())
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct BytesCodec(());
impl BytesCodec {
    pub fn new() -> BytesCodec {
        BytesCodec(())
    }
}
impl Decoder for BytesCodec {
    type Item = TransmissionBytes;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<TransmissionBytes>, io::Error> {
        if !buf.is_empty() {
            let mut bytes = TransmissionBytes::new_offset(HEAD_LENGTH);
            bytes.put(buf)?;
            buf.clear();
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<TransmissionBytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, data: TransmissionBytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        buf.reserve(data.len());
        buf.extend_from_slice(&data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_suggests_running_as_administrator() {
        let error = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");

        assert_eq!(
            device_creation_error_context(DeviceMode::Tun, &error),
            "创建 TUN 失败：权限不足，请尝试以管理员身份运行程序"
        );
    }

    #[test]
    fn unrelated_error_keeps_the_original_hint() {
        let error = io::Error::new(io::ErrorKind::NotFound, "driver not found");

        assert_eq!(
            device_creation_error_context(DeviceMode::Tun, &error),
            "创建 TUN 失败"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_access_denied_code_suggests_running_as_administrator() {
        let error = io::Error::from_raw_os_error(5);

        assert_eq!(
            device_creation_error_context(DeviceMode::Tap, &error),
            "创建 TAP 失败：权限不足，请尝试以管理员身份运行程序"
        );
    }
}
