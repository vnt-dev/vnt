use crate::context::config::DeviceMode;
use crate::enhanced_tunnel::outbound::EnhancedOutbound;
use crate::protocol::ip_packet_protocol::HEAD_LENGTH;
use crate::protocol::transmission::TransmissionBytes;
use crate::utils::task_control::TaskGroup;
use anyhow::{Context, bail};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc::{Receiver, Sender};
use tun_rs::AsyncDevice;
use tun_rs::async_framed::{Decoder, DeviceFramedRead, DeviceFramedWrite, Encoder};
#[cfg(not(target_os = "android"))]
use tun_rs::{DeviceBuilder, Layer};

pub struct DeviceIOManager {
    task_group: TaskGroup,
    device: DeviceMutex,
}
type DeviceMutex = Arc<tokio::sync::Mutex<(Option<DeviceTask>, Option<(Ipv4Addr, u8)>)>>;
pub struct DeviceTask {
    #[cfg_attr(target_os = "android", allow(dead_code))]
    device: Arc<AsyncDevice>,
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
        if receiver.is_none() || enhanced_outbound.is_none() {
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
        let task = create(
            &self.task_group,
            device,
            receiver_value.receiver,
            enhanced_outbound,
            device_mode,
        );
        self.device.lock().await.0.replace(task);
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    pub async fn device_if_index(&self) -> anyhow::Result<u32> {
        let guard = self.device.lock().await;
        if let Some(v) = &guard.0 {
            Ok(v.device.if_index()?)
        } else {
            bail!("device doesn't exist")
        }
    }
    #[cfg(not(target_os = "android"))]
    pub async fn set_network(&self, ip: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let mut guard = self.device.lock().await;
        let Some(dev) = guard.0.as_ref() else {
            bail!("虚拟网卡尚未启动")
        };
        if let Some(v) = guard.1.as_ref()
            && v.0 == ip
            && v.1 == prefix_len
        {
            return Ok(());
        }
        dev.device
            .set_network_address(ip, prefix_len, None)
            .context("设置IP失败")?;
        guard.1 = Some((ip, prefix_len));
        Ok(())
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
        let dev = builder.build_async().with_context(|| {
            if config.device_mode == DeviceMode::Tap && cfg!(windows) {
                "创建 TAP 失败；Windows TAP 模式需要预先安装 tap-windows (tap0901) 驱动"
            } else if config.device_mode == DeviceMode::Tap {
                "创建 TAP 失败"
            } else {
                "创建 TUN 失败"
            }
        })?;
        #[cfg(target_os = "linux")]
        {
            _ = dev.set_tx_queue_len(1000);
        }
        Ok(dev)
    }
}
fn create(
    task_group: &TaskGroup,
    device: Arc<AsyncDevice>,
    receiver: Receiver<TransmissionBytes>,
    enhanced_outbound: EnhancedOutbound,
    device_mode: DeviceMode,
) -> DeviceTask {
    let mut device_framed_read = DeviceFramedRead::new(device.clone(), BytesCodec::new());
    let read_buffer_size =
        framed_read_buffer_size(device_mode, device_framed_read.read_buffer_size());
    device_framed_read.set_read_buffer_size(read_buffer_size);
    let device_framed_write = DeviceFramedWrite::new(device.clone(), BytesCodec::new());
    let outbound_device = device.clone();

    // 读写两个方向独立运行；任一方向结束（出错或设备关闭）都会停止整个任务组，
    // 避免虚拟网卡失效后其他任务继续运行。
    task_group.spawn_stop_all(async move {
        if let Err(e) = in_device_loop(receiver, device_framed_write).await {
            log::error!("in_device_loop error, stopping all tasks: {e:?}");
        } else {
            log::warn!("in_device_loop exited, stopping all tasks");
        }
    });
    task_group.spawn_stop_all(async move {
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
    });

    DeviceTask { device }
}

fn framed_read_buffer_size(device_mode: DeviceMode, mtu: usize) -> usize {
    if device_mode == DeviceMode::Tap {
        mtu.saturating_add(crate::ethernet::MAX_ETHERNET_HEADER_LEN)
    } else {
        mtu
    }
}

async fn in_device_loop(
    mut receiver: Receiver<TransmissionBytes>,
    mut device_framed_write: DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>>,
) -> anyhow::Result<()> {
    while let Some(data) = receiver.recv().await {
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
    enhanced_outbound: EnhancedOutbound,
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
    fn tap_read_buffer_includes_ethernet_and_vlan_headers() {
        assert_eq!(
            framed_read_buffer_size(DeviceMode::Tap, 1380),
            1380 + crate::ethernet::MAX_ETHERNET_HEADER_LEN
        );
        assert_eq!(framed_read_buffer_size(DeviceMode::Tun, 1380), 1380);
    }
}
