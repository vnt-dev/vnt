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
use tokio::sync::mpsc::{Receiver, Sender};
use tun_rs::async_framed::{Decoder, DeviceFramedRead, DeviceFramedWrite, Encoder};
use tun_rs::{AsyncDevice, DeviceBuilder};

#[derive(Clone)]
pub struct DeviceIOManager {
    task_group: TaskGroup,
    device: DeviceMutex,
}
type DeviceMutex = Arc<tokio::sync::Mutex<(Option<DeviceTask>, Option<(Ipv4Addr, u8)>)>>;
pub struct DeviceTask {
    device: Arc<AsyncDevice>,
    task_recv: SubTask,
    task_send: SubTask,
}
#[derive(Debug, Default)]
pub struct DeviceConfig {
    pub tun_name: Option<String>,
    #[cfg(unix)]
    pub tun_fd: Option<i32>,
    pub mtu: Option<u16>,
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
}
#[derive(Clone)]
pub struct TunInbound {
    pub(crate) sender: Sender<TransmissionBytes>,
}

pub struct TunReceiver {
    receiver: Receiver<TransmissionBytes>,
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
    pub async fn stop_task(&self) {
        let mut guard = self.device.lock().await;
        if let Some(dev) = guard.0.take() {
            dev.task_recv.stop().await;
            dev.task_send.stop().await;
        }
    }
    pub async fn start_task(
        &self,
        device_config: DeviceConfig,
        receiver: TunReceiver,
        enhanced_outbound: EnhancedOutbound,
    ) -> anyhow::Result<()> {
        self.stop_task().await;
        let task = create(
            &self.task_group,
            device_config,
            receiver.receiver,
            enhanced_outbound,
        )?;
        self.device.lock().await.0.replace(task);
        Ok(())
    }
    #[cfg(not(target_os = "android"))]
    pub async fn tun_if_index(&self) -> anyhow::Result<u32> {
        let guard = self.device.lock().await;
        if let Some(v) = &guard.0 {
            Ok(v.device.if_index()?)
        } else {
            bail!("device doesn't exist")
        }
    }
    pub async fn set_network(&self, ip: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let mut guard = self.device.lock().await;
        let Some(dev) = guard.0.as_ref() else {
            bail!("未启动tun")
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

fn create_tun(config: DeviceConfig) -> anyhow::Result<AsyncDevice> {
    #[cfg(unix)]
    if let Some(fd) = config.tun_fd {
        // SAFETY: Caller must ensure fd is a valid, open file descriptor for a TUN device.
        // Using an invalid fd may cause undefined behavior.
        unsafe { return Ok(AsyncDevice::from_fd(fd)?) }
    }
    let mut builder = DeviceBuilder::new();
    if let Some(tun_name) = config.tun_name {
        builder = builder.name(tun_name);
    }
    if let Some(mtu) = config.mtu {
        builder = builder.mtu(mtu);
    }
    #[cfg(windows)]
    {
        builder = builder.metric(1);
    }
    #[cfg(target_os = "linux")]
    {
        builder = builder.offload(true);
    }
    let dev = builder.build_async().context("创建tun失败")?;
    #[cfg(target_os = "linux")]
    {
        _ = dev.set_tx_queue_len(1000);
    }
    Ok(dev)
}
fn create(
    task_group: &TaskGroup,
    config: DeviceConfig,
    receiver: Receiver<TransmissionBytes>,
    enhanced_outbound: EnhancedOutbound,
) -> anyhow::Result<DeviceTask> {
    let device = Arc::new(create_tun(config)?);

    let device_framed_read = DeviceFramedRead::new(device.clone(), BytesCodec::new());
    let device_framed_write = DeviceFramedWrite::new(device.clone(), BytesCodec::new());

    let task_recv = task_group.spawn(async move {
        if let Err(e) = in_tun_loop(receiver, device_framed_write).await {
            log::error!("in_tun_loop error: {e:?}")
        }
    });
    let task_send = task_group.spawn(async move {
        if let Err(e) = out_tun_loop(device_framed_read, enhanced_outbound).await {
            log::error!("out_tun_loop error: {e:?}");
        }
    });

    Ok(DeviceTask {
        device,
        task_recv,
        task_send,
    })
}

async fn in_tun_loop(
    mut receiver: Receiver<TransmissionBytes>,
    mut device_framed_write: DeviceFramedWrite<BytesCodec, Arc<AsyncDevice>>,
) -> anyhow::Result<()> {
    while let Some(data) = receiver.recv().await {
        match device_framed_write.send(data).await {
            Ok(_) => {}
            Err(e) => {
                log::error!("send to tun error: {:?}", e);
                return Err(anyhow::anyhow!(e));
            }
        }
    }
    Ok(())
}

async fn out_tun_loop(
    mut device_framed_read: DeviceFramedRead<BytesCodec, Arc<AsyncDevice>>,
    enhanced_outbound: EnhancedOutbound,
) -> anyhow::Result<()> {
    while let Some(rs) = device_framed_read.next().await {
        let bytes_mut = rs?;
        enhanced_outbound.ipv4_outbound(bytes_mut).await;
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
