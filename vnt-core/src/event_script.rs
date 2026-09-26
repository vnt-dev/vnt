/// 事件脚本：在掉线或重连成功时调用外部脚本。
///
/// 脚本通过命令行参数接收事件名和事件数据，例如：
/// ```text
/// <script> disconnected --server quic://1.2.3.4:29872
/// <script> reconnected --server quic://1.2.3.4:29872 --ip 10.26.0.2 ...
/// <script> device_applied --ip 10.26.0.2 --prefix-length 24 --mtu 1380 ...
/// ```
///
/// 脚本异步执行（fire-and-forget），失败仅记录日志，不影响组网主流程。
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventScriptType {
    /// 与服务器断开连接（掉线）
    Disconnected,
    /// 断开后重连成功
    Reconnected,
    /// 配置变更后虚拟网卡被（重新）应用：热更新地址/路由/MTU/网卡名、
    /// 重启网卡任务，或实例重建后新网卡启动
    DeviceApplied,
}

impl EventScriptType {
    /// 传给脚本的第一个参数（事件名）。
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Reconnected => "reconnected",
            Self::DeviceApplied => "device_applied",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct EventScript {
    script: Option<String>,
}

impl EventScript {
    pub(crate) fn new(script: Option<String>) -> Self {
        Self {
            script: script
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }

    /// 触发事件，异步执行脚本（不等待脚本结束）。
    pub(crate) async fn notify(&self, event: EventScriptType, params: &[(&str, String)]) {
        let Some(script) = &self.script else {
            return;
        };
        let mut command = Command::new(script);
        command
            .arg(event.as_str())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for (key, value) in params {
            command.arg(format!("--{key}")).arg(value);
        }
        #[cfg(windows)]
        {
            // CREATE_NO_WINDOW：避免执行脚本时弹出黑色控制台窗口
            command.creation_flags(0x0800_0000);
        }
        match command.spawn() {
            Ok(mut child) => {
                log::info!("事件脚本已触发: {} {}", event.as_str(), script);
                // 在后台等待子进程退出并回收，避免产生僵尸进程
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
            }
            Err(e) => {
                log::error!("事件脚本执行失败: {script}: {e}");
            }
        }
    }
}
