//! 单实例锁：同一台机器、同一个网络只允许一个客户端注册到服务端。
//!
//! `device_id` 来自机器标识（`machine_uid`），因此同一台机器上无论用哪个用户、
//! 哪个程序（`vnt2_cli`、VNT Desktop 的内置内核 `vnt2-web`）启动，派生出的
//! device_id 都相同。两者同时加入同一网络时，服务端会把后注册的连接当成
//! "同一设备的新连接"，将先注册的那条踢掉，双方随即各自重连并再次互踢，
//! 表现为无限重连、虚拟网内所有节点都不通。
//!
//! 这里以 `device_id + network_code` 为键加跨进程独占锁：
//! 第二个实例在启动阶段就失败，不会污染服务端状态。不同网络使用不同的键，
//! 因此一个内核管理多个互不相干的网络时不受影响。
//!
//! 各平台实现：
//! - Windows：命名互斥体 `Global\vnt-<hash>`，进程退出时由内核自动释放。
//! - Linux：抽象命名空间 Unix socket（`sun_path[0] == 0`），不落盘，进程崩溃自动释放。
//! - 其它 Unix（macOS 等）：`flock` 锁文件，路径在临时目录下，进程退出自动释放。
//! - Android / iOS：宿主系统本身即单实例，直接放行。

use sha2::{Digest, Sha256};
use std::fmt;
use std::io;

/// 锁已被其它客户端实例持有。
#[derive(Debug, Clone)]
pub struct LockHeld {
    /// 实际使用的锁名，便于排查是哪个网络在占用。
    pub name: String,
}

impl fmt::Display for LockHeld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "another client instance holds {}", self.name)
    }
}

impl std::error::Error for LockHeld {}

/// 抢锁失败的原因。
#[derive(Debug)]
pub enum AcquireError {
    /// 已有实例持有该网络的锁。
    Held(LockHeld),
    /// 系统调用失败（不是"已被占用"）。
    Io(io::Error),
}

impl fmt::Display for AcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held(held) => write!(f, "{held}"),
            Self::Io(error) => write!(f, "acquire instance lock failed: {error}"),
        }
    }
}

impl std::error::Error for AcquireError {}

impl From<io::Error> for AcquireError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// 进程级独占锁。持有期间其它**进程**无法为同一网络抢锁；最后一个句柄
/// drop 时释放。
///
/// 同一进程内重复获取同一个网络的锁会共享同一把（同一进程本来就共享同一套
/// device_id 与 client_instance_id，注册多次毫无意义），跨进程才互斥——后者
/// 正是 cli 与 VNT Desktop 内核同时运行的场景。
#[derive(Debug)]
pub struct InstanceLock {
    name: String,
    /// 仅作 RAII 卫兵：存活即持锁，Drop 时释放，因此不需要读取。
    #[allow(dead_code)]
    platform: platform::PlatformLock,
}

/// 进程内已持有的锁表，值为弱引用：外部句柄全部释放后条目失效。
static PROCESS_LOCKS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<InstanceLock>>>,
> = std::sync::OnceLock::new();

fn process_locks(
) -> &'static std::sync::Mutex<std::collections::HashMap<String, std::sync::Weak<InstanceLock>>> {
    PROCESS_LOCKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

impl InstanceLock {
    /// 为 `network_code` 抢锁。
    ///
    /// 键由机器级 `device_id` 与 `network_code` 共同派生，因此同一台机器上
    /// 同一网络只能有一个进程持有，不同网络互不干扰。
    ///
    /// 返回 `Arc`：同一进程内再次获取同一网络会拿到同一个句柄。
    pub fn acquire(network_code: &str) -> Result<std::sync::Arc<Self>, AcquireError> {
        let name = lock_name(network_code);
        let registry = process_locks();
        // 先查进程内是否已持有，顺带清理已失效的弱引用。
        {
            let mut guard = registry.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(existing) = guard.get(&name) {
                if let Some(lock) = existing.upgrade() {
                    return Ok(lock);
                }
                guard.remove(&name);
            }
        }
        let platform = match platform::PlatformLock::try_acquire(&name)? {
            Ok(platform) => platform,
            Err(()) => return Err(AcquireError::Held(LockHeld { name })),
        };
        let lock = std::sync::Arc::new(Self { name, platform });
        registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(lock.name.clone(), std::sync::Arc::downgrade(&lock));
        Ok(lock)
    }

    /// 当前持有的锁名。
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 平台锁随本结构体释放；同时移除进程内的弱引用，避免下次获取时
        // 拿到已失效的条目。
        if let Ok(mut guard) = process_locks().lock() {
            guard.remove(&self.name);
        }
    }
}

/// 由机器标识与网络编号派生出的稳定锁名。
///
/// 用 SHA-256 而不是 `DefaultHasher`：同一个网络的锁必须能被不同版本、
/// 不同程序（cli 与 Desktop 内核）算出同一个名字，而标准库哈希值不保证稳定。
fn lock_name(network_code: &str) -> String {
    let device_id = crate::utils::device_id::get_device_id().unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(network_code.as_bytes());
    let digest = hasher.finalize();
    format!("vnt-{}", hex::encode(&digest[..8]))
}

#[cfg(windows)]
mod platform {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    /// 句柄是内核对象，可跨线程使用；所有权仍由本结构体独占。
    #[derive(Debug)]
    pub struct PlatformLock {
        handle: HANDLE,
    }

    // SAFETY: `handle` 是 `CreateMutexW` 返回的有效内核句柄，只在本结构体内
    // 通过 `CloseHandle` 释放一次；HANDLE 本身可自由跨线程传递。
    unsafe impl Send for PlatformLock {}
    unsafe impl Sync for PlatformLock {}

    impl PlatformLock {
        /// `Ok(Ok(_))` 抢到，`Ok(Err(()))` 已被占用，`Err(_)` 为真实故障。
        pub fn try_acquire(name: &str) -> std::io::Result<Result<Self, ()>> {
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            // CreateMutexW 在名字已存在时同样返回句柄，需靠 GetLastError 区分。
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe { CloseHandle(handle) };
                return Ok(Err(()));
            }
            Ok(Ok(Self { handle }))
        }
    }

    impl Drop for PlatformLock {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;

    /// 抽象命名空间的 Unix socket：绑定成功即持有锁，`bind` 冲突即已有实例。
    /// 抽象地址不写入文件系统，进程退出（含崩溃）时由内核回收。
    #[derive(Debug)]
    pub struct PlatformLock {
        fd: i32,
    }

    impl PlatformLock {
        pub fn try_acquire(name: &str) -> io::Result<Result<Self, ()>> {
            let name = name.as_bytes();
            // 抽象名以 sun_path[0] == 0 开头，可用长度比 sun_path 少一个字节。
            let max_len = std::mem::size_of::<libc::sockaddr_un>()
                - std::mem::offset_of!(libc::sockaddr_un, sun_path)
                - 1;
            if name.len() > max_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "instance lock name too long",
                ));
            }
            // SAFETY: socket/bind/close 都是普通系统调用，参数在下文逐一初始化。
            unsafe {
                let fd = libc::socket(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                addr.sun_path[0] = 0;
                for (index, byte) in name.iter().enumerate() {
                    addr.sun_path[index + 1] = *byte as libc::c_char;
                }
                let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
                if libc::bind(fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, len) != 0 {
                    let error = io::Error::last_os_error();
                    libc::close(fd);
                    if error.raw_os_error() == Some(libc::EADDRINUSE) {
                        return Ok(Err(()));
                    }
                    return Err(error);
                }
                Ok(Ok(Self { fd }))
            }
        }
    }

    impl Drop for PlatformLock {
        fn drop(&mut self) {
            // SAFETY: fd 由本结构体独占，Drop 只执行一次。
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "android"), not(target_os = "ios")))]
mod platform {
    use std::fs::OpenOptions;
    use std::io;
    use std::os::unix::io::AsRawFd;

    /// macOS 等平台不支持抽象 Unix socket，退化为临时目录下的 flock 文件。
    #[derive(Debug)]
    pub struct PlatformLock {
        _file: std::fs::File,
    }

    impl PlatformLock {
        pub fn try_acquire(name: &str) -> io::Result<Result<Self, ()>> {
            let path = std::env::temp_dir().join(format!("{name}.lock"));
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            // SAFETY: fd 来自上面打开的文件，在 `file` 生命周期内始终有效。
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Ok(Err(()));
                }
                return Err(error);
            }
            Ok(Ok(Self { _file: file }))
        }
    }
}

/// 宿主系统保证单实例（Android / iOS），无需额外同步。
#[cfg(any(target_os = "android", target_os = "ios"))]
mod platform {
    use std::io;

    #[derive(Debug)]
    pub struct PlatformLock;

    impl PlatformLock {
        pub fn try_acquire(_name: &str) -> io::Result<Result<Self, ()>> {
            Ok(Ok(Self))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_name_is_stable_and_network_specific() {
        let first = lock_name("btsd321_net");
        let second = lock_name("btsd321_net");
        assert_eq!(first, second, "同一网络的锁名必须稳定");
        assert_ne!(first, lock_name("other_net"), "不同网络必须使用不同锁名");
        assert!(first.starts_with("vnt-"));
    }

    #[test]
    fn same_process_shares_one_lock() {
        let network = format!("lock-share-test-{}", std::process::id());
        let first = InstanceLock::acquire(&network).expect("首次抢锁");
        let second = InstanceLock::acquire(&network).expect("同进程重复获取应共享同一把锁");
        assert_eq!(first.name(), second.name());
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "同进程应拿到同一个句柄"
        );
    }

    #[test]
    fn releasing_allows_acquiring_again() {
        let network = format!("lock-release-test-{}", std::process::id());
        {
            let _held = InstanceLock::acquire(&network).expect("首次抢锁");
        }
        InstanceLock::acquire(&network).expect("释放后应能重新抢到");
    }

    /// 直接验证平台层互斥：绕过进程内共享后，第二个持有者必须被拒绝。
    /// 这一层才是跨进程（cli 与 Desktop 内核同时运行）真正生效的保证。
    #[test]
    fn platform_lock_rejects_second_holder() {
        let name = format!("vnt-platform-test-{}", std::process::id());
        let first = platform::PlatformLock::try_acquire(&name)
            .expect("系统调用不应失败")
            .expect("首次应抢到平台锁");
        match platform::PlatformLock::try_acquire(&name) {
            Ok(Err(())) => {}
            Ok(Ok(_)) => panic!("平台锁应拒绝第二个持有者"),
            Err(error) => panic!("系统调用不应失败: {error}"),
        }
        drop(first);
        platform::PlatformLock::try_acquire(&name)
            .expect("系统调用不应失败")
            .expect("释放后应能重新抢到");
    }

    /// 调用方（main）靠 `downcast_ref` 识别"锁被占用"，而错误从
    /// `create_network` 返回时会带上若干层 context，必须仍能取到 `LockHeld`。
    #[test]
    fn lock_held_survives_context_wrapping() {
        let error = anyhow::Error::new(LockHeld {
            name: "vnt-test".to_string(),
        })
        .context("创建网络失败");
        let held = error
            .downcast_ref::<LockHeld>()
            .expect("context 包裹后仍应能 downcast 出 LockHeld");
        assert_eq!(held.name, "vnt-test");
    }
}
