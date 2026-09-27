//! 可移植的 64 位原子类型。
//!
//! mips(el)-unknown-linux-musl 等目标的最大原子宽度是 32 位，std 中没有
//! AtomicU64/AtomicI64。支持 64 位原子的平台直接使用 std 类型；不支持时
//! 回退为 Mutex 保护的普通整数（当前用法均为低频操作，锁开销可忽略）。

#[cfg(target_has_atomic = "64")]
pub use std::sync::atomic::AtomicI64;
#[cfg(target_has_atomic = "64")]
pub use std::sync::atomic::AtomicU64;

#[cfg(not(target_has_atomic = "64"))]
pub use fallback::{AtomicI64, AtomicU64};

#[cfg(not(target_has_atomic = "64"))]
mod fallback {
    use parking_lot::Mutex;
    use std::sync::atomic::Ordering;

    pub struct AtomicU64(Mutex<u64>);

    impl AtomicU64 {
        pub fn new(value: u64) -> Self {
            Self(Mutex::new(value))
        }

        pub fn load(&self, _ordering: Ordering) -> u64 {
            *self.0.lock()
        }

        pub fn fetch_max(&self, value: u64, _ordering: Ordering) -> u64 {
            let mut guard = self.0.lock();
            let old = *guard;
            if value > old {
                *guard = value;
            }
            old
        }
    }

    pub struct AtomicI64(Mutex<i64>);

    impl AtomicI64 {
        pub fn new(value: i64) -> Self {
            Self(Mutex::new(value))
        }

        pub fn load(&self, _ordering: Ordering) -> i64 {
            *self.0.lock()
        }

        pub fn compare_exchange(
            &self,
            current: i64,
            new: i64,
            _success: Ordering,
            _failure: Ordering,
        ) -> Result<i64, i64> {
            let mut guard = self.0.lock();
            if *guard == current {
                *guard = new;
                Ok(current)
            } else {
                Err(*guard)
            }
        }
    }
}
