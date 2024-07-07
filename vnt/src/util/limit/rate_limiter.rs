use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Instant;

#[derive(Clone)]
pub struct ConcurrentRateLimiter {
    inner: Arc<Mutex<RateLimiter>>,
}

impl ConcurrentRateLimiter {
    pub fn new(capacity: usize, refill_rate: usize) -> Self {
        let inner = RateLimiter::new(capacity, refill_rate);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
    pub fn try_acquire(&self) -> bool {
        self.inner.lock().try_acquire()
    }
}

pub struct RateLimiter {
    capacity: usize,
    tokens: usize,
    refill_rate: usize,
    last_refill: Instant,
}

impl RateLimiter {
    // 初始化限流器
    pub fn new(capacity: usize, refill_rate: usize) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    // 尝试获取一个令牌
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    // 补充令牌
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs() as usize;
        let new_tokens = elapsed * self.refill_rate;

        if new_tokens > 0 {
            self.tokens = std::cmp::min(self.capacity, self.tokens + new_tokens);
            self.last_refill = now;
        }
    }
}
