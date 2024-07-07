use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct TrafficMeterMultiAddress {
    history_capacity: usize,
    inner: Arc<Mutex<(u64, HashMap<Ipv4Addr, TrafficMeter>)>>,
}

impl Default for TrafficMeterMultiAddress {
    fn default() -> Self {
        TrafficMeterMultiAddress::new(100)
    }
}

impl TrafficMeterMultiAddress {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new((0, HashMap::new())));
        Self {
            inner,
            history_capacity,
        }
    }
    pub fn add_traffic(&self, ip: Ipv4Addr, amount: usize) {
        let mut guard = self.inner.lock();
        guard.0 += amount as u64;
        guard
            .1
            .entry(ip)
            .or_insert(TrafficMeter::new(self.history_capacity))
            .add_traffic(amount)
    }
    pub fn total(&self) -> u64 {
        self.inner.lock().0
    }
    pub fn get_all(&self) -> (u64, HashMap<Ipv4Addr, u64>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard.1.iter().map(|(ip, t)| (*ip, t.total())).collect(),
        )
    }
    pub fn get_all_history(&self) -> (u64, HashMap<Ipv4Addr, (u64, Vec<usize>)>) {
        let guard = self.inner.lock();
        (
            guard.0,
            guard
                .1
                .iter()
                .map(|(ip, t)| (*ip, (t.total(), t.get_history())))
                .collect(),
        )
    }
    pub fn get_history(&self, ip: &Ipv4Addr) -> Option<(u64, Vec<usize>)> {
        self.inner
            .lock()
            .1
            .get(ip)
            .map(|t| (t.total(), t.get_history()))
    }
}

#[derive(Clone)]
pub struct ConcurrentTrafficMeter {
    inner: Arc<Mutex<TrafficMeter>>,
}

impl ConcurrentTrafficMeter {
    pub fn new(history_capacity: usize) -> Self {
        let inner = Arc::new(Mutex::new(TrafficMeter::new(history_capacity)));
        Self { inner }
    }
    pub fn add_traffic(&self, amount: usize) {
        self.inner.lock().add_traffic(amount)
    }
    pub fn get_history(&self) -> Vec<usize> {
        self.inner.lock().get_history()
    }
}

pub struct TrafficMeter {
    start_time: Instant,
    total: u64,
    count: usize,
    history_capacity: usize,
    history: VecDeque<usize>,
}

impl TrafficMeter {
    // 初始化一个新的 TrafficMeter
    pub fn new(history_capacity: usize) -> Self {
        Self {
            start_time: Instant::now(),
            total: 0,
            count: 0,
            history: VecDeque::with_capacity(history_capacity),
            history_capacity,
        }
    }

    // 增加流量计数
    pub fn add_traffic(&mut self, amount: usize) {
        self.total += amount as u64;
        self.count += amount;
        self.check_time();
    }

    // 检查时间是否超过一秒，如果是，记录流量并重置计数器和时间
    fn check_time(&mut self) {
        if self.start_time.elapsed() >= Duration::new(1, 0) {
            // 将当前计数添加到历史记录
            if self.history.len() >= self.history_capacity {
                self.history.pop_front(); // 保持历史记录不超过capacity
            }
            self.history.push_back(self.count);

            // 重置计数器和时间
            self.count = 0;
            self.start_time = Instant::now();
        }
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    // 获取流量记录
    pub fn get_history(&self) -> Vec<usize> {
        self.history.iter().cloned().collect()
    }
}
