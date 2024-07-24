use crate::util::StopManager;
use crossbeam_utils::atomic::AtomicCell;
use std::collections::BinaryHeap;
use std::sync::mpsc::TrySendError;
use std::sync::Arc;
use std::{
    cmp::Ordering,
    sync::mpsc::{sync_channel, Receiver, SyncSender},
    time::{Duration, Instant},
};

struct DelayedTask {
    f: Box<dyn FnOnce(&Scheduler) + Send>,
    next: Instant,
}

impl Eq for DelayedTask {}

impl PartialEq for DelayedTask {
    fn eq(&self, other: &Self) -> bool {
        self.next.eq(&other.next)
    }
}

impl PartialOrd for DelayedTask {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.next.partial_cmp(&other.next).map(|ord| ord.reverse())
    }
}

impl Ord for DelayedTask {
    fn cmp(&self, other: &Self) -> Ordering {
        self.next.cmp(&other.next).reverse()
    }
}

enum Op {
    Task(DelayedTask),
    Stop,
}

#[derive(Clone)]
pub struct Scheduler {
    sender: SyncSender<Op>,
    state: Arc<AtomicCell<SchedulerState>>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum SchedulerState {
    Running,
    ShutdownNow, // 立即停止任务执行，队列中剩余的任务不再执行
    _Shutdown,   //执行完队列中剩余的任务再停止
}

impl Scheduler {
    pub fn new(stop_manager: StopManager) -> anyhow::Result<Self> {
        let (sender, receiver) = sync_channel::<Op>(32);
        let state = Arc::new(AtomicCell::new(SchedulerState::Running));
        let s = Self { sender, state };
        let s_inner = s.clone();
        let worker = {
            let scheduler = s.clone();
            stop_manager.add_listener("Scheduler".into(), move || {
                scheduler.shutdown_now();
            })?
        };
        std::thread::Builder::new()
            .name("Scheduler".into())
            .spawn(move || {
                run(receiver, &s_inner);
                s_inner.shutdown_now();
                worker.stop_all();
            })
            .expect("Scheduler");
        Ok(s)
    }
    pub fn timeout<F>(&self, time: Duration, f: F) -> bool
    where
        F: FnOnce(&Scheduler) + Send + 'static,
    {
        if self.state.load() != SchedulerState::Running {
            log::error!("定时任务执行停止");
            return false;
        }
        let task = DelayedTask {
            f: Box::new(f),
            next: Instant::now().checked_add(time).unwrap(),
        };
        // 如果是任务中调用此方法，那这里用send可能会导致整个定时任务阻塞
        // 任务总数不能大于或等于通道长度，所以改成try_send快速失败
        match self.sender.try_send(Op::Task(task)) {
            Ok(_) => true,
            Err(e) => {
                match e {
                    TrySendError::Full(_) => {
                        log::error!("定时任务队列达到上限");
                    }
                    TrySendError::Disconnected(_) => {
                        log::error!("定时任务执行停止 通道关闭");
                    }
                }
                false
            }
        }
    }
    pub fn shutdown_now(&self) {
        self.state.store(SchedulerState::ShutdownNow);
        let _ = self.sender.send(Op::Stop);
    }
}

fn run(receiver: Receiver<Op>, s_inner: &Scheduler) {
    let mut binary_heap = BinaryHeap::<DelayedTask>::with_capacity(32);
    loop {
        while let Some(task) = binary_heap.peek() {
            if s_inner.state.load() == SchedulerState::ShutdownNow {
                return;
            }
            let now = Instant::now();
            if now < task.next {
                //需要等待对应时间
                match receiver.recv_timeout(task.next - now) {
                    Ok(op) => {
                        if add_task(op, &mut binary_heap) {
                            continue;
                        }
                        return;
                    }
                    Err(e) => match e {
                        std::sync::mpsc::RecvTimeoutError::Timeout => continue,
                        std::sync::mpsc::RecvTimeoutError::Disconnected => return,
                    },
                }
            } else {
                if let Some(task) = binary_heap.pop() {
                    (task.f)(s_inner);
                }
            }
        }
        //取出所有任务
        loop {
            match receiver.try_recv() {
                Ok(op) => {
                    if add_task(op, &mut binary_heap) {
                        continue;
                    }
                    return;
                }
                Err(e) => match e {
                    std::sync::mpsc::TryRecvError::Empty => break,
                    std::sync::mpsc::TryRecvError::Disconnected => return,
                },
            }
        }

        if binary_heap.is_empty() {
            //任务队列为空时陷入等待
            if let Ok(op) = receiver.recv() {
                if add_task(op, &mut binary_heap) {
                    continue;
                }
            }
            return;
        }
    }
}

fn add_task(op: Op, binary_heap: &mut BinaryHeap<DelayedTask>) -> bool {
    return match op {
        Op::Task(task) => {
            binary_heap.push(task);
            true
        }
        Op::Stop => false,
    };
}
