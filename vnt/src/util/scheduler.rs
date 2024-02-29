use crate::util::StopManager;
use std::collections::BinaryHeap;
use std::{
    cmp::Ordering,
    io,
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
}
impl Scheduler {
    pub fn new(stop_manager: StopManager) -> io::Result<Self> {
        let (sender, receiver) = sync_channel::<Op>(32);
        let s = Self { sender };
        let s_inner = s.clone();
        let worker = {
            let scheduler = s.clone();
            stop_manager.add_listener("Scheduler".into(), move || {
                scheduler.shutdown();
            })?
        };
        std::thread::Builder::new()
            .name("Scheduler".into())
            .spawn(move || {
                run(receiver, s_inner);
                worker.stop_all();
            })
            .unwrap();
        Ok(s)
    }
    pub fn timeout<F>(&self, time: Duration, f: F) -> bool
    where
        F: FnOnce(&Scheduler) + Send + 'static,
    {
        let task = DelayedTask {
            f: Box::new(f),
            next: Instant::now().checked_add(time).unwrap(),
        };
        self.sender.send(Op::Task(task)).is_ok()
    }
    pub fn shutdown(self) {
        let _ = self.sender.send(Op::Stop);
    }
}
fn run(receiver: Receiver<Op>, s_inner: Scheduler) {
    let mut binary_heap = BinaryHeap::<DelayedTask>::with_capacity(32);
    loop {
        while let Some(task) = binary_heap.peek() {
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
                    (task.f)(&s_inner);
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
