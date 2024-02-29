use std::sync::mpsc::{sync_channel, Receiver, SendError, SyncSender};

pub fn channel_group<T>(size: usize, bound: usize) -> (GroupSyncSender<T>, Vec<Receiver<T>>) {
    let mut senders = Vec::with_capacity(size);
    let mut receivers = Vec::with_capacity(size);
    for _ in 0..size {
        let (s, r) = sync_channel(bound);
        senders.push(s);
        receivers.push(r);
    }
    (
        GroupSyncSender {
            count: 0,
            base: senders,
        },
        receivers,
    )
}

pub struct GroupSyncSender<T> {
    count: usize,
    base: Vec<SyncSender<T>>,
}

impl<T> GroupSyncSender<T> {
    pub fn send(&mut self, t: T) -> Result<(), SendError<T>> {
        self.count += 1;
        self.base[self.count % self.base.len()].send(t)
    }
}
