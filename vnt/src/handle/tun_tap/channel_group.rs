#[derive(Clone)]
pub struct BufSenderGroup(
    usize,
    Vec<std::sync::mpsc::SyncSender<(Vec<u8>, usize, usize)>>,
);

pub struct BufReceiverGroup(pub Vec<std::sync::mpsc::Receiver<(Vec<u8>, usize, usize)>>);

impl BufSenderGroup {
    pub fn send(&mut self, val: (Vec<u8>, usize, usize)) -> bool {
        let index = self.0 % self.1.len();
        self.0 = self.0.wrapping_add(1);
        self.1[index].send(val).is_ok()
    }
}

pub fn buf_channel_group(size: usize) -> (BufSenderGroup, BufReceiverGroup) {
    let mut buf_sender_group = Vec::with_capacity(size);
    let mut buf_receiver_group = Vec::with_capacity(size);
    for _ in 0..size {
        let (buf_sender, buf_receiver) =
            std::sync::mpsc::sync_channel::<(Vec<u8>, usize, usize)>(1);
        buf_sender_group.push(buf_sender);
        buf_receiver_group.push(buf_receiver);
    }
    (
        BufSenderGroup(0, buf_sender_group),
        BufReceiverGroup(buf_receiver_group),
    )
}
