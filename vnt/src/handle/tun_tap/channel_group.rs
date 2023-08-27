use byte_pool::Block;

#[derive(Clone)]
pub struct BufSenderGroup(usize, Vec<tokio::sync::mpsc::Sender<(Block<'static>, usize, usize)>>);

pub struct BufReceiverGroup(pub Vec<tokio::sync::mpsc::Receiver<(Block<'static>, usize, usize)>>);

impl BufSenderGroup {
    pub async fn send(&mut self, val: (Block<'static>, usize, usize)) -> bool {
        let index = self.0 % self.1.len();
        self.0 = self.0.wrapping_add(1);
        self.1[index].send(val).await.is_ok()
    }
}

pub fn buf_channel_group(size: usize) -> (BufSenderGroup, BufReceiverGroup) {
    let mut buf_sender_group = Vec::with_capacity(size);
    let mut buf_receiver_group = Vec::with_capacity(size);
    for _ in 0..size {
        let (buf_sender, buf_receiver) = tokio::sync::mpsc::channel::<(Block<'static>, usize, usize)>(10);
        buf_sender_group.push(buf_sender);
        buf_receiver_group.push(buf_receiver);
    }
    (BufSenderGroup(0, buf_sender_group), BufReceiverGroup(buf_receiver_group))
}