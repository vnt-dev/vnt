use crate::channel::channel::Context;
use std::ops::Deref;

#[derive(Clone)]
pub struct ChannelSender {
    context: Context,
}

impl ChannelSender {
    pub fn new(context: Context) -> Self {
        Self { context }
    }
}

impl Deref for ChannelSender {
    type Target = Context;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}
