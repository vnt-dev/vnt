use bytes::BytesMut;
use prost::Message;

pub(crate) mod client_message;
pub mod control_message;
pub(crate) mod ip_packet_protocol;
pub(crate) mod rpc_message;
pub(crate) mod transmission;

pub trait ProtoToBytesMut: Message {
    fn encode_bytes_mut(&self) -> BytesMut
    where
        Self: Sized,
    {
        let mut bytes_mut = BytesMut::with_capacity(self.encoded_len());
        self.encode_raw(&mut bytes_mut);
        bytes_mut
    }
}

impl<T: Message> ProtoToBytesMut for T {}
