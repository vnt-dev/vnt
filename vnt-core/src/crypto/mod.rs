use crate::crypto::chacha20_poly1305::TAG_LEN;
use crate::protocol::ip_packet_protocol::NetPacket;
use std::io;
use std::sync::Arc;

mod chacha20_poly1305;

use crate::protocol::transmission::{ExtendEnd, ShrinkEnd};

#[derive(Clone)]
pub(crate) struct PacketCrypto {
    crypto: Option<Arc<chacha20_poly1305::PacketCrypto>>,
}
impl PacketCrypto {
    pub(crate) fn key_sign(s: &str) -> String {
        chacha20_poly1305::PacketCrypto::key_sign(s)
    }

    pub(crate) fn new_from_str(s: Option<&str>) -> Self {
        Self {
            crypto: s
                .map(chacha20_poly1305::PacketCrypto::new_from_str)
                .map(Arc::new),
        }
    }
    pub(crate) fn encrypt_reserve(&self) -> usize {
        if self.crypto.is_some() { TAG_LEN } else { 0 }
    }
    pub(crate) fn encrypt_in_place<B: AsRef<[u8]> + AsMut<[u8]> + ExtendEnd>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(crypto) = self.crypto.as_ref() {
            pkt.source_buf_mut().extend_end(TAG_LEN);
            return crypto.encrypt_in_place(pkt);
        }
        Ok(())
    }
    pub(crate) fn decrypt_in_place<B: AsRef<[u8]> + AsMut<[u8]> + ShrinkEnd>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(crypto) = self.crypto.as_ref() {
            let _ = crypto.decrypt_in_place(pkt)?;
            pkt.source_buf_mut().shrink_end(TAG_LEN);
        }
        Ok(())
    }
}
