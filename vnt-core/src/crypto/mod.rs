use crate::crypto::chacha20_poly1305::{FEC_AUTH_TAG_LEN, TAG_LEN};
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

    pub(crate) fn new_from_str(s: Option<&str>) -> io::Result<Self> {
        let crypto = s
            .map(chacha20_poly1305::PacketCrypto::new_from_str)
            .transpose()?
            .map(Arc::new);
        Ok(Self { crypto })
    }
    pub(crate) fn encrypt_reserve(&self) -> usize {
        if self.crypto.is_some() { TAG_LEN } else { 0 }
    }
    pub(crate) fn fec_auth_reserve(&self) -> usize {
        if self.crypto.is_some() {
            FEC_AUTH_TAG_LEN
        } else {
            0
        }
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
    pub(crate) fn authenticate_fec_in_place<B: AsRef<[u8]> + AsMut<[u8]> + ExtendEnd>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(crypto) = self.crypto.as_ref() {
            pkt.source_buf_mut().extend_end(FEC_AUTH_TAG_LEN);
            crypto.authenticate_fec_in_place(pkt)?;
        }
        Ok(())
    }
    pub(crate) fn verify_fec_in_place<B: AsRef<[u8]> + AsMut<[u8]> + ShrinkEnd>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        if let Some(crypto) = self.crypto.as_ref() {
            crypto.verify_fec(pkt)?;
            pkt.source_buf_mut().shrink_end(FEC_AUTH_TAG_LEN);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, MsgType};
    use crate::protocol::transmission::TransmissionBytes;

    #[test]
    fn fec_auth_is_noop_without_password() {
        let crypto = PacketCrypto::new_from_str(None).unwrap();
        let mut packet = NetPacket::new(TransmissionBytes::zeroed(HEAD_LENGTH + 8)).unwrap();
        packet.set_msg_type(MsgType::Turn);
        packet.set_fec_flag(true);
        let original = packet.buffer().to_vec();

        crypto.authenticate_fec_in_place(&mut packet).unwrap();
        assert_eq!(crypto.fec_auth_reserve(), 0);
        assert_eq!(packet.buffer(), original);
        crypto.verify_fec_in_place(&mut packet).unwrap();
        assert_eq!(packet.buffer(), original);
    }
}
