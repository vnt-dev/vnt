use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::io;

pub const TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct PacketCrypto {
    key: LessSafeKey,
}

impl PacketCrypto {
    pub fn key_sign(s: &str) -> String {
        use ring::digest::{Context, SHA256};

        const PREFIX: &[u8] = b"KEY-BEGIN";
        const SUFFIX: &[u8] = b"KEY-END";

        let mut ctx = Context::new(&SHA256);
        ctx.update(PREFIX);
        ctx.update(s.as_bytes());
        ctx.update(SUFFIX);
        let digest = ctx.finish();
        let mut key_bytes = [0u8; 16];
        key_bytes.copy_from_slice(&digest.as_ref()[..16]);
        key_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
    pub fn new(key_bytes: [u8; 32]) -> Self {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap();
        let key = LessSafeKey::new(unbound);
        Self { key }
    }
    pub fn new_from_str(s: &str) -> Self {
        let hash = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(hash.as_ref());
        Self::new(key_bytes)
    }
    /// 根据包头生成 12 字节 nonce
    pub fn make_nonce<B: AsRef<[u8]>>(&self, pkt: &NetPacket<B>) -> io::Result<[u8; 12]> {
        let buf = pkt.buffer();

        if buf.len() < HEAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        let msg_type = buf[0];
        let seq = &buf[4..8];
        let src = &buf[8..12];
        let dst = &buf[12..16];

        let mut nonce12 = [0u8; 12];
        nonce12[0..4].copy_from_slice(seq);
        nonce12[4..8].copy_from_slice(dst);
        nonce12[8..12].copy_from_slice(src);
        nonce12[0] = msg_type;

        Ok(nonce12)
    }

    /// 原地加密（in-place）
    /// payload 后需要预留16字节用于存放 tag
    pub fn encrypt_in_place<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        let nonce = Nonce::assume_unique_for_key(self.make_nonce(pkt)?);

        let payload = pkt.payload_mut();
        let payload_len = payload.len() - TAG_LEN; // 实际 payload 长度（不含 tag 预留空间）

        // 只加密实际的 payload 部分
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut payload[..payload_len])
            .map_err(|_| io::Error::other("encrypt failed"))?;

        // 将 tag 写入 payload 后的预留空间
        payload[payload_len..payload_len + TAG_LEN].copy_from_slice(tag.as_ref());

        Ok(())
    }

    /// 原地解密（in-place）
    pub fn decrypt_in_place<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<usize> {
        let nonce = Nonce::assume_unique_for_key(self.make_nonce(pkt)?);

        let payload_with_tag = pkt.payload_mut();

        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), payload_with_tag)
            .map_err(|_| io::Error::other("decrypt failed"))?;
        Ok(plaintext.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    // 用于构造一个简单的 NetPacket，包含头 16 字节 + payload + 16 字节 TAG 预留
    fn build_test_packet(payload_len: usize) -> NetPacket<BytesMut> {
        // 16 字节 head + payload + 16 字节预留 TAG
        let total_len = HEAD_LENGTH + payload_len + TAG_LEN;
        let mut buf = BytesMut::zeroed(total_len);

        // 构造一个头（16 字节）
        buf[0] = 4; // MsgType::Ping
        buf[4..8].copy_from_slice(&12345u32.to_be_bytes());
        buf[8..12].copy_from_slice(&111u32.to_be_bytes());
        buf[12..16].copy_from_slice(&222u32.to_be_bytes());

        // 构造 payload（明文）
        let payload_plain = &mut buf[HEAD_LENGTH..HEAD_LENGTH + payload_len];
        for (i, p) in payload_plain.iter_mut().enumerate() {
            *p = (i as u8) ^ 0xAB;
        }

        NetPacket::new(buf).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_in_place() {
        let key = [7u8; 32];
        let crypto = PacketCrypto::new(key);

        let payload_len = 20;
        let mut pkt = build_test_packet(payload_len);

        // 备份原 payload
        let original_payload: Vec<u8> =
            pkt.buffer()[HEAD_LENGTH..HEAD_LENGTH + payload_len].to_vec();

        // 加密
        crypto.encrypt_in_place(&mut pkt).expect("encrypt failed");

        let encrypted_buf = pkt.buffer();
        let tag_start = HEAD_LENGTH + payload_len;
        let tag_end = tag_start + TAG_LEN;

        // TAG 不应该是全 0
        assert_ne!(&encrypted_buf[tag_start..tag_end], &[0u8; TAG_LEN]);

        // payload 已被加密，不等于明文
        assert_ne!(
            &encrypted_buf[HEAD_LENGTH..HEAD_LENGTH + payload_len],
            &original_payload[..]
        );

        // 解密
        crypto.decrypt_in_place(&mut pkt).expect("decrypt failed");

        let decrypted_buf = pkt.buffer();
        let decrypted_payload = &decrypted_buf[HEAD_LENGTH..HEAD_LENGTH + payload_len];

        // 解密后与原文一致
        assert_eq!(decrypted_payload, &original_payload[..]);
    }
}
