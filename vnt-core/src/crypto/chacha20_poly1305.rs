use crate::protocol::ip_packet_protocol::{HEAD_LENGTH, NetPacket};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use subtle::ConstantTimeEq;

pub const TAG_LEN: usize = 16;
pub const FEC_AUTH_TAG_LEN: usize = 16;
const FEC_AUTH_KEY_LABEL: &[u8] = b"vnt-fec-auth-v1";

#[derive(Clone)]
pub struct PacketCrypto {
    key: LessSafeKey,
    fec_auth_key: hmac::Key,
    /// 出站包序号，用于构造唯一 nonce。Clone 共享同一计数器。
    /// 随机起始值可避免进程重启后（相同密钥）复用低序号段的 nonce。
    seq: Arc<AtomicU32>,
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
    pub fn new(key_bytes: [u8; 32]) -> io::Result<Self> {
        let derivation_key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let derived_auth_key = hmac::sign(&derivation_key, FEC_AUTH_KEY_LABEL);
        let fec_auth_key = hmac::Key::new(hmac::HMAC_SHA256, derived_auth_key.as_ref());
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| io::Error::other("failed to initialize ChaCha20-Poly1305 key"))?;
        let key = LessSafeKey::new(unbound);
        Ok(Self {
            key,
            fec_auth_key,
            seq: Arc::new(AtomicU32::new(rand::random())),
        })
    }
    pub fn new_from_str(s: &str) -> io::Result<Self> {
        let hash = ring::digest::digest(&ring::digest::SHA256, s.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(hash.as_ref());
        Self::new(key_bytes)
    }
    /// 根据包头生成 12 字节 nonce。
    /// nonce 只承担"唯一性"职责：seq（随机起始计数器）+ src + dst，
    /// 三者构成每个 (src, dst) 流内不重复的 96 位值；
    /// 头部其余字段的完整性认证由 AAD 负责，与 nonce 无关。
    pub fn make_nonce<B: AsRef<[u8]>>(&self, pkt: &NetPacket<B>) -> io::Result<[u8; 12]> {
        let buf = pkt.buffer();

        if buf.len() < HEAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small",
            ));
        }
        let seq = &buf[4..8];
        let src = &buf[8..12];
        let dst = &buf[12..16];

        let mut nonce12 = [0u8; 12];
        nonce12[0..4].copy_from_slice(seq);
        nonce12[4..8].copy_from_slice(dst);
        nonce12[8..12].copy_from_slice(src);

        Ok(nonce12)
    }

    /// AAD 承担"认证"职责：覆盖传输中不变、但不参与 nonce 的头部字节
    /// byte0(msg_type)/byte2(flags)/byte3(reserved)。
    /// msg_type 与 flags（COMPRESSED/FEC/GATEWAY/ETHERNET）只由发送方设置、
    /// 传输中不会被修改，必须纳入认证，否则中间人可翻转造成不可检测的
    /// 丢包/语义篡改；ttl(byte1) 在中继转发时会递减，不能纳入 AAD。
    fn make_aad<B: AsRef<[u8]>>(pkt: &NetPacket<B>) -> [u8; 3] {
        let buf = pkt.buffer();
        if buf.len() < HEAD_LENGTH {
            return [0; 3];
        }
        [buf[0], buf[2], buf[3]]
    }

    /// 计算 FEC 外层认证标签。只排除中继会递减的当前 TTL（低四位），
    /// 最大 TTL、其余头字段和完整 FEC payload 均参与认证。
    fn fec_auth_tag<B: AsRef<[u8]>>(
        &self,
        pkt: &NetPacket<B>,
        payload_len: usize,
    ) -> io::Result<[u8; FEC_AUTH_TAG_LEN]> {
        let buf = pkt.buffer();
        let packet_len = HEAD_LENGTH
            .checked_add(payload_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "packet too large"))?;
        if buf.len() < packet_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for FEC authentication",
            ));
        }

        let mut ctx = hmac::Context::with_key(&self.fec_auth_key);
        ctx.update(&buf[0..1]);
        ctx.update(&[buf[1] & 0xF0]);
        ctx.update(&buf[2..HEAD_LENGTH]);
        ctx.update(&buf[HEAD_LENGTH..packet_len]);
        let full_tag = ctx.sign();
        let mut tag = [0u8; FEC_AUTH_TAG_LEN];
        tag.copy_from_slice(&full_tag.as_ref()[..FEC_AUTH_TAG_LEN]);
        Ok(tag)
    }

    pub fn authenticate_fec_in_place<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        let payload_len = pkt
            .payload()
            .len()
            .checked_sub(FEC_AUTH_TAG_LEN)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing FEC authentication reserve",
                )
            })?;
        let tag = self.fec_auth_tag(pkt, payload_len)?;
        pkt.payload_mut()[payload_len..].copy_from_slice(&tag);
        Ok(())
    }

    pub fn verify_fec<B: AsRef<[u8]>>(&self, pkt: &NetPacket<B>) -> io::Result<()> {
        let payload_len = pkt
            .payload()
            .len()
            .checked_sub(FEC_AUTH_TAG_LEN)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "missing FEC authentication tag")
            })?;
        let expected = self.fec_auth_tag(pkt, payload_len)?;
        let actual = &pkt.payload()[payload_len..];
        if bool::from(expected.as_slice().ct_eq(actual)) {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid FEC authentication tag",
            ))
        }
    }

    /// 原地加密（in-place）
    /// payload 后需要预留16字节用于存放 tag
    pub fn encrypt_in_place<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        pkt: &mut NetPacket<B>,
    ) -> io::Result<()> {
        // 为每个出站包分配递增 seq，保证同一 (src, dst) 流内 nonce 不重复
        // （seq 占满 4 字节，约 43 亿个包后才回绕）
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        pkt.set_seq(seq);
        let nonce = Nonce::assume_unique_for_key(self.make_nonce(pkt)?);
        let aad = Aad::from(Self::make_aad(pkt));

        let payload = pkt.payload_mut();
        let payload_len = payload.len() - TAG_LEN; // 实际 payload 长度（不含 tag 预留空间）

        // 只加密实际的 payload 部分
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut payload[..payload_len])
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
        let aad = Aad::from(Self::make_aad(pkt));

        let payload_with_tag = pkt.payload_mut();

        let plaintext = self
            .key
            .open_in_place(nonce, aad, payload_with_tag)
            .map_err(|_| io::Error::other("decrypt failed"))?;
        Ok(plaintext.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ip_packet_protocol::MsgType;
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
        let crypto = PacketCrypto::new(key).unwrap();

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

    #[test]
    fn test_nonce_unique_per_packet() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();

        let mut pkt1 = build_test_packet(20);
        let mut pkt2 = build_test_packet(20);

        let nonce1 = crypto.make_nonce(&pkt1).unwrap();
        crypto.encrypt_in_place(&mut pkt1).expect("encrypt failed");
        crypto.encrypt_in_place(&mut pkt2).expect("encrypt failed");
        let nonce2 = crypto.make_nonce(&pkt1).unwrap();
        let nonce3 = crypto.make_nonce(&pkt2).unwrap();

        // 加密会自动分配递增 seq，两个相同头部的包 nonce 必须不同
        assert_eq!(pkt1.seq() + 1, pkt2.seq());
        assert_ne!(nonce1, nonce2);
        assert_ne!(nonce2, nonce3);
        // 密文也必须不同（相同明文、不同 nonce）
        assert_ne!(pkt1.buffer(), pkt2.buffer());

        // 两个包都能正常解密（头部 seq 不同，只比较 payload 区域）
        crypto.decrypt_in_place(&mut pkt1).expect("decrypt failed");
        crypto.decrypt_in_place(&mut pkt2).expect("decrypt failed");
        assert_eq!(
            &pkt1.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20],
            &pkt2.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20]
        );
    }

    #[test]
    fn test_clone_shares_seq_counter() {
        let crypto = PacketCrypto::new([9u8; 32]).unwrap();
        let cloned = crypto.clone();

        let mut pkt1 = build_test_packet(8);
        let mut pkt2 = build_test_packet(8);
        crypto.encrypt_in_place(&mut pkt1).expect("encrypt failed");
        cloned.encrypt_in_place(&mut pkt2).expect("encrypt failed");

        assert_eq!(pkt1.seq() + 1, pkt2.seq());
    }

    /// nonce 与 AAD 完全由包自带的头部字节推导，与发送端状态无关：
    /// 即使对端用自己的 seq 状态发包，本端仅凭头部即可正确解密。
    #[test]
    fn test_cross_version_compat() {
        let key = [7u8; 32];
        let crypto = PacketCrypto::new(key).unwrap();
        // 用相同密钥的另一个实例模拟对端
        let peer = PacketCrypto::new(key).unwrap();

        // 模拟旧版本发包：seq 固定为 0，nonce 直接由头部计算
        let mut pkt = build_test_packet(20);
        let original: Vec<u8> = pkt.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20].to_vec();
        pkt.set_seq(0);
        let nonce = Nonce::assume_unique_for_key(peer.make_nonce(&pkt).unwrap());
        let aad = Aad::from(PacketCrypto::make_aad(&pkt));
        let payload = pkt.payload_mut();
        let payload_len = payload.len() - TAG_LEN;
        let tag = peer
            .key
            .seal_in_place_separate_tag(nonce, aad, &mut payload[..payload_len])
            .unwrap();
        payload[payload_len..payload_len + TAG_LEN].copy_from_slice(tag.as_ref());

        // 新版本解密旧版本的包
        crypto.decrypt_in_place(&mut pkt).expect("decrypt failed");
        assert_eq!(&pkt.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20], &original[..]);

        // 反向：新版本发(自动分配 seq)，旧版本逻辑解密(nonce 只读头部)
        let mut pkt2 = build_test_packet(20);
        let original2: Vec<u8> = pkt2.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20].to_vec();
        crypto.encrypt_in_place(&mut pkt2).expect("encrypt failed");
        assert_ne!(pkt2.seq(), 0, "sanity check: new version assigns seq");
        peer.decrypt_in_place(&mut pkt2).expect("decrypt failed");
        assert_eq!(
            &pkt2.buffer()[HEAD_LENGTH..HEAD_LENGTH + 20],
            &original2[..]
        );
    }

    /// AAD 覆盖 flags(byte2)：中间人翻转 COMPRESSED/FEC/GATEWAY 标志位
    /// 必须导致解密失败，而不是被静默接受。
    #[test]
    fn test_tampered_flags_rejected() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();

        let mut pkt = build_test_packet(20);
        crypto.encrypt_in_place(&mut pkt).expect("encrypt failed");

        // 翻转 flags 字节（模拟中间人篡改）
        pkt.set_fec_flag(true);

        assert!(
            crypto.decrypt_in_place(&mut pkt).is_err(),
            "tampered flags must fail authentication"
        );
    }

    /// AAD 覆盖 msg_type(byte0)：中间人篡改消息类型必须导致解密失败。
    #[test]
    fn test_tampered_msg_type_rejected() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();

        let mut pkt = build_test_packet(20);
        crypto.encrypt_in_place(&mut pkt).expect("encrypt failed");

        pkt.set_msg_type(MsgType::Pong);

        assert!(
            crypto.decrypt_in_place(&mut pkt).is_err(),
            "tampered msg_type must fail authentication"
        );
    }

    /// ttl(byte1) 在中继转发时会递减，不属于 AAD：
    /// 转发后 ttl 变化的包必须仍能正常解密。
    #[test]
    fn test_ttl_change_still_decrypts() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();

        let payload_len = 20;
        let mut pkt = build_test_packet(payload_len);
        pkt.set_ttl(15); // 初始 ttl
        let original: Vec<u8> = pkt.buffer()[HEAD_LENGTH..HEAD_LENGTH + payload_len].to_vec();
        crypto.encrypt_in_place(&mut pkt).expect("encrypt failed");

        // 模拟中继递减 ttl
        pkt.set_ttl(14);

        crypto
            .decrypt_in_place(&mut pkt)
            .expect("ttl change must not break decryption");
        assert_eq!(
            &pkt.buffer()[HEAD_LENGTH..HEAD_LENGTH + payload_len],
            &original[..]
        );
    }

    fn build_fec_auth_packet(payload_len: usize) -> NetPacket<BytesMut> {
        let mut packet = NetPacket::new(BytesMut::zeroed(
            HEAD_LENGTH + payload_len + FEC_AUTH_TAG_LEN,
        ))
        .unwrap();
        packet.set_msg_type(MsgType::Turn);
        packet.set_ttl(5);
        packet.set_seq(0x1234_5678);
        packet.set_src_id(0x0A00_0001);
        packet.set_dest_id(0x0A00_0002);
        packet.set_fec_flag(true);
        for (i, byte) in packet.payload_mut()[..payload_len].iter_mut().enumerate() {
            *byte = i as u8 ^ 0xA5;
        }
        packet
    }

    #[test]
    fn fec_auth_accepts_current_ttl_change() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();
        let mut packet = build_fec_auth_packet(32);
        crypto.authenticate_fec_in_place(&mut packet).unwrap();

        packet.decr_ttl();
        crypto.verify_fec(&packet).unwrap();
    }

    #[test]
    fn fec_auth_rejects_authenticated_field_tampering() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();

        let assert_rejected = |mutate: fn(&mut NetPacket<BytesMut>)| {
            let mut packet = build_fec_auth_packet(32);
            crypto.authenticate_fec_in_place(&mut packet).unwrap();
            mutate(&mut packet);
            assert!(crypto.verify_fec(&packet).is_err());
        };

        assert_rejected(|packet| packet.set_msg_type(MsgType::Pong));
        assert_rejected(|packet| packet.head_mut()[1] ^= 0x10);
        assert_rejected(|packet| packet.set_ethernet_flag(true));
        assert_rejected(|packet| packet.set_src_id(0x0A00_0003));
        assert_rejected(|packet| packet.set_dest_id(0x0A00_0004));
        assert_rejected(|packet| packet.payload_mut()[0] ^= 1);
    }

    #[test]
    fn fec_auth_rejects_wrong_missing_truncated_and_random_tags() {
        let crypto = PacketCrypto::new([7u8; 32]).unwrap();
        let wrong_crypto = PacketCrypto::new([8u8; 32]).unwrap();
        let mut packet = build_fec_auth_packet(32);
        crypto.authenticate_fec_in_place(&mut packet).unwrap();
        assert!(wrong_crypto.verify_fec(&packet).is_err());

        packet.payload_mut()[32..].fill(0x5A);
        assert!(crypto.verify_fec(&packet).is_err());

        let missing = NetPacket::new(BytesMut::zeroed(HEAD_LENGTH + 8)).unwrap();
        assert!(crypto.verify_fec(&missing).is_err());

        let mut truncated = build_fec_auth_packet(32);
        crypto.authenticate_fec_in_place(&mut truncated).unwrap();
        let mut truncated = truncated.into_buffer();
        truncated.truncate(truncated.len() - 1);
        assert!(
            crypto
                .verify_fec(&NetPacket::new(truncated).unwrap())
                .is_err()
        );
    }
}
