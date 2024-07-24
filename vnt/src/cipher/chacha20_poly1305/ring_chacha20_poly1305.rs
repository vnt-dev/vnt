use anyhow::anyhow;

use ring::aead;
use ring::aead::{LessSafeKey, UnboundKey};

use crate::cipher::finger::{gen_nonce, gen_random_nonce};
use crate::cipher::Finger;
use crate::protocol::body::{
    AEADSecretBody, SecretTail, SecretTailMut, FINGER_RESERVED, RANDOM_RESERVED, TAG_RESERVED,
};
use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct ChaCha20Poly1305Cipher {
    key: Vec<u8>,
    pub(crate) cipher: LessSafeKey,
    pub(crate) finger: Option<Finger>,
}

impl ChaCha20Poly1305Cipher {
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &key).unwrap());
        Self {
            key: key.to_vec(),
            cipher,
            finger,
        }
    }
}

impl ChaCha20Poly1305Cipher {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl ChaCha20Poly1305Cipher {
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        if net_packet.payload().len() < TAG_RESERVED {
            log::error!("数据异常,长度小于{}", TAG_RESERVED);
            return Err(anyhow!("data err"));
        }
        let mut head_tag = net_packet.head_tag();
        let mut secret_body = AEADSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&head_tag, secret_body.data_tag_mut());
            if &finger != secret_body.finger() {
                return Err(anyhow!("ring CHACHA20_POLY1305 finger err"));
            }
        }
        gen_nonce(&mut head_tag, secret_body.random_buf());
        let nonce = aead::Nonce::assume_unique_for_key(head_tag);
        let rs = self
            .cipher
            .open_in_place(nonce, aead::Aad::empty(), secret_body.data_tag_mut());
        if let Err(e) = rs {
            return Err(anyhow!("ring CHACHA20_POLY1305 解密失败:{}", e));
        }
        let len = secret_body.data().len();
        net_packet.set_encrypt_flag(false);
        net_packet.set_payload_len(len)?;
        return Ok(());
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    /// 返回加密后载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let head_tag = net_packet.head_tag();
        let data_len = net_packet.data_len();
        if self.finger.is_some() {
            net_packet.set_data_len(data_len + TAG_RESERVED + RANDOM_RESERVED + FINGER_RESERVED)?;
        } else {
            net_packet.set_data_len(data_len + TAG_RESERVED + RANDOM_RESERVED)?;
        }
        let mut secret_body = AEADSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        let mut nonce = head_tag;
        secret_body.set_random(&gen_random_nonce(&mut nonce));
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let rs = self.cipher.seal_in_place_separate_tag(
            nonce,
            aead::Aad::empty(),
            secret_body.data_mut(),
        );
        match rs {
            Ok(tag) => {
                let tag = tag.as_ref();
                if tag.len() != 16 {
                    return Err(anyhow!("加密tag长度错误:{}", tag.len()));
                }
                secret_body.set_tag(tag)?;
                if let Some(finger) = &self.finger {
                    let finger = finger.calculate_finger(&head_tag, secret_body.data_tag_mut());
                    secret_body.set_finger(&finger)?;
                }
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(anyhow!("ring CHACHA20_POLY1305 加密失败:{}", e)),
        }
    }
}

#[test]
fn test_ring_chacha20_poly1305() {
    let d = ChaCha20Poly1305Cipher::new_256([0; 32], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([0; 73]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
    let d = ChaCha20Poly1305Cipher::new_256([0; 32], None);
    let mut p = NetPacket::new_encrypt([0; 73]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
