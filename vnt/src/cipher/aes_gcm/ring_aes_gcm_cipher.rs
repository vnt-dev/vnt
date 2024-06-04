use anyhow::anyhow;
use rand::RngCore;
use ring::aead;
use ring::aead::{LessSafeKey, UnboundKey};

use crate::cipher::Finger;
use crate::protocol::body::{SecretBody, AES_GCM_ENCRYPTION_RESERVED};
use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
    pub(crate) finger: Option<Finger>,
}

pub enum AesGcmEnum {
    AesGCM128(LessSafeKey, [u8; 16]),
    AesGCM256(LessSafeKey, [u8; 32]),
}

impl Clone for AesGcmEnum {
    fn clone(&self) -> Self {
        match &self {
            AesGcmEnum::AesGCM128(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM128(c, *key)
            }
            AesGcmEnum::AesGCM256(_, key) => {
                let c =
                    LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM256(c, *key)
            }
        }
    }
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM128(cipher, key),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM256(cipher, key),
            finger,
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        if net_packet.payload().len() < AES_GCM_ENCRYPTION_RESERVED {
            log::error!("数据异常,长度小于{}", AES_GCM_ENCRYPTION_RESERVED);
            return Err(anyhow!("data err"));
        }
        let nonce_raw = net_packet.head_tag();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);
        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&nonce_raw, secret_body.en_body());
            if &finger != secret_body.finger() {
                return Err(anyhow!("ring aes finger err"));
            }
        }

        let rs = match &self.cipher {
            AesGcmEnum::AesGCM128(cipher, _) => {
                cipher.open_in_place(nonce, aead::Aad::empty(), secret_body.en_body_mut())
            }
            AesGcmEnum::AesGCM256(cipher, _) => {
                cipher.open_in_place(nonce, aead::Aad::empty(), secret_body.en_body_mut())
            }
        };
        if let Err(e) = rs {
            return Err(anyhow!("解密失败:{}", e));
        }
        net_packet.set_encrypt_flag(false);
        net_packet.set_data_len(net_packet.data_len() - AES_GCM_ENCRYPTION_RESERVED)?;
        return Ok(());
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    /// 返回加密后载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let nonce_raw = net_packet.head_tag();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);
        let data_len = net_packet.data_len() + AES_GCM_ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        secret_body.set_random(rand::thread_rng().next_u32());

        let rs = match &self.cipher {
            AesGcmEnum::AesGCM128(cipher, _) => {
                cipher.seal_in_place_separate_tag(nonce, aead::Aad::empty(), secret_body.body_mut())
            }
            AesGcmEnum::AesGCM256(cipher, _) => {
                cipher.seal_in_place_separate_tag(nonce, aead::Aad::empty(), secret_body.body_mut())
            }
        };
        return match rs {
            Ok(tag) => {
                let tag = tag.as_ref();
                if tag.len() != 16 {
                    return Err(anyhow!("加密tag长度错误:{}", tag.len()));
                }
                secret_body.set_tag(tag)?;
                if let Some(finger) = &self.finger {
                    let finger = finger.calculate_finger(&nonce_raw, secret_body.en_body());
                    secret_body.set_finger(&finger)?;
                }
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(anyhow!("加密失败:{}", e)),
        };
    }
}

#[test]
fn test_aes_gcm() {
    let d = AesGcmCipher::new_256([0; 32], Some(Finger::new("123")));
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);

    let d = AesGcmCipher::new_256([0; 32], None);
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
