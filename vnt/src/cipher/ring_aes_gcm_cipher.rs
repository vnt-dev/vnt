use std::io;
use rand::RngCore;
use ring::aead;
use ring::aead::{LessSafeKey, UnboundKey};
use crate::cipher::Finger;

use crate::protocol::NetPacket;
use crate::protocol::body::{ENCRYPTION_RESERVED, SecretBody};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
    pub(crate) finger: Finger,
}

pub enum AesGcmEnum {
    AesGCM128(LessSafeKey, [u8; 16]),
    AesGCM256(LessSafeKey, [u8; 32]),
}

impl Clone for AesGcmEnum {
    fn clone(&self) -> Self {
        match &self {
            AesGcmEnum::AesGCM128(_, key) => {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM128(c, *key)
            }
            AesGcmEnum::AesGCM256(_, key) => {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                AesGcmEnum::AesGCM256(c, *key)
            }
        }
    }
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16], finger: Finger) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM128(cipher, key),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Finger) -> Self {
        let cipher = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
        Self {
            cipher: AesGcmEnum::AesGCM256(cipher, key),
            finger,
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(io::Error::new(io::ErrorKind::Other, "not encrypt"));
        }
        if net_packet.payload().len() < ENCRYPTION_RESERVED {
            log::error!("数据异常,长度小于{}",ENCRYPTION_RESERVED);
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
        }
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);
        let mut secret_body = SecretBody::new(net_packet.payload_mut())?;
        let tag = secret_body.tag();
        let finger = self.finger.calculate_finger(&nonce_raw, secret_body.en_body());
        if &finger != secret_body.finger() {
            return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
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
            return Err(io::Error::new(io::ErrorKind::Other, format!("解密失败:{}", e)));
        }
        net_packet.set_encrypt_flag(false);
        net_packet.set_data_len(net_packet.data_len() - ENCRYPTION_RESERVED)?;
        return Ok(());
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    /// 返回加密后载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let nonce = aead::Nonce::assume_unique_for_key(nonce_raw);
        let data_len = net_packet.data_len() + ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = SecretBody::new(net_packet.payload_mut())?;
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
                    return Err(io::Error::new(io::ErrorKind::Other, format!("加密tag长度错误:{}", tag.len())));
                }
                secret_body.set_tag(tag)?;
                let finger = self.finger.calculate_finger(&nonce_raw, secret_body.en_body());
                secret_body.set_finger(&finger)?;
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("加密失败:{}", e)))
            }
        };
    }
}