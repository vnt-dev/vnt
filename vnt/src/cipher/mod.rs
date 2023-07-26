use std::io;
use ring::aead;
use ring::aead::{LessSafeKey, UnboundKey};
use sha2::Digest;

use crate::protocol;
use crate::protocol::{ip_turn_packet, NetPacket};

pub enum Cipher {
    AesGCM128(LessSafeKey, [u8; 16]),
    AesGCM256(LessSafeKey, [u8; 32]),
    None,
}

impl Clone for Cipher {
    fn clone(&self) -> Self {
        match &self {
            Cipher::AesGCM128(_, key) => {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key.as_slice()).unwrap());
                Cipher::AesGCM128(c, *key)
            }
            Cipher::AesGCM256(_, key) => {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, key.as_slice()).unwrap());
                Cipher::AesGCM256(c, *key)
            }
            Cipher::None => {
                Cipher::None
            }
        }
    }
}

impl Cipher {
    pub fn new(password: Option<String>) -> Self {
        if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            if password.len() < 8 {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key[..16]).unwrap());
                Cipher::AesGCM128(c, key[..16].try_into().unwrap())
            } else {
                let c = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &key).unwrap());
                Cipher::AesGCM256(c, key)
            }
        } else {
            Cipher::None
        }
    }
    pub fn decrypt_ipv4(&self, net_packet: &mut NetPacket<&mut [u8]>) -> io::Result<Option<usize>> {
        match &self {
            Cipher::None => {
                return Ok(None);
            }
            _ => {}
        }
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(io::Error::new(io::ErrorKind::Other, "not encrypt"));
        }
        if net_packet.payload().len() < 16 {
            log::error!("数据异常,长度小于16");
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
        }
        let mut nonce = [0; 12];
        nonce[0..4].copy_from_slice(&net_packet.source().octets());
        nonce[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce[8] = protocol::Protocol::IpTurn.into();
        nonce[9] = ip_turn_packet::Protocol::Ipv4.into();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let payload_len = net_packet.payload().len() - 16;
        let rs = match &self {
            Cipher::AesGCM128(cipher, _) => {
                cipher.open_in_place(nonce, aead::Aad::empty(), net_packet.payload_mut())
            }
            Cipher::AesGCM256(cipher, _) => {
                cipher.open_in_place(nonce, aead::Aad::empty(), net_packet.payload_mut())
            }
            Cipher::None => {
                return Ok(None);
            }
        };
        if let Err(e) = rs {
            return Err(io::Error::new(io::ErrorKind::Other, format!("解密失败:{}", e)));
        }
        return Ok(Some(payload_len));
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    /// 返回加密后载荷的长度
    pub fn encrypt_ipv4(&self, payload_len: usize, net_packet: &mut NetPacket<&mut [u8]>) -> io::Result<Option<usize>> {
        match &self {
            Cipher::None => {
                return Ok(None);
            }
            _ => {}
        }
        let mut nonce = [0; 12];
        nonce[0..4].copy_from_slice(&net_packet.source().octets());
        nonce[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce[8] = protocol::Protocol::IpTurn.into();
        nonce[9] = ip_turn_packet::Protocol::Ipv4.into();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let rs = match &self {
            Cipher::AesGCM128(cipher, _) => {
                cipher.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut net_packet.payload_mut()[..payload_len])
            }
            Cipher::AesGCM256(cipher, _) => {
                cipher.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut net_packet.payload_mut()[..payload_len])
            }
            Cipher::None => {
                return Ok(None);
            }
        };
        return match rs {
            Ok(tag) => {
                let tag = tag.as_ref();
                if tag.len() != 16 {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("加密tag长度错误:{}", tag.len())));
                }
                net_packet.set_encrypt_flag(true);
                net_packet.payload_mut()[payload_len..payload_len + 16].copy_from_slice(tag);
                Ok(Some(payload_len + 16))
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("加密失败:{}", e)))
            }
        };
    }
}