use std::io;

use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, Nonce, Tag,KeyInit};
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use sha2::Digest;

use crate::protocol;
use crate::protocol::{ip_turn_packet, NetPacket};

#[derive(Clone)]
pub enum Cipher {
    AesGCM128(Aes128Gcm),
    AesGCM256(Aes256Gcm),
    None,
}

impl Cipher {
    pub fn new(password: Option<String>) -> Self {
        if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            if password.len() < 8 {
                let key: &Key<Aes128Gcm> = key[..16].into();
                Cipher::AesGCM128(Aes128Gcm::new(&key))
            } else {
                let key: &Key<Aes256Gcm> = &key.into();
                Cipher::AesGCM256(Aes256Gcm::new(&key))
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
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce);
        let payload_len = net_packet.payload().len() - 16;
        let tag: GenericArray<u8, U16> = Tag::clone_from_slice(&net_packet.payload()[payload_len..]);
        let rs = match &self {
            Cipher::AesGCM128(cipher) => {
                cipher.decrypt_in_place_detached(nonce, &[], &mut net_packet.payload_mut()[..payload_len], &tag)
            }
            Cipher::AesGCM256(cipher) => {
                cipher.decrypt_in_place_detached(nonce, &[], &mut net_packet.payload_mut()[..payload_len], &tag)
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
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce);
        let rs = match &self {
            Cipher::AesGCM128(cipher) => {
                cipher.encrypt_in_place_detached(nonce, &[], &mut net_packet.payload_mut()[..payload_len])
            }
            Cipher::AesGCM256(cipher) => {
                cipher.encrypt_in_place_detached(nonce, &[], &mut net_packet.payload_mut()[..payload_len])
            }
            Cipher::None => {
                return Ok(None);
            }
        };
        return match rs {
            Ok(tag) => {
                if tag.len() != 16 {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("加密tag长度错误:{}", tag.len())));
                }
                net_packet.set_encrypt_flag(true);
                net_packet.payload_mut()[payload_len..payload_len + 16].copy_from_slice(tag.as_slice());
                Ok(Some(payload_len + 16))
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("加密失败:{}", e)))
            }
        };
    }
}