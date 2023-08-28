use std::io;

use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce, Tag};
use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use rand::RngCore;

use crate::cipher::finger::Finger;
use crate::protocol::{body::ENCRYPTION_RESERVED, body::SecretBody, NetPacket};



#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
    pub(crate) finger: Finger,
}

#[derive(Clone)]
pub enum AesGcmEnum {
    AES128GCM(Aes128Gcm),
    AES256GCM(Aes256Gcm),
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16], finger: Finger) -> Self {
        let key: &Key<Aes128Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES128GCM(Aes128Gcm::new(key)),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Finger) -> Self {
        let key: &Key<Aes256Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES256GCM(Aes256Gcm::new(key)),
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
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);

        let mut secret_body = SecretBody::new(net_packet.payload_mut())?;
        let tag = secret_body.tag();
        let finger = self.finger.calculate_finger(&nonce_raw, secret_body.en_body());
        if &finger != secret_body.finger() {
            return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
        }
        let tag: GenericArray<u8, U16> = Tag::clone_from_slice(tag);
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => { aes_gcm.decrypt_in_place_detached(nonce, &[], secret_body.body_mut(), &tag) }
            AesGcmEnum::AES256GCM(aes_gcm) => { aes_gcm.decrypt_in_place_detached(nonce, &[], secret_body.body_mut(), &tag) }
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
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        if net_packet.reserve() < ENCRYPTION_RESERVED {
            return Err(io::Error::new(io::ErrorKind::Other, "too short"));
        }
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);
        let data_len = net_packet.data_len() + ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = SecretBody::new(net_packet.payload_mut())?;
        secret_body.set_random(rand::thread_rng().next_u32());
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => { aes_gcm.encrypt_in_place_detached(nonce, &[], secret_body.body_mut()) }
            AesGcmEnum::AES256GCM(aes_gcm) => { aes_gcm.encrypt_in_place_detached(nonce, &[], secret_body.body_mut()) }
        };
        return match rs {
            Ok(tag) => {
                secret_body.set_tag(tag.as_slice())?;
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