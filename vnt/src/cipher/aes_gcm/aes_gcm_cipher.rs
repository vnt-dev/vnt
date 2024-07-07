use aes_gcm::aead::consts::{U12, U16};
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce, Tag};
use anyhow::anyhow;
use rand::RngCore;

use crate::cipher::finger::Finger;
use crate::protocol::{body::SecretBody, body::AES_GCM_ENCRYPTION_RESERVED, NetPacket};

#[derive(Clone)]
pub struct AesGcmCipher {
    pub(crate) cipher: AesGcmEnum,
    pub(crate) finger: Option<Finger>,
}

#[derive(Clone)]
pub enum AesGcmEnum {
    AES128GCM(Aes128Gcm),
    AES256GCM(Aes256Gcm),
}

impl AesGcmCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        let key: &Key<Aes128Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES128GCM(Aes128Gcm::new(key)),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        let key: &Key<Aes256Gcm> = &key.into();
        Self {
            cipher: AesGcmEnum::AES256GCM(Aes256Gcm::new(key)),
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
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);

        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        let tag = secret_body.tag();
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&nonce_raw, secret_body.en_body());
            if &finger != secret_body.finger() {
                return Err(anyhow!("finger err"));
            }
        }
        let tag: GenericArray<u8, U16> = Tag::clone_from_slice(tag);
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                aes_gcm.decrypt_in_place_detached(nonce, &[], secret_body.body_mut(), &tag)
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                aes_gcm.decrypt_in_place_detached(nonce, &[], secret_body.body_mut(), &tag)
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
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if net_packet.reserve() < AES_GCM_ENCRYPTION_RESERVED {
            return Err(anyhow!("too short"));
        }
        let nonce_raw = net_packet.head_tag();
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(&nonce_raw);
        let data_len = net_packet.data_len() + AES_GCM_ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        secret_body.set_random(rand::thread_rng().next_u32());
        let rs = match &self.cipher {
            AesGcmEnum::AES128GCM(aes_gcm) => {
                aes_gcm.encrypt_in_place_detached(nonce, &[], secret_body.body_mut())
            }
            AesGcmEnum::AES256GCM(aes_gcm) => {
                aes_gcm.encrypt_in_place_detached(nonce, &[], secret_body.body_mut())
            }
        };
        return match rs {
            Ok(tag) => {
                secret_body.set_tag(tag.as_slice())?;
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
        NetPacket::new_encrypt([1; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
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
