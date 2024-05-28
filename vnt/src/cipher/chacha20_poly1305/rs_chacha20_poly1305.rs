use anyhow::anyhow;
use chacha20poly1305::aead::{Nonce, Tag};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, Key, KeyInit};

use crate::cipher::Finger;
use crate::protocol::body::{SecretBody, AES_GCM_ENCRYPTION_RESERVED};
use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct ChaCha20Poly1305Cipher {
    key: Vec<u8>,
    pub(crate) cipher: ChaCha20Poly1305,
    pub(crate) finger: Option<Finger>,
}

impl ChaCha20Poly1305Cipher {
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        let key: &Key = &key.into();
        let cipher = ChaCha20Poly1305::new(key);
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
        if net_packet.payload().len() < AES_GCM_ENCRYPTION_RESERVED {
            log::error!("数据异常,长度小于{}", AES_GCM_ENCRYPTION_RESERVED);
            return Err(anyhow!("data err"));
        }
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&nonce_raw, secret_body.en_body());
            if &finger != secret_body.finger() {
                return Err(anyhow!("rs CHACHA20_POLY1305 finger err"));
            }
        }
        let nonce: Nonce<ChaCha20Poly1305> = nonce_raw.into();
        let tag: Tag<ChaCha20Poly1305> =
            Tag::<ChaCha20Poly1305>::from_slice(secret_body.tag()).clone();
        if let Err(e) =
            self.cipher
                .decrypt_in_place_detached(&nonce, &[], secret_body.body_mut(), &tag)
        {
            return Err(anyhow!("rs CHACHA20_POLY1305 decrypt_ipv4 {:?}", e));
        }
        net_packet.set_encrypt_flag(false);
        net_packet.set_data_len(net_packet.data_len() - AES_GCM_ENCRYPTION_RESERVED)?;
        Ok(())
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    /// 返回加密后载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let nonce = nonce_raw.into();
        let data_len = net_packet.data_len() + AES_GCM_ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut secret_body = SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        let rs = self
            .cipher
            .encrypt_in_place_detached(&nonce, &[], secret_body.body_mut());
        return match rs {
            Ok(tag) => {
                let tag: &[u8] = tag.as_ref();
                if tag.len() != 16 {
                    return Err(anyhow!("加密tag长度错误:{}", tag.len(),));
                }
                secret_body.set_tag(tag)?;
                if let Some(finger) = &self.finger {
                    let finger = finger.calculate_finger(&nonce_raw, secret_body.en_body());
                    secret_body.set_finger(&finger)?;
                }
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(anyhow!("rs CHACHA20_POLY1305 加密失败:{}", e)),
        };
    }
}

#[test]
fn test_rs_chacha20_poly1305() {
    let d = ChaCha20Poly1305Cipher::new_256([0; 32], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([0; 73]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
