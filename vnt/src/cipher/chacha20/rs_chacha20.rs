use aes::cipher::Iv;
use anyhow::anyhow;
use chacha20::cipher::{Key, KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

use crate::cipher::Finger;
use crate::protocol::body::ChaCah20SecretBody;
use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct ChaCha20Cipher {
    key: [u8; 32],
    pub(crate) finger: Option<Finger>,
}

impl ChaCha20Cipher {
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        Self { key, finger }
    }
}

impl ChaCha20Cipher {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl ChaCha20Cipher {
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        let mut iv = [0; 12];
        iv[0..4].copy_from_slice(&net_packet.source().octets());
        iv[4..8].copy_from_slice(&net_packet.destination().octets());
        iv[8] = net_packet.protocol().into();
        iv[9] = net_packet.transport_protocol();
        iv[10] = net_packet.is_gateway() as u8;
        iv[11] = net_packet.source_ttl();

        let mut secret_body =
            ChaCah20SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&iv[..12], secret_body.en_body());
            if &finger != secret_body.finger() {
                return Err(anyhow!("ChaCha20 finger err"));
            }
        }

        ChaCha20::new(
            Key::<ChaCha20>::from_slice(&self.key),
            Iv::<ChaCha20>::from_slice(&iv),
        )
        .apply_keystream(secret_body.en_body_mut());
        let len = secret_body.en_body().len();
        net_packet.set_encrypt_flag(false);
        net_packet.set_payload_len(len)?;
        Ok(())
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let data_len = net_packet.data_len();
        let mut iv = [0; 12];
        iv[0..4].copy_from_slice(&net_packet.source().octets());
        iv[4..8].copy_from_slice(&net_packet.destination().octets());
        iv[8] = net_packet.protocol().into();
        iv[9] = net_packet.transport_protocol();
        iv[10] = net_packet.is_gateway() as u8;
        iv[11] = net_packet.source_ttl();
        if let Some(_) = &self.finger {
            net_packet.set_data_len(data_len + 12)?;
        }
        let mut secret_body =
            ChaCah20SecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        ChaCha20::new(
            Key::<ChaCha20>::from_slice(&self.key),
            Iv::<ChaCha20>::from_slice(&iv),
        )
        .apply_keystream(secret_body.en_body_mut());
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&iv[..12], secret_body.en_body_mut());
            let mut secret_body = ChaCah20SecretBody::new(net_packet.payload_mut(), true)?;
            secret_body.set_finger(&finger)?;
        }

        net_packet.set_encrypt_flag(true);
        Ok(())
    }
}

#[test]
fn test_chacha20() {
    let d = ChaCha20Cipher::new_256([0; 32], Some(Finger::new("123")));
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);

    let d = ChaCha20Cipher::new_256([0; 32], None);
    let mut p =
        NetPacket::new_encrypt([0; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
