use aes::cipher::Iv;
use anyhow::anyhow;
use chacha20::cipher::{Key, KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

use crate::cipher::finger::{gen_nonce, gen_random_nonce};
use crate::cipher::Finger;
use crate::protocol::body::{
    IVSecretBody, SecretTail, SecretTailMut, FINGER_RESERVED, RANDOM_RESERVED,
};
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
        let mut head_tag = net_packet.head_tag();

        let mut secret_body = IVSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&head_tag, secret_body.data());
            if &finger != secret_body.finger() {
                return Err(anyhow!("ChaCha20 finger err"));
            }
        }
        gen_nonce(&mut head_tag, secret_body.random_buf());
        ChaCha20::new(
            Key::<ChaCha20>::from_slice(&self.key),
            Iv::<ChaCha20>::from_slice(&head_tag),
        )
        .apply_keystream(secret_body.data_mut());
        let len = secret_body.data().len();
        net_packet.set_encrypt_flag(false);
        net_packet.set_payload_len(len)?;
        Ok(())
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let data_len = net_packet.data_len();
        let head_tag = net_packet.head_tag();
        if let Some(_) = &self.finger {
            net_packet.set_data_len(data_len + RANDOM_RESERVED + FINGER_RESERVED)?;
        } else {
            net_packet.set_data_len(data_len + RANDOM_RESERVED)?;
        }
        let mut secret_body = IVSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        let mut nonce = head_tag;
        secret_body.set_random(&gen_random_nonce(&mut nonce));

        ChaCha20::new(
            Key::<ChaCha20>::from_slice(&self.key),
            Iv::<ChaCha20>::from_slice(&nonce),
        )
        .apply_keystream(secret_body.data_mut());
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&head_tag, secret_body.data());
            let mut secret_body = IVSecretBody::new(net_packet.payload_mut(), true)?;
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
        NetPacket::new_encrypt([1; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);

    let d = ChaCha20Cipher::new_256([0; 32], None);
    let mut p =
        NetPacket::new_encrypt([2; 13 + crate::protocol::body::ENCRYPTION_RESERVED]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
