use std::io;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;

use crate::cipher::Finger;
use crate::protocol::body::AesCbcSecretBody;
use crate::protocol::{HEAD_LEN, NetPacket};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Clone)]
pub struct AesCbcCipher {
    pub(crate) cipher: AesCbcEnum,
    pub(crate) finger: Finger,
}

#[derive(Clone)]
pub enum AesCbcEnum {
    AES128CBC([u8; 16]),
    AES256CBC([u8; 32]),
}

impl AesCbcCipher {
    pub fn key(&self) -> &[u8] {
        match &self.cipher {
            AesCbcEnum::AES128CBC(key) => { key }
            AesCbcEnum::AES256CBC(key) => { key }
        }
    }
}

impl AesCbcCipher {
    pub fn new_128(key: [u8; 16], finger: Finger) -> Self {
        Self {
            cipher: AesCbcEnum::AES128CBC(key),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Finger) -> Self {
        Self {
            cipher: AesCbcEnum::AES256CBC(key),
            finger,
        }
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(io::Error::new(io::ErrorKind::Other, "not encrypt"));
        }
        if net_packet.payload().len() < 12 + 16 {
            log::error!("数据异常,长度{}小于{}",net_packet.payload().len(),12+16);
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
        }
        let mut iv = [0; 16];
        iv[0..4].copy_from_slice(&net_packet.source().octets());
        iv[4..8].copy_from_slice(&net_packet.destination().octets());
        iv[8] = net_packet.protocol().into();
        iv[9] = net_packet.transport_protocol();
        iv[10] = net_packet.is_gateway() as u8;
        iv[11] = net_packet.source_ttl();
        iv[12..16].copy_from_slice(&self.finger.hash[0..4]);

        let mut secret_body = AesCbcSecretBody::new(net_packet.payload_mut())?;
        let finger = self.finger.calculate_finger(&iv[..12], secret_body.en_body());
        if &finger != secret_body.finger() {
            return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
        }
        let rs = match &self.cipher {
            AesCbcEnum::AES128CBC(key) => { Aes128CbcDec::new(&(*key).into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(secret_body.en_body_mut()) }
            AesCbcEnum::AES256CBC(key) => { Aes256CbcDec::new(&(*key).into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(secret_body.en_body_mut()) }
        };
        match rs {
            Ok(buf) => {
                let len = buf.len();
                net_packet.set_encrypt_flag(false);
                //减去末尾的随机数
                net_packet.set_data_len(HEAD_LEN + len - 4)?;
                Ok(())
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("解密失败:{}", e)))
            }
        }
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        let mut iv = [0; 16];
        iv[0..4].copy_from_slice(&net_packet.source().octets());
        iv[4..8].copy_from_slice(&net_packet.destination().octets());
        iv[8] = net_packet.protocol().into();
        iv[9] = net_packet.transport_protocol();
        iv[10] = net_packet.is_gateway() as u8;
        iv[11] = net_packet.source_ttl();
        iv[12..16].copy_from_slice(&self.finger.hash[0..4]);
        //先扩充随机数
        let data_len = net_packet.data_len();
        net_packet.set_data_len(data_len + 16)?;
        let mut secret_body = AesCbcSecretBody::new(net_packet.payload_mut())?;
        secret_body.set_random(rand::thread_rng().next_u32());
        let p_len = secret_body.en_body().len();
        net_packet.set_data_len_max();
        let rs = match &self.cipher {
            AesCbcEnum::AES128CBC(key) => { Aes128CbcEnc::new(&(*key).into(), &iv.into()).encrypt_padded_mut::<Pkcs7>(net_packet.payload_mut(), p_len) }
            AesCbcEnum::AES256CBC(key) => { Aes256CbcEnc::new(&(*key).into(), &iv.into()).encrypt_padded_mut::<Pkcs7>(net_packet.payload_mut(), p_len) }
        };
        return match rs {
            Ok(buf) => {
                let len = buf.len();
                let finger = self.finger.calculate_finger(&iv[..12], buf);
                //设置实际长度
                net_packet.set_data_len(HEAD_LEN + len + finger.len())?;
                let mut secret_body = AesCbcSecretBody::new(net_packet.payload_mut())?;
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