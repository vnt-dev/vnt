use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::anyhow;
use rand::RngCore;

use crate::cipher::Finger;
use crate::protocol::body::AesCbcSecretBody;
use crate::protocol::{NetPacket, HEAD_LEN};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Clone)]
pub struct AesCbcCipher {
    pub(crate) cipher: AesCbcEnum,
    pub(crate) finger: Option<Finger>,
}

#[derive(Clone)]
pub enum AesCbcEnum {
    AES128CBC([u8; 16]),
    AES256CBC([u8; 32]),
}

impl AesCbcCipher {
    pub fn key(&self) -> &[u8] {
        match &self.cipher {
            AesCbcEnum::AES128CBC(key) => key,
            AesCbcEnum::AES256CBC(key) => key,
        }
    }
}

impl AesCbcCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        Self {
            cipher: AesCbcEnum::AES128CBC(key),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        Self {
            cipher: AesCbcEnum::AES256CBC(key),
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
        if net_packet.payload().len() < 16 {
            log::error!("数据异常,长度{}小于{}", net_packet.payload().len(), 16);
            return Err(anyhow!("aes_cbc data err"));
        }
        let mut iv = [0; 16];
        iv[0..12].copy_from_slice(&net_packet.head_tag());
        if let Some(finger) = &self.finger {
            iv[12..16].copy_from_slice(&finger.hash[0..4]);
        }

        let mut secret_body =
            AesCbcSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        if let Some(finger) = &self.finger {
            let finger = finger.calculate_finger(&iv[..12], secret_body.en_body());
            if &finger != secret_body.finger() {
                return Err(anyhow!("aes_cbc finger err"));
            }
        }
        let rs = match &self.cipher {
            AesCbcEnum::AES128CBC(key) => Aes128CbcDec::new(&(*key).into(), &iv.into())
                .decrypt_padded_mut::<Pkcs7>(secret_body.en_body_mut()),
            AesCbcEnum::AES256CBC(key) => Aes256CbcDec::new(&(*key).into(), &iv.into())
                .decrypt_padded_mut::<Pkcs7>(secret_body.en_body_mut()),
        };
        match rs {
            Ok(buf) => {
                let len = buf.len();
                net_packet.set_encrypt_flag(false);
                //减去末尾的随机数
                net_packet.set_data_len(HEAD_LEN + len - 4)?;
                Ok(())
            }
            Err(e) => Err(anyhow!("aes_cbc 解密失败:{}", e)),
        }
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let data_len = net_packet.data_len();
        let mut iv = [0; 16];
        iv[0..12].copy_from_slice(&net_packet.head_tag());
        if let Some(finger) = &self.finger {
            iv[12..16].copy_from_slice(&finger.hash[0..4]);
            net_packet.set_data_len(data_len + 16)?;
        } else {
            net_packet.set_data_len(data_len + 4)?;
        }
        //先扩充随机数
        let mut secret_body =
            AesCbcSecretBody::new(net_packet.payload_mut(), self.finger.is_some())?;
        secret_body.set_random(rand::thread_rng().next_u32());
        let p_len = secret_body.en_body().len();
        net_packet.set_data_len_max();
        let rs = match &self.cipher {
            AesCbcEnum::AES128CBC(key) => Aes128CbcEnc::new(&(*key).into(), &iv.into())
                .encrypt_padded_mut::<Pkcs7>(net_packet.payload_mut(), p_len),
            AesCbcEnum::AES256CBC(key) => Aes256CbcEnc::new(&(*key).into(), &iv.into())
                .encrypt_padded_mut::<Pkcs7>(net_packet.payload_mut(), p_len),
        };
        return match rs {
            Ok(buf) => {
                let len = buf.len();
                if let Some(finger) = &self.finger {
                    let finger = finger.calculate_finger(&iv[..12], buf);
                    //设置实际长度
                    net_packet.set_data_len(HEAD_LEN + len + finger.len())?;
                    let mut secret_body = AesCbcSecretBody::new(net_packet.payload_mut(), true)?;
                    secret_body.set_finger(&finger)?;
                } else {
                    net_packet.set_data_len(HEAD_LEN + len)?;
                }

                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(anyhow!("aes_cbc 加密失败:{}", e)),
        };
    }
}
#[test]
fn test_aes_cbc() {
    let d = AesCbcCipher::new_128([0; 16], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([0; 100]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
    let d = AesCbcCipher::new_128([0; 16], None);
    let mut p = NetPacket::new_encrypt([0; 100]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
