use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use anyhow::anyhow;

use crate::cipher::Finger;
use crate::protocol::{NetPacket, HEAD_LEN};

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
type Aes256EcbEnc = ecb::Encryptor<aes::Aes256>;
type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;

#[derive(Clone)]
pub struct AesEcbCipher {
    key: AesEcbEnum,
    pub(crate) finger: Option<Finger>,
}

#[derive(Clone, Copy)]
pub enum AesEcbEnum {
    AES128ECB([u8; 16]),
    AES256ECB([u8; 32]),
}

impl AesEcbCipher {
    pub fn key(&self) -> &[u8] {
        match &self.key {
            AesEcbEnum::AES128ECB(key) => key,
            AesEcbEnum::AES256ECB(key) => key,
        }
    }
}

impl AesEcbCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        Self {
            key: AesEcbEnum::AES128ECB(key),
            finger,
        }
    }
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        Self {
            key: AesEcbEnum::AES256ECB(key),
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

        if let Some(finger) = &self.finger {
            let nonce_raw = net_packet.head_tag();
            let len = net_packet.payload().len();
            if len < 12 {
                return Err(anyhow!("payload len <12"));
            }
            let secret_body = &net_packet.payload()[..len - 12];
            let finger = finger.calculate_finger(&nonce_raw, secret_body);
            if &finger != &net_packet.payload()[len - 12..] {
                return Err(anyhow!("finger err"));
            }
            net_packet.set_data_len(net_packet.data_len() - finger.len())?;
        }
        if net_packet.payload().len() < 16 {
            log::error!("数据异常,长度{}小于{}", net_packet.payload().len(), 16);
            return Err(anyhow!("data err"));
        }
        let mut out = [0u8; 1024 * 5];
        let rs = match self.key {
            AesEcbEnum::AES128ECB(key) => Aes128EcbDec::new(&key.into())
                .decrypt_padded_b2b_mut::<Pkcs7>(net_packet.payload(), &mut out),
            AesEcbEnum::AES256ECB(key) => Aes256EcbDec::new(&key.into())
                .decrypt_padded_b2b_mut::<Pkcs7>(net_packet.payload(), &mut out),
        };
        match rs {
            Ok(buf) => {
                //校验头部
                let src_net_packet = NetPacket::new(buf)?;
                if src_net_packet.source() != net_packet.source() {
                    return Err(anyhow!("data err"));
                }
                if src_net_packet.destination() != net_packet.destination() {
                    return Err(anyhow!("data err"));
                }
                if src_net_packet.protocol() != net_packet.protocol() {
                    return Err(anyhow!("data err"));
                }
                if src_net_packet.transport_protocol() != net_packet.transport_protocol() {
                    return Err(anyhow!("data err"));
                }
                if src_net_packet.is_gateway() != net_packet.is_gateway() {
                    return Err(anyhow!("data err"));
                }
                if src_net_packet.source_ttl() != net_packet.source_ttl() {
                    return Err(anyhow!("data err"));
                }
                net_packet.set_data_len(buf.len())?;
                net_packet.set_payload(src_net_packet.payload())?;
                net_packet.set_encrypt_flag(false);
                Ok(())
            }
            Err(e) => Err(anyhow!("aes_ecb解密失败:{}", e)),
        }
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let mut out = [0u8; 1024 * 5];
        let rs = match self.key {
            AesEcbEnum::AES128ECB(key) => Aes128EcbEnc::new(&key.into())
                .encrypt_padded_b2b_mut::<Pkcs7>(net_packet.buffer(), &mut out),
            AesEcbEnum::AES256ECB(key) => Aes256EcbEnc::new(&key.into())
                .encrypt_padded_b2b_mut::<Pkcs7>(net_packet.buffer(), &mut out),
        };

        return match rs {
            Ok(buf) => {
                net_packet.set_data_len(HEAD_LEN + buf.len())?;
                net_packet.set_payload(buf)?;
                net_packet.set_encrypt_flag(true);

                if let Some(finger) = &self.finger {
                    let nonce_raw = net_packet.head_tag();
                    let finger = finger.calculate_finger(&nonce_raw, buf);
                    let src_data_len = net_packet.data_len();
                    //设置实际长度
                    net_packet.set_data_len(src_data_len + finger.len())?;

                    net_packet.buffer_mut()[src_data_len..].copy_from_slice(&finger);
                }
                Ok(())
            }
            Err(e) => Err(anyhow!("aes_ecb加密失败:{}", e)),
        };
    }
}

#[test]
fn test_aes_ecb() {
    let d = AesEcbCipher::new_128([0; 16], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([0; 100]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src)
}
