use crate::cipher::Finger;
use crate::protocol::{NetPacket, HEAD_LEN};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use std::io;

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
    ) -> io::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(io::Error::new(io::ErrorKind::Other, "not encrypt"));
        }

        if let Some(finger) = &self.finger {
            let mut nonce_raw = [0; 12];
            nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
            nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
            nonce_raw[8] = net_packet.protocol().into();
            nonce_raw[9] = net_packet.transport_protocol();
            nonce_raw[10] = net_packet.is_gateway() as u8;
            nonce_raw[11] = net_packet.source_ttl();
            let len = net_packet.payload().len();
            if len < 12 {
                return Err(io::Error::new(io::ErrorKind::Other, "payload len <12"));
            }
            let secret_body = &net_packet.payload()[..len - 12];
            let finger = finger.calculate_finger(&nonce_raw, secret_body);
            if &finger != &net_packet.payload()[len - 12..] {
                return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
            }
            net_packet.set_data_len(net_packet.data_len() - finger.len())?;
        }
        if net_packet.payload().len() < 16 {
            log::error!("数据异常,长度{}小于{}", net_packet.payload().len(), 16);
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
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
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                if src_net_packet.destination() != net_packet.destination() {
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                if src_net_packet.protocol() != net_packet.protocol() {
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                if src_net_packet.transport_protocol() != net_packet.transport_protocol() {
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                if src_net_packet.is_gateway() != net_packet.is_gateway() {
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                if src_net_packet.source_ttl() != net_packet.source_ttl() {
                    return Err(io::Error::new(io::ErrorKind::Other, "data err"));
                }
                net_packet.set_data_len(buf.len())?;
                net_packet.set_payload(src_net_packet.payload())?;
                net_packet.set_encrypt_flag(false);
                Ok(())
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("aes_ecb解密失败:{}", e),
            )),
        }
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
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
                    let mut nonce_raw = [0; 12];
                    nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
                    nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
                    nonce_raw[8] = net_packet.protocol().into();
                    nonce_raw[9] = net_packet.transport_protocol();
                    nonce_raw[10] = net_packet.is_gateway() as u8;
                    nonce_raw[11] = net_packet.source_ttl();
                    let finger = finger.calculate_finger(&nonce_raw, buf);
                    let src_data_len = net_packet.data_len();
                    //设置实际长度
                    net_packet.set_data_len(src_data_len + finger.len())?;

                    net_packet.buffer_mut()[src_data_len..].copy_from_slice(&finger);
                }
                Ok(())
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("aes_ecb加密失败:{}", e),
            )),
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
