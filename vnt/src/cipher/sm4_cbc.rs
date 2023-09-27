use crate::cipher::Finger;
use crate::protocol::{NetPacket, HEAD_LEN};
use libsm::sm4::cipher_mode::CipherMode;
use libsm::sm4::Sm4CipherMode;
use rand::RngCore;
use std::io;

pub struct Sm4CbcCipher {
    key: [u8; 16],
    pub(crate) cipher: Sm4CipherMode,
    pub(crate) finger: Option<Finger>,
}

impl Clone for Sm4CbcCipher {
    fn clone(&self) -> Self {
        let cipher = Sm4CipherMode::new(&self.key, CipherMode::Cbc).unwrap();
        Self {
            key: self.key,
            cipher,
            finger: self.finger.clone(),
        }
    }
}

impl Sm4CbcCipher {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl Sm4CbcCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        let cipher = Sm4CipherMode::new(&key, CipherMode::Cbc).unwrap();
        Self {
            key,
            cipher,
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
        let payload = net_packet.payload();
        let len = payload.len();
        if len < 16 || len > 1024 * 4 {
            log::error!("数据异常,长度{}小于16或大于4096", len);
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
        }
        let mut out = [0u8; 1024 * 4];
        let data = &payload[..len - 16];
        let iv = &payload[len - 16..];
        match self.cipher.decrypt(data, iv, &mut out) {
            Ok(len) => {
                let src_net_packet = NetPacket::new(&out[..len])?;
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
                net_packet.set_data_len(len)?;
                net_packet.set_payload(src_net_packet.payload())?;
                net_packet.set_encrypt_flag(false);
                Ok(())
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sm4_cbc解密失败:{}", e),
            )),
        }
    }
    /// net_packet 必须预留足够长度
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        let mut out = [0u8; 1024 * 4];
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        if net_packet.data_len() > 1024 * 4 - 32 {
            log::error!(
                "数据异常,长度{}大于1024 * 4 - 32",
                net_packet.buffer().len()
            );
            return Err(io::Error::new(io::ErrorKind::Other, "data err"));
        }
        match self.cipher.encrypt(net_packet.buffer(), &iv, &mut out) {
            Ok(len) => {
                net_packet.set_data_len(HEAD_LEN + len + 16)?;
                net_packet.payload_mut()[..len].copy_from_slice(&out[..len]);
                net_packet.payload_mut()[len..].copy_from_slice(&iv);
                if let Some(finger) = &self.finger {
                    let mut nonce_raw = [0; 12];
                    nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
                    nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
                    nonce_raw[8] = net_packet.protocol().into();
                    nonce_raw[9] = net_packet.transport_protocol();
                    nonce_raw[10] = net_packet.is_gateway() as u8;
                    nonce_raw[11] = net_packet.source_ttl();
                    let finger = finger.calculate_finger(&nonce_raw, net_packet.payload());
                    let src_data_len = net_packet.data_len();
                    //设置实际长度
                    net_packet.set_data_len(src_data_len + finger.len())?;

                    net_packet.buffer_mut()[src_data_len..].copy_from_slice(&finger);
                }
                net_packet.set_encrypt_flag(true);
                Ok(())
            }
            Err(e) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("sm4_cbc加密失败:{}", e),
            )),
        }
    }
}

#[test]
fn test_sm4_ecb() {
    let d = Sm4CbcCipher::new_128([0; 16], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([1; 1024]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
    let d = Sm4CbcCipher::new_128([0; 16], None);
    let mut p = NetPacket::new_encrypt([1; 102]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src)
}
