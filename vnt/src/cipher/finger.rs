use std::io;

use sha2::Digest;

use crate::protocol::{body::ENCRYPTION_RESERVED, body::SecretBody, NetPacket};

#[derive(Clone)]
pub struct Finger {
    token: String,
}

impl Finger {
    pub fn new(token: String) -> Self {
        Finger { token }
    }
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> io::Result<()> {
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
        let secret_body = SecretBody::new(net_packet.payload())?;
        let finger = self.calculate_finger(&nonce_raw, &secret_body);
        if &finger != secret_body.finger() {
            return Err(io::Error::new(io::ErrorKind::Other, "finger err"));
        }
        Ok(())
    }
    pub fn calculate_finger<B: AsRef<[u8]>>(&self, nonce_raw: &[u8; 12], secret_body: &SecretBody<B>) -> [u8; 12] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(secret_body.body());
        hasher.update(nonce_raw);
        hasher.update(secret_body.tag());
        hasher.update(&self.token);
        let key: [u8; 32] = hasher.finalize().into();
        return key[20..].try_into().unwrap();
    }
}