use anyhow::anyhow;
use rand::RngCore;

use sha2::Digest;

use crate::protocol::NetPacket;

#[derive(Clone)]
pub struct Finger {
    pub(crate) hash: [u8; 32],
}

impl Finger {
    pub fn new(str: &str) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(str.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        Finger { hash }
    }
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        let payload_len = net_packet.payload().len();
        if payload_len < 12 {
            log::error!("数据异常,长度小于{}", 12);
            return Err(anyhow!("data err"));
        }
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();
        let payload = net_packet.payload();
        let finger = self.calculate_finger(&nonce_raw, &payload[..payload_len - 12]);
        if &finger[..] != &payload[payload_len - 12..] {
            return Err(anyhow!("finger err"));
        }
        Ok(())
    }
    pub fn calculate_finger(&self, nonce: &[u8], secret_body: &[u8]) -> [u8; 12] {
        let mut hasher = sha2::Sha256::new();
        hasher.update(nonce);
        hasher.update(secret_body);
        hasher.update(&self.hash);
        let key: [u8; 32] = hasher.finalize().into();
        return key[20..].try_into().unwrap();
    }
}
impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn head_tag(&self) -> [u8; 12] {
        let mut tag = [0; 12];
        tag[0..4].copy_from_slice(&self.buffer()[4..8]);
        tag[4..8].copy_from_slice(&self.buffer()[8..12]);
        tag[8] = self.protocol().into();
        tag[9] = self.transport_protocol();
        tag[10] = self.is_gateway() as u8;
        tag[11] = self.source_ttl();
        tag
    }
}
pub fn gen_nonce(tag: &mut [u8], random: &[u8]) {
    tag[8] = random[0] ^ tag[8];
    tag[9] = random[1] ^ tag[9];
    tag[10] = random[2] ^ tag[10];
    tag[11] = random[3] ^ tag[11];
}
pub fn gen_random_nonce(tag: &mut [u8; 12]) -> [u8; 4] {
    let mut random = [0; 4];
    rand::thread_rng().fill_bytes(&mut random);
    gen_nonce(tag, &random);
    random
}
