use anyhow::anyhow;

use crate::protocol::NetPacket;

pub fn simple_hash(input: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    let bytes = input.as_bytes();
    for (index, v) in result.iter_mut().enumerate() {
        *v = bytes[index % bytes.len()];
    }

    let mut state = 0u8;

    for (i, &byte) in bytes.iter().enumerate() {
        let combined = byte.wrapping_add(state).rotate_left((i % 8) as u32);
        result[i % 32] ^= combined;
        state = state.wrapping_add(byte).rotate_left(3);
    }

    for i in 0..32 {
        result[i] = result[i]
            .rotate_left((result[(i + 1) % 32] % 8) as u32)
            .wrapping_add(state);
        state = state.wrapping_add(result[i]).rotate_left(3);
    }

    result
}

#[derive(Clone)]
pub struct XORCipher {
    key: [u8; 32],
}

impl XORCipher {
    pub fn new_256(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl XORCipher {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl XORCipher {
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }
        let key = &self.key;
        for (i, byte) in net_packet.payload_mut().iter_mut().enumerate() {
            *byte ^= key[i & 31];
        }
        net_packet.set_encrypt_flag(false);
        Ok(())
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        net_packet.set_encrypt_flag(true);
        let key = &self.key;
        for (i, byte) in net_packet.payload_mut().iter_mut().enumerate() {
            *byte ^= key[i & 31];
        }
        Ok(())
    }
}

#[test]
fn test_xor() {
    let d = XORCipher::new_256(simple_hash("password"));
    let mut p = NetPacket::new_encrypt([0; 1000]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src)
}
