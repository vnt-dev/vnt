use std::io;
use crate::cipher::Finger;
use crate::protocol::NetPacket;
use sha2::Digest;
#[cfg(feature = "ring-cipher")]
use crate::cipher::ring_cipher::AesGcmCipher;
#[cfg(not(feature = "ring-cipher"))]
use crate::cipher::aes_gcm_cipher::AesGcmCipher;

#[derive(Clone)]
pub enum Cipher {
    Aes((AesGcmCipher, Vec<u8>)),
    None,
}

impl Cipher {
    pub fn new_password(password: Option<String>, token: String) -> Self {
        let finger = Finger::new(token);
        if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            if password.len() < 8 {
                let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                Cipher::Aes((aes, key[..16].to_vec()))
            } else {
                let aes = AesGcmCipher::new_256(key, finger);
                Cipher::Aes((aes, key.to_vec()))
            }
        } else {
            Cipher::None
        }
    }
    pub fn new_key(key: [u8; 32], token: String) -> io::Result<Self> {
        let finger = Finger::new(token);
        match key.len() {
            16 => {
                let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                Ok(Cipher::Aes((aes, key[..16].to_vec())))
            }
            32 => {
                let aes = AesGcmCipher::new_256(key, finger);
                Ok(Cipher::Aes((aes, key.to_vec())))
            }
            _ => {
                Err(io::Error::new(io::ErrorKind::Other, "key error"))
            }
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        match self {
            Cipher::Aes((aes_gcm, _)) => {
                aes_gcm.decrypt_ipv4(net_packet)
            }
            Cipher::None => {
                if net_packet.is_encrypt() {
                    return Err(io::Error::new(io::ErrorKind::Other, "not key"));
                }
                Ok(())
            }
        }
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        match self {
            Cipher::Aes((aes_gcm, _)) => {
                aes_gcm.encrypt_ipv4(net_packet)
            }
            Cipher::None => {
                Ok(())
            }
        }
    }
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> io::Result<()> {
        match self {
            Cipher::Aes((aes_gcm, _)) => {
                aes_gcm.finger.check_finger(net_packet)
            }
            Cipher::None => {
                Ok(())
            }
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            Cipher::Aes((_, key)) => {
                Some(key)
            }
            Cipher::None => {
                None
            }
        }
    }
}