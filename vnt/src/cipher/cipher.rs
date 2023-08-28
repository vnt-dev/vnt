use std::io;
use std::str::FromStr;
use crate::cipher::{aes_cbc, Finger};
use crate::protocol::NetPacket;
use sha2::Digest;
#[cfg(feature = "ring-cipher")]
use crate::cipher::ring_aes_gcm_cipher::AesGcmCipher;
#[cfg(not(feature = "ring-cipher"))]
use crate::cipher::aes_gcm_cipher::AesGcmCipher;
use aes_cbc::AesCbcCipher;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CipherModel {
    AesGcm,
    AesCbc,
}

impl FromStr for CipherModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes_gcm" => {
                Ok(CipherModel::AesGcm)
            }
            "aes_cbc" => { Ok(CipherModel::AesCbc) }
            _ => {
                Err(format!("not match '{}'", s))
            }
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    AesGcm((AesGcmCipher, Vec<u8>)),
    AesCbc(AesCbcCipher),
    None,
}

impl Cipher {
    pub fn new_password(model: CipherModel, password: Option<String>, token: String) -> Self {
        let finger = Finger::new(&token);
        if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            match model {
                CipherModel::AesGcm => {
                    if password.len() < 8 {
                        let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesGcm((aes, key[..16].to_vec()))
                    } else {
                        let aes = AesGcmCipher::new_256(key, finger);
                        Cipher::AesGcm((aes, key.to_vec()))
                    }
                }
                CipherModel::AesCbc => {
                    if password.len() < 8 {
                        let aes = AesCbcCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesCbc(aes)
                    } else {
                        let aes = AesCbcCipher::new_256(key, finger);
                        Cipher::AesCbc(aes)
                    }
                }
            }
        } else {
            Cipher::None
        }
    }
    pub fn new_key(key: [u8; 32], token: String) -> io::Result<Self> {
        let finger = Finger::new(&token);
        match key.len() {
            16 => {
                let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                Ok(Cipher::AesGcm((aes, key[..16].to_vec())))
            }
            32 => {
                let aes = AesGcmCipher::new_256(key, finger);
                Ok(Cipher::AesGcm((aes, key.to_vec())))
            }
            _ => {
                Err(io::Error::new(io::ErrorKind::Other, "key error"))
            }
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<()> {
        match self {
            Cipher::AesGcm((aes_gcm, _)) => {
                aes_gcm.decrypt_ipv4(net_packet)
            }
            Cipher::AesCbc(aes_cbc) => {
                aes_cbc.decrypt_ipv4(net_packet).unwrap();
                Ok(())
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
            Cipher::AesGcm((aes_gcm, _)) => {
                aes_gcm.encrypt_ipv4(net_packet)
            }
            Cipher::AesCbc(aes_cbc) => {
                aes_cbc.encrypt_ipv4(net_packet).unwrap();
                Ok(())
            }
            Cipher::None => {
                Ok(())
            }
        }
    }
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> io::Result<()> {
        match self {
            Cipher::AesGcm((aes_gcm, _)) => {
                aes_gcm.finger.check_finger(net_packet)
            }
            Cipher::AesCbc(aes_cbc) => {
                aes_cbc.finger.check_finger(net_packet)
            }
            Cipher::None => {
                Ok(())
            }
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            Cipher::AesGcm((_, key)) => {
                Some(key)
            }
            Cipher::AesCbc(aes_cbc) => {
                Some(aes_cbc.key())
            }
            Cipher::None => {
                None
            }
        }
    }
}