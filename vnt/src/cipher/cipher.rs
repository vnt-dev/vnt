#[cfg(not(any(feature = "openssl-vendored", feature = "openssl")))]
use crate::cipher::aes_ecb::AesEcbCipher;
#[cfg(not(feature = "ring-cipher"))]
use crate::cipher::aes_gcm_cipher::AesGcmCipher;
#[cfg(any(feature = "openssl-vendored", feature = "openssl"))]
use crate::cipher::openssl_aes_ecb::AesEcbCipher;
#[cfg(feature = "ring-cipher")]
use crate::cipher::ring_aes_gcm_cipher::AesGcmCipher;
use crate::cipher::{aes_cbc, Finger};
use crate::protocol::NetPacket;
use aes_cbc::AesCbcCipher;
use sha2::Digest;
use std::io;
use std::str::FromStr;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CipherModel {
    AesGcm,
    AesCbc,
    AesEcb,
}

impl FromStr for CipherModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "aes_gcm" => Ok(CipherModel::AesGcm),
            "aes_cbc" => Ok(CipherModel::AesCbc),
            "aes_ecb" => Ok(CipherModel::AesEcb),
            _ => Err(format!("not match '{}', enum:aes_gcm/aes_cbc/aes_ecb", s)),
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    AesGcm((AesGcmCipher, Vec<u8>)),
    AesCbc(AesCbcCipher),
    AesEcb(AesEcbCipher),
    None,
}

impl Cipher {
    pub fn new_password(
        model: CipherModel,
        password: Option<String>,
        token: Option<String>,
    ) -> Self {
        let finger = token.map(|token| Finger::new(&token));
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
                CipherModel::AesEcb => {
                    if password.len() < 8 {
                        let aes = AesEcbCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesEcb(aes)
                    } else {
                        let aes = AesEcbCipher::new_256(key, finger);
                        Cipher::AesEcb(aes)
                    }
                }
            }
        } else {
            Cipher::None
        }
    }
    pub fn new_key(key: [u8; 32], token: String) -> io::Result<Self> {
        let finger = Some(Finger::new(&token));
        match key.len() {
            16 => {
                let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                Ok(Cipher::AesGcm((aes, key[..16].to_vec())))
            }
            32 => {
                let aes = AesGcmCipher::new_256(key, finger);
                Ok(Cipher::AesGcm((aes, key.to_vec())))
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "key error")),
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        match self {
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.decrypt_ipv4(net_packet),
            Cipher::AesCbc(aes_cbc) => aes_cbc.decrypt_ipv4(net_packet),
            Cipher::AesEcb(aes_ecb) => aes_ecb.decrypt_ipv4(net_packet),
            Cipher::None => {
                if net_packet.is_encrypt() {
                    return Err(io::Error::new(io::ErrorKind::Other, "not key"));
                }
                Ok(())
            }
        }
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        match self {
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.encrypt_ipv4(net_packet),
            Cipher::AesCbc(aes_cbc) => aes_cbc.encrypt_ipv4(net_packet),
            Cipher::AesEcb(aes_ecb) => aes_ecb.encrypt_ipv4(net_packet),
            Cipher::None => Ok(()),
        }
    }
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> io::Result<()> {
        let finger = match self {
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.finger.as_ref(),
            Cipher::AesCbc(aes_cbc) => aes_cbc.finger.as_ref(),
            Cipher::AesEcb(aes_ecb) => aes_ecb.finger.as_ref(),
            Cipher::None => None,
        };
        if let Some(finger) = finger {
            finger.check_finger(net_packet)
        } else {
            Ok(())
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            Cipher::AesGcm((_, key)) => Some(key),
            Cipher::AesCbc(aes_cbc) => Some(aes_cbc.key()),
            Cipher::AesEcb(aes_ecb) => Some(aes_ecb.key()),
            Cipher::None => None,
        }
    }
}
