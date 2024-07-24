use std::fmt::Display;
use std::str::FromStr;

use anyhow::anyhow;
#[cfg(cipher)]
use sha2::Digest;

#[cfg(feature = "aes_cbc")]
use crate::cipher::aes_cbc::AesCbcCipher;
#[cfg(feature = "aes_ecb")]
use crate::cipher::aes_ecb::AesEcbCipher;
#[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
use crate::cipher::aes_gcm::AesGcmCipher;
#[cfg(feature = "chacha20_poly1305")]
use crate::cipher::chacha20::ChaCha20Cipher;
#[cfg(feature = "chacha20_poly1305")]
use crate::cipher::chacha20_poly1305::ChaCha20Poly1305Cipher;
#[cfg(feature = "sm4_cbc")]
use crate::cipher::sm4_cbc::Sm4CbcCipher;
use crate::cipher::xor::XORCipher;
#[cfg(cipher)]
use crate::cipher::Finger;
use crate::protocol::NetPacket;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CipherModel {
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    AesGcm,
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20Poly1305,
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20,
    #[cfg(feature = "aes_cbc")]
    AesCbc,
    #[cfg(feature = "aes_ecb")]
    AesEcb,
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc,
    Xor,
    None,
}

impl Display for CipherModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            CipherModel::AesGcm => "aes_gcm".to_string(),
            #[cfg(feature = "chacha20_poly1305")]
            CipherModel::Chacha20Poly1305 => "chacha20_poly1305".to_string(),
            #[cfg(feature = "chacha20_poly1305")]
            CipherModel::Chacha20 => "chacha20".to_string(),
            #[cfg(feature = "aes_cbc")]
            CipherModel::AesCbc => "aes_cbc".to_string(),
            #[cfg(feature = "aes_ecb")]
            CipherModel::AesEcb => "aes_ecb".to_string(),
            #[cfg(feature = "sm4_cbc")]
            CipherModel::Sm4Cbc => "sm4_cbc".to_string(),
            CipherModel::Xor => "xor".to_string(),
            CipherModel::None => "none".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl FromStr for CipherModel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            "aes_gcm" => Ok(CipherModel::AesGcm),
            #[cfg(feature = "chacha20_poly1305")]
            "chacha20_poly1305" => Ok(CipherModel::Chacha20Poly1305),
            #[cfg(feature = "chacha20_poly1305")]
            "chacha20" => Ok(CipherModel::Chacha20),
            #[cfg(feature = "aes_cbc")]
            "aes_cbc" => Ok(CipherModel::AesCbc),
            #[cfg(feature = "aes_ecb")]
            "aes_ecb" => Ok(CipherModel::AesEcb),
            #[cfg(feature = "sm4_cbc")]
            "sm4_cbc" => Ok(CipherModel::Sm4Cbc),
            "xor" => Ok(CipherModel::Xor),
            _ => {
                let mut enums = String::new();
                #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
                enums.push_str("/aes_gcm");
                #[cfg(feature = "chacha20_poly1305")]
                enums.push_str("/chacha20_poly1305/chacha20");
                #[cfg(feature = "aes_cbc")]
                enums.push_str("/aes_cbc");
                #[cfg(feature = "aes_ecb")]
                enums.push_str("/aes_ecb");
                #[cfg(feature = "sm4_cbc")]
                enums.push_str("/sm4_cbc");
                enums.push_str("/xor");
                Err(format!("not match '{}', enum:{}", s, &enums[1..]))
            }
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    AesGcm((AesGcmCipher, Vec<u8>)),
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20Poly1305(ChaCha20Poly1305Cipher),
    #[cfg(feature = "chacha20_poly1305")]
    Chacha20(ChaCha20Cipher),
    #[cfg(feature = "aes_cbc")]
    AesCbc(AesCbcCipher),
    #[cfg(feature = "aes_ecb")]
    AesEcb(AesEcbCipher),
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc(Sm4CbcCipher),
    Xor(XORCipher),
    None,
}

impl Cipher {
    pub fn new_password(
        model: CipherModel,
        password: Option<String>,
        token: Option<String>,
    ) -> anyhow::Result<Self> {
        if let Some(password) = password {
            #[cfg(cipher)]
            let key: [u8; 32] = {
                let mut hasher = sha2::Sha256::new();
                hasher.update(password.as_bytes());
                hasher.finalize().into()
            };
            match model {
                #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
                CipherModel::AesGcm => {
                    let finger = token.map(|token| Finger::new(&token));
                    if password.len() < 8 {
                        let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Ok(Cipher::AesGcm((aes, key[..16].to_vec())))
                    } else {
                        let aes = AesGcmCipher::new_256(key, finger);
                        Ok(Cipher::AesGcm((aes, key.to_vec())))
                    }
                }
                #[cfg(feature = "chacha20_poly1305")]
                CipherModel::Chacha20Poly1305 => {
                    let finger = token.map(|token| Finger::new(&token));
                    let chacha = ChaCha20Poly1305Cipher::new_256(key, finger);
                    Ok(Cipher::Chacha20Poly1305(chacha))
                }
                #[cfg(feature = "chacha20_poly1305")]
                CipherModel::Chacha20 => {
                    let finger = token.map(|token| Finger::new(&token));
                    let chacha = ChaCha20Cipher::new_256(key, finger);
                    Ok(Cipher::Chacha20(chacha))
                }
                #[cfg(feature = "aes_cbc")]
                CipherModel::AesCbc => {
                    let finger = token.map(|token| Finger::new(&token));
                    if password.len() < 8 {
                        let aes = AesCbcCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Ok(Cipher::AesCbc(aes))
                    } else {
                        let aes = AesCbcCipher::new_256(key, finger);
                        Ok(Cipher::AesCbc(aes))
                    }
                }
                #[cfg(feature = "aes_ecb")]
                CipherModel::AesEcb => {
                    let finger = token.map(|token| Finger::new(&token));
                    if password.len() < 8 {
                        let aes = AesEcbCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Ok(Cipher::AesEcb(aes))
                    } else {
                        let aes = AesEcbCipher::new_256(key, finger);
                        Ok(Cipher::AesEcb(aes))
                    }
                }
                #[cfg(feature = "sm4_cbc")]
                CipherModel::Sm4Cbc => {
                    let finger = token.map(|token| Finger::new(&token));
                    let aes = Sm4CbcCipher::new_128(key[..16].try_into().unwrap(), finger);
                    Ok(Cipher::Sm4Cbc(aes))
                }
                CipherModel::Xor => {
                    if token.is_some() {
                        Err(anyhow::anyhow!(
                            "'finger' and 'xor' cannot be used simultaneously"
                        ))?
                    }
                    Ok(Cipher::Xor(XORCipher::new_256(
                        crate::cipher::xor::simple_hash(&password),
                    )))
                }
                CipherModel::None => Ok(Cipher::None),
            }
        } else {
            Ok(Cipher::None)
        }
    }
    #[cfg(not(any(feature = "aes_gcm", feature = "server_encrypt")))]
    pub fn new_key(_key: [u8; 32], _token: String) -> anyhow::Result<Self> {
        Err(anyhow!("key error"))
    }
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    pub fn new_key(key: [u8; 32], token: String) -> anyhow::Result<Self> {
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
            _ => Err(anyhow!("key error")),
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.decrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => chacha20poly1305.decrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => chacha20.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.decrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.decrypt_ipv4(net_packet),
            Cipher::Xor(xor) => xor.decrypt_ipv4(net_packet),
            Cipher::None => {
                if net_packet.is_encrypt() {
                    return Err(anyhow!("not key"));
                }
                Ok(())
            }
        }
    }
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.encrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => chacha20poly1305.encrypt_ipv4(net_packet),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => chacha20.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.encrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.encrypt_ipv4(net_packet),
            Cipher::Xor(xor) => xor.encrypt_ipv4(net_packet),
            Cipher::None => Ok(()),
        }
    }
    #[cfg(not(cipher))]
    pub fn check_finger<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        _net_packet: &NetPacket<B>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    #[cfg(cipher)]
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> anyhow::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => chacha20poly1305
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => chacha20
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            Cipher::Xor(_) => Ok(()),
            Cipher::None => Ok(()),
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((_, key)) => Some(key),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20Poly1305(chacha20poly1305) => Some(chacha20poly1305.key()),
            #[cfg(feature = "chacha20_poly1305")]
            Cipher::Chacha20(chacha20) => Some(chacha20.key()),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => Some(aes_cbc.key()),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => Some(aes_ecb.key()),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => Some(sm4_cbc.key()),
            Cipher::Xor(xor) => Some(xor.key()),
            Cipher::None => None,
        }
    }
}
