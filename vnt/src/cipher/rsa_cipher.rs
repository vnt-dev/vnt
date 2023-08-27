use std::io;
use rand::Rng;
use rsa::pkcs8::der::Decode;
use rsa::{PublicKey, RsaPublicKey};
use spki::{DecodePublicKey, EncodePublicKey};
use crate::protocol::body::{ENCRYPTION_RESERVED, RsaSecretBody};
use crate::protocol::NetPacket;
use sha2::Digest;

#[derive(Clone)]
pub struct RsaCipher {
    inner: Inner,
}

#[derive(Clone)]
struct Inner {
    public_key: RsaPublicKey,
}

impl RsaCipher {
    pub fn new(der: &[u8]) -> io::Result<Self> {
        match RsaPublicKey::from_public_key_der(der) {
            Ok(public_key) => {
                let inner = Inner {
                    public_key,
                };
                Ok(Self {
                    inner
                })
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("from_public_key_der failed {}", e)))
            }
        }
    }
    pub fn finger(&self) -> io::Result<String> {
        match self.inner.public_key.to_public_key_der() {
            Ok(der) => {
                match rsa::pkcs8::SubjectPublicKeyInfo::from_der(der.as_bytes()) {
                    Ok(spki) => {
                        match spki.fingerprint_base64() {
                            Ok(finger) => {
                                Ok(finger)
                            }
                            Err(e) => {
                                Err(io::Error::new(io::ErrorKind::Other, format!("fingerprint_base64 error {}", e)))
                            }
                        }
                    }
                    Err(e) => {
                        Err(io::Error::new(io::ErrorKind::Other, format!("from_der error {}", e)))
                    }
                }
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("to_public_key_der error {}", e)))
            }
        }
    }
}

impl RsaCipher {
    /// net_packet 必须预留足够长度
    pub fn encrypt<B: AsRef<[u8]> + AsMut<[u8]>>(&self, net_packet: &mut NetPacket<B>) -> io::Result<NetPacket<Vec<u8>>> {
        if net_packet.reserve() < ENCRYPTION_RESERVED {
            return Err(io::Error::new(io::ErrorKind::Other, "too short"));
        }
        let data_len = net_packet.data_len() + ENCRYPTION_RESERVED;
        net_packet.set_data_len(data_len)?;
        let mut nonce_raw = [0; 12];
        nonce_raw[0..4].copy_from_slice(&net_packet.source().octets());
        nonce_raw[4..8].copy_from_slice(&net_packet.destination().octets());
        nonce_raw[8] = net_packet.protocol().into();
        nonce_raw[9] = net_packet.transport_protocol();
        nonce_raw[10] = net_packet.is_gateway() as u8;
        nonce_raw[11] = net_packet.source_ttl();

        let mut secret_body = RsaSecretBody::new(net_packet.payload_mut())?;
        let mut rng = rand::thread_rng();
        rng.fill(secret_body.random_mut());

        let mut hasher = sha2::Sha256::new();
        hasher.update(secret_body.body());
        hasher.update(nonce_raw);
        let key: [u8; 32] = hasher.finalize().into();
        secret_body.set_finger(&key[16..])?;
        match self.inner.public_key.encrypt(&mut rng, rsa::PaddingScheme::PKCS1v15Encrypt, secret_body.buffer()) {
            Ok(enc_data) => {
                let mut net_packet_e = NetPacket::new(vec![0; 12 + enc_data.len()])?;
                net_packet_e.buffer_mut()[..12].copy_from_slice(&net_packet.buffer()[..12]);
                net_packet_e.set_payload(&enc_data)?;
                Ok(net_packet_e)
            }
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, format!("encrypt failed {}", e)))
            }
        }
    }
}