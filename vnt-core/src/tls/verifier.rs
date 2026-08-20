use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

#[derive(Debug)]
pub struct FingerprintVerifier {
    pub expected_fingerprint: [u8; 32],
    supported_algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}
impl FingerprintVerifier {
    pub fn new(expected_fingerprint: [u8; 32]) -> Self {
        Self {
            expected_fingerprint,
            supported_algorithms: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let calculated_hash: [u8; 32] = hasher.finalize().into();

        if calculated_hash == self.expected_fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            log::error!(
                "Certificate fingerprint mismatch. Expected: {:X?}, Got: {:X?}",
                self.expected_fingerprint,
                calculated_hash
            );
            Err(Error::InvalidCertificate(CertificateError::BadSignature))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // 必须真正验证握手签名：证书本身（由密码确定性生成）是公开信息，
        // 只比对指纹而不验签无法抵抗重放真实证书的主动中间人
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algorithms.supported_schemes()
    }
}
#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

pub fn load_root_cert() -> anyhow::Result<rustls::RootCertStore> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    let certs = rustls_native_certs::load_native_certs().certs;
    for cert in certs {
        root_cert_store
            .add(cert)
            .context("Failed to add native cert to store")?;
    }
    Ok(root_cert_store)
}

#[derive(Debug, Clone, Default)]
pub enum CertValidationMode {
    #[default]
    InsecureSkipVerification,
    VerifyFingerprint([u8; 32]),
    Standard,
}
impl FromStr for CertValidationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let val = value.trim().to_lowercase();
        if val == "skip" {
            return Ok(CertValidationMode::InsecureSkipVerification);
        }
        if val == "standard" {
            return Ok(CertValidationMode::Standard);
        }
        if let Some(hex_str) = val.strip_prefix("finger:") {
            let decoded =
                hex::decode(hex_str).map_err(|e| format!("Invalid hex in fingerprint: {}", e))?;

            if decoded.len() != 32 {
                return Err(format!(
                    "Fingerprint must be 32 bytes (64 hex chars), got {} bytes",
                    decoded.len()
                ));
            }

            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decoded);
            return Ok(CertValidationMode::VerifyFingerprint(arr));
        }
        Err(format!("Unknown certificate validation mode: {}", value))
    }
}
impl fmt::Display for CertValidationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertValidationMode::InsecureSkipVerification => {
                write!(f, "skip")
            }
            CertValidationMode::Standard => {
                write!(f, "standard")
            }
            CertValidationMode::VerifyFingerprint(fingerprint) => {
                let hex_str = hex::encode(fingerprint);

                write!(f, "finger:{}", hex_str)
            }
        }
    }
}

impl CertValidationMode {
    pub fn build_verifier(&self) -> anyhow::Result<std::sync::Arc<dyn ServerCertVerifier>> {
        match self {
            CertValidationMode::InsecureSkipVerification => {
                Ok(std::sync::Arc::new(InsecureVerifier))
            }
            CertValidationMode::VerifyFingerprint(fingerprint) => {
                Ok(std::sync::Arc::new(FingerprintVerifier::new(*fingerprint)))
            }
            CertValidationMode::Standard => {
                let root_store = load_root_cert()?;
                let verifier =
                    rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
                        .build()?;

                Ok(verifier)
            }
        }
    }
    pub fn create_tls_client_config(&self) -> anyhow::Result<ClientConfig> {
        let verifier = self.build_verifier()?;

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::cert::generate_deterministic_cert;
    use rustls::ServerConfig;
    use rustls::pki_types::ServerName;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn fingerprint_of(cert: &CertificateDer<'_>) -> [u8; 32] {
        Sha256::digest(cert.as_ref()).into()
    }

    async fn try_handshake(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> std::io::Result<()> {
        let (client_io, server_io) = tokio::io::duplex(8192);
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let connector = tokio_rustls::TlsConnector::from(client_config);
        let server_name = ServerName::try_from("deterministic-node")
            .unwrap()
            .to_owned();

        let (client, _server) = tokio::join!(
            connector.connect(server_name, client_io),
            acceptor.accept(server_io),
        );
        client.map(|_| ())
    }

    #[tokio::test]
    async fn test_fingerprint_handshake() {
        let password = "handshake_test_password";
        let (cert, key) = generate_deterministic_cert(password).unwrap();
        let fingerprint = fingerprint_of(&cert);

        let server_config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );

        // 正例：指纹匹配且服务端持有对应私钥。
        // 修复前 verify_tls13_signature 无条件放行，握手必然成功；
        // 修复后走真实验签，只有实现正确才能握手成功。
        let client_config = Arc::new(
            CertValidationMode::VerifyFingerprint(fingerprint)
                .create_tls_client_config()
                .unwrap(),
        );
        try_handshake(server_config.clone(), client_config)
            .await
            .expect("handshake with matching fingerprint should succeed");

        // 反例：指纹不匹配（攻击者证书），握手必须失败
        let wrong_fingerprint = [0xABu8; 32];
        let client_config = Arc::new(
            CertValidationMode::VerifyFingerprint(wrong_fingerprint)
                .create_tls_client_config()
                .unwrap(),
        );
        assert!(
            try_handshake(server_config, client_config).await.is_err(),
            "handshake with mismatched fingerprint should fail"
        );
    }
}
