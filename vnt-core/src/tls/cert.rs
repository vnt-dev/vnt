use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519, SerialNumber};
use rustls::pki_types;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, // Sequence (len 46)
    0x02, 0x01, 0x00, // Version 0
    0x30, 0x05, // Sequence (len 5)
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID: 1.3.101.112 (Ed25519)
    0x04, 0x22, // Octet String (len 34) - 包装私钥
    0x04, 0x20, // Octet String (len 32) - 内部 CurvePrivateKey
];

pub fn generate_deterministic_cert(
    password: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // 基于密码生成 32 字节的确定性种子
    let seed = derive_seed_from_password(password);

    let mut pkcs8_bytes = Vec::with_capacity(ED25519_PKCS8_V1_PREFIX.len() + seed.len());
    pkcs8_bytes.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
    pkcs8_bytes.extend_from_slice(&seed);
    let private_key_der = pki_types::PrivateKeyDer::try_from(pkcs8_bytes.clone())
        .map_err(|e| anyhow::anyhow!("Failed to convert private key: {}", e))?;
    let key_pair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_ED25519)
        .context("Failed to load determinstic Ed25519 key")?;

    let mut params = CertificateParams::new(vec!["deterministic-node".to_string()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "Deterministic Self-Signed Cert");

    let not_before = OffsetDateTime::UNIX_EPOCH;
    let not_after = not_before + Duration::days(365 * 1000);
    params.not_before = not_before;
    params.not_after = not_after;

    let serial_number_bytes = derive_serial_number(password);
    params.serial_number = Some(SerialNumber::from_slice(&serial_number_bytes));

    // Ed25519 签名是确定性的 (RFC 8032)，不需要随机数，因此每次运行结果字节完全一致
    let cert = params
        .self_signed(&key_pair)
        .context("Failed to sign certificate")?;

    let cert_der = cert.der().clone();

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_bytes));

    Ok((cert_der, private_key_der))
}

fn derive_serial_number(password: &str) -> [u8; 20] {
    let mut hasher = Sha256::new();
    hasher.update(b"vnt-serial-v1:");
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    let mut serial = [0u8; 20];
    serial.copy_from_slice(&result[..20]);
    serial
}

fn derive_seed_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vnt-ed25519-seed-v1:");
    hasher.update(password.as_bytes());

    let mut result = hasher.finalize();
    for _ in 0..10 {
        let mut hasher = Sha256::new();
        hasher.update(result);
        result = hasher.finalize();
    }

    result.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_cert_generation() {
        let password = "test_password_123";

        // 生成两次证书
        let (cert1, key1) = generate_deterministic_cert(password).unwrap();
        let (cert2, key2) = generate_deterministic_cert(password).unwrap();

        // 验证私钥相同
        assert_eq!(
            key1.secret_der(),
            key2.secret_der(),
            "Private keys should be identical"
        );

        // 验证证书相同
        assert_eq!(cert1, cert2, "Certificates should be identical");
    }

    #[test]
    fn test_different_passwords_generate_different_certs() {
        let (cert1, key1) = generate_deterministic_cert("password1").unwrap();
        let (cert2, key2) = generate_deterministic_cert("password2").unwrap();

        // 不同密码应该生成不同的证书和密钥
        assert_ne!(cert1, cert2);
        assert_ne!(key1.secret_der(), key2.secret_der());
    }
}
