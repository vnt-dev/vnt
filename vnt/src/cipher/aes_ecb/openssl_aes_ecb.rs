use std::ptr;

use anyhow::anyhow;
use libc::c_int;
use openssl_sys::EVP_CIPHER_CTX;

use crate::cipher::Finger;
use crate::protocol::{NetPacket, HEAD_LEN};

pub struct AesEcbCipher {
    key: Vec<u8>,
    pub(crate) en_ctx: *mut EVP_CIPHER_CTX,
    pub(crate) de_ctx: *mut EVP_CIPHER_CTX,
    pub(crate) finger: Option<Finger>,
}

impl Drop for AesEcbCipher {
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_CIPHER_CTX_free(self.de_ctx);
            openssl_sys::EVP_CIPHER_CTX_free(self.en_ctx);
        }
    }
}

impl Clone for AesEcbCipher {
    fn clone(&self) -> Self {
        if self.key.len() == 16 {
            AesEcbCipher::new_128(self.key.clone().try_into().unwrap(), self.finger.clone())
        } else {
            AesEcbCipher::new_256(self.key.clone().try_into().unwrap(), self.finger.clone())
        }
    }
}

unsafe impl Sync for AesEcbCipher {}

unsafe impl Send for AesEcbCipher {}

impl AesEcbCipher {
    pub fn key(&self) -> &[u8] {
        &self.key
    }
}

impl AesEcbCipher {
    pub fn new_128(key: [u8; 16], finger: Option<Finger>) -> Self {
        unsafe {
            let cipher = openssl_sys::EVP_aes_128_ecb();
            let en_ctx = openssl_sys::EVP_CIPHER_CTX_new();
            openssl_sys::EVP_EncryptInit_ex(
                en_ctx,
                cipher,
                ptr::null_mut(),
                key.as_ptr(),
                ptr::null(),
            );

            let de_ctx = openssl_sys::EVP_CIPHER_CTX_new();
            openssl_sys::EVP_DecryptInit_ex(
                de_ctx,
                cipher,
                ptr::null_mut(),
                key.as_ptr(),
                ptr::null(),
            );
            Self {
                key: key.to_vec(),
                en_ctx,
                de_ctx,
                finger,
            }
        }
    }
    pub fn new_256(key: [u8; 32], finger: Option<Finger>) -> Self {
        unsafe {
            let cipher = openssl_sys::EVP_aes_256_ecb();
            let en_ctx = openssl_sys::EVP_CIPHER_CTX_new();
            openssl_sys::EVP_EncryptInit_ex(
                en_ctx,
                cipher,
                ptr::null_mut(),
                key.as_ptr(),
                ptr::null(),
            );
            let de_ctx = openssl_sys::EVP_CIPHER_CTX_new();
            openssl_sys::EVP_DecryptInit_ex(
                de_ctx,
                cipher,
                ptr::null_mut(),
                key.as_ptr(),
                ptr::null(),
            );
            Self {
                key: key.to_vec(),
                en_ctx,
                de_ctx,
                finger,
            }
        }
    }

    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        if !net_packet.is_encrypt() {
            //未加密的数据直接丢弃
            return Err(anyhow!("not encrypt"));
        }

        if let Some(finger) = &self.finger {
            let nonce_raw = net_packet.head_tag();
            let len = net_packet.payload().len();
            if len < 12 {
                return Err(anyhow!("data len err"));
            }
            let secret_body = &net_packet.payload()[..len - 12];
            let finger = finger.calculate_finger(&nonce_raw, secret_body);
            if &finger != &net_packet.payload()[len - 12..] {
                return Err(anyhow!("finger err"));
            }
            net_packet.set_data_len(net_packet.data_len() - finger.len())?;
        }
        if net_packet.payload().len() < 16 {
            log::error!("数据异常,长度{}小于{}", net_packet.payload().len(), 16);
            return Err(anyhow!("data err"));
        }
        let input = net_packet.payload();
        let mut out = [0u8; 1024 * 5];
        let mut out_len = 0;
        let ctx = self.de_ctx;
        unsafe {
            let out_ptr = out.as_mut_ptr();
            let in_len = input.len() as c_int;
            openssl_sys::EVP_DecryptUpdate(ctx, out_ptr, &mut out_len, input.as_ptr(), in_len);
            let mut last_len = 0;
            openssl_sys::EVP_DecryptFinal_ex(ctx, out_ptr.offset(out_len as isize), &mut last_len);
            out_len += last_len;
        }
        let out_len = out_len as usize;
        let text = &out[..out_len];
        {
            //校验头部
            let src_net_packet = NetPacket::new(text)?;
            if src_net_packet.source() != net_packet.source() {
                return Err(anyhow!("data err"));
            }
            if src_net_packet.destination() != net_packet.destination() {
                return Err(anyhow!("data err"));
            }
            if src_net_packet.protocol() != net_packet.protocol() {
                return Err(anyhow!("data err"));
            }
            if src_net_packet.transport_protocol() != net_packet.transport_protocol() {
                return Err(anyhow!("data err"));
            }
            if src_net_packet.is_gateway() != net_packet.is_gateway() {
                return Err(anyhow!("data err"));
            }
            if src_net_packet.source_ttl() != net_packet.source_ttl() {
                return Err(anyhow!("data err"));
            }
        }
        net_packet.set_encrypt_flag(false);
        net_packet.set_data_len(out_len)?;
        net_packet.set_payload(&text[12..])?;
        Ok(())
    }
    /// net_packet 必须预留足够长度  大于 12+16+16
    /// data_len是有效载荷的长度
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> anyhow::Result<()> {
        let input = net_packet.buffer();
        let mut out = [0u8; 1024 * 5];
        let mut out_len = 0;
        let ctx = self.en_ctx;
        //将头部也参与加密
        unsafe {
            let out_ptr = out.as_mut_ptr();
            let in_len = input.len() as c_int;
            openssl_sys::EVP_EncryptUpdate(ctx, out_ptr, &mut out_len, input.as_ptr(), in_len);
            let mut last_len = 0;
            openssl_sys::EVP_EncryptFinal_ex(ctx, out_ptr.offset(out_len as isize), &mut last_len);
            out_len += last_len;
        }
        let out_len = out_len as usize;
        if out_len == 0 {
            return Err(anyhow!("ciphertext len err"));
        }
        //密文
        let ciphertext = &out[..out_len];
        net_packet.set_data_len(HEAD_LEN + out_len)?;
        net_packet.payload_mut().copy_from_slice(ciphertext);
        net_packet.set_encrypt_flag(true);
        if let Some(finger) = &self.finger {
            let nonce_raw = net_packet.head_tag();
            let finger = finger.calculate_finger(&nonce_raw, ciphertext);
            let src_data_len = net_packet.data_len();
            //设置实际长度
            net_packet.set_data_len(src_data_len + finger.len())?;

            net_packet.buffer_mut()[src_data_len..].copy_from_slice(&finger);
        }
        Ok(())
    }
}

#[test]
fn test_openssl_aes_ecb() {
    let d = AesEcbCipher::new_128([0; 16], Some(Finger::new("123")));
    let mut p = NetPacket::new_encrypt([0; 100]).unwrap();
    let src = p.buffer().to_vec();
    d.encrypt_ipv4(&mut p).unwrap();
    d.decrypt_ipv4(&mut p).unwrap();
    assert_eq!(p.buffer(), &src);
}
