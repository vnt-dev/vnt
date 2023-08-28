use std::{fmt, io};

pub const ENCRYPTION_RESERVED: usize = 32;
/* aes_gcm加密数据体
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          数据体                                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         random(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          tag(32)                                            |
  |                                          tag(32)                                            |
  |                                          tag(32)                                            |
  |                                          tag(32)                                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  注：finger用于快速校验数据是否被修改，上层可使用token、协议头参与计算finger，
     确保服务端和客户端都能感知修改(服务端不能解密也能校验指纹)
 */
pub struct SecretBody<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> SecretBody<B> {
    pub fn new(buffer: B) -> io::Result<SecretBody<B>> {
        let len = buffer.as_ref().len();
        // 不能大于udp最大载荷长度
        if len < 32 || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        Ok(SecretBody { buffer })
    }
    pub fn data(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 32;
        &self.buffer.as_ref()[..end]
    }
    pub fn random(&self) -> u32 {
        let end = self.buffer.as_ref().len() - 16 - 12;
        u32::from_be_bytes(self.buffer.as_ref()[end - 4..end].try_into().unwrap())
    }
    pub fn body(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 16 - 12;
        &self.buffer.as_ref()[..end]
    }
    pub fn tag(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 12;
        &self.buffer.as_ref()[end - 16..end]
    }
    /// 数据部分+tag部分
    pub fn en_body(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 12;
        &self.buffer.as_ref()[..end]
    }
    pub fn finger(&self) -> &[u8] {
        let end = self.buffer.as_ref().len();
        &self.buffer.as_ref()[end - 12..end]
    }
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> SecretBody<B> {
    pub fn set_data(&mut self, data: &[u8]) -> io::Result<()> {
        let end = self.buffer.as_ref().len() - 32;
        if end - 4 != data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "end-4 != data.len"));
        }
        self.buffer.as_mut()[..end].copy_from_slice(data);
        Ok(())
    }
    pub fn set_random(&mut self, random: u32) {
        let end = self.buffer.as_ref().len() - 16 - 12;
        self.buffer.as_mut()[end - 4..end].copy_from_slice(&random.to_be_bytes());
    }

    pub fn set_tag(&mut self, tag: &[u8]) -> io::Result<()> {
        if tag.len() != 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tag.len != 16"));
        }
        let end = self.buffer.as_ref().len() - 12;
        self.buffer.as_mut()[end - 16..end].copy_from_slice(tag);
        Ok(())
    }
    pub fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if finger.len() != 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "finger.len != 12"));
        }
        let end = self.buffer.as_ref().len();
        self.buffer.as_mut()[end - 12..end].copy_from_slice(finger);
        Ok(())
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 32;
        &mut self.buffer.as_mut()[..end]
    }
    /// 数据部分
    pub fn body_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 12 - 16;
        &mut self.buffer.as_mut()[..end]
    }
    pub fn tag_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 12;
        &mut self.buffer.as_mut()[end - 16..end]
    }
    /// 数据部分+tag部分
    pub fn en_body_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 12;
        &mut self.buffer.as_mut()[..end]
    }
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for SecretBody<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBody")
            .field("random", &self.random())
            .field("body", &self.body())
            .field("tag", &self.tag())
            .finish()
    }
}
/* aes_cbc加密数据体
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          数据体                                              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         random(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  注：finger用于快速校验数据是否被修改，上层可使用token、协议头参与计算finger，
     确保服务端和客户端都能感知修改(服务端不能解密也能校验指纹)
 */
pub struct AesCbcSecretBody<B> {
    buffer: B,
}
impl<B: AsRef<[u8]>> AesCbcSecretBody<B> {
    pub fn new(buffer: B) -> io::Result<AesCbcSecretBody<B>> {
        let len = buffer.as_ref().len();
        // 不能大于udp最大载荷长度
        if len < 16 || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        Ok(AesCbcSecretBody { buffer })
    }
    pub fn en_body(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 12;
        &self.buffer.as_ref()[..end]
    }
    pub fn finger(&self) -> &[u8] {
        let end = self.buffer.as_ref().len();
        &self.buffer.as_ref()[end - 12..end]
    }
}
impl<B: AsRef<[u8]> + AsMut<[u8]>> AesCbcSecretBody<B> {
    pub fn set_random(&mut self, random: u32) {
        let end = self.buffer.as_ref().len() - 12;
        self.buffer.as_mut()[end - 4..end].copy_from_slice(&random.to_be_bytes());
    }
    pub fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if finger.len() != 12 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "finger.len != 12"));
        }
        let end = self.buffer.as_ref().len();
        self.buffer.as_mut()[end - 12..end].copy_from_slice(finger);
        Ok(())
    }
    pub fn en_body_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 12;
        &mut self.buffer.as_mut()[..end]
    }
}

/* rsa加密数据体
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                          数据体(n)                                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         random(32)                                          |
  |                                         random(32)                                          |
  |                                         random(32)                                          |
  |                                         random(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  |                                         finger(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
pub struct RsaSecretBody<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> RsaSecretBody<B> {
    pub fn new(buffer: B) -> io::Result<RsaSecretBody<B>> {
        let len = buffer.as_ref().len();
        // 不能大于udp最大载荷长度
        if len < 32 || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "length overflow",
            ));
        }
        Ok(RsaSecretBody { buffer })
    }
    pub fn data(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 32;
        &self.buffer.as_ref()[..end]
    }
    pub fn random(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 16;
        &self.buffer.as_ref()[end - 16..end]
    }
    pub fn body(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 16;
        &self.buffer.as_ref()[..end]
    }
    pub fn finger(&self) -> &[u8] {
        let end = self.buffer.as_ref().len() - 16;
        &self.buffer.as_ref()[end..]
    }
    pub fn buffer(&self) -> &[u8] {
        &self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> RsaSecretBody<B> {
    pub fn set_random(&mut self, random: &[u8]) -> io::Result<()> {
        if random.len() != 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "random.len != 16"));
        }
        let end = self.buffer.as_ref().len() - 16;
        self.buffer.as_mut()[end - 16..end].copy_from_slice(random);
        Ok(())
    }
    pub fn random_mut(&mut self) -> &mut [u8] {
        let end = self.buffer.as_ref().len() - 16;
        &mut self.buffer.as_mut()[end - 16..end]
    }
    pub fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if finger.len() != 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "finger.len != 16"));
        }
        let end = self.buffer.as_ref().len();
        self.buffer.as_mut()[end - 16..end].copy_from_slice(finger);
        Ok(())
    }
}