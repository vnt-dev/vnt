use std::{fmt, io};

pub const ENCRYPTION_RESERVED: usize = 16 + 32 + 12;
pub const AES_GCM_ENCRYPTION_RESERVED: usize = 32;
pub const RSA_ENCRYPTION_RESERVED: usize = 32;

pub const RANDOM_RESERVED: usize = 4;
pub const FINGER_RESERVED: usize = 12;
pub const TAG_RESERVED: usize = 16;

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                         random(32)                                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                         finger(32)                                          |
|                                         finger(32)                                          |
|                                         finger(32)                                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
pub trait SecretTail {
    fn buffer(&self) -> &[u8];
    fn exist_finger(&self) -> bool;
    fn random_buf(&self) -> &[u8] {
        let buf = self.buffer();
        let mut end = buf.len();
        if self.exist_finger() {
            end -= FINGER_RESERVED;
        }
        &buf[end - RANDOM_RESERVED..end]
    }
    fn finger(&self) -> &[u8] {
        if self.exist_finger() {
            let buf = self.buffer();
            let end = buf.len();
            &buf[end - FINGER_RESERVED..end]
        } else {
            &[]
        }
    }
}

pub trait SecretTailMut: SecretTail {
    fn buffer_mut(&mut self) -> &mut [u8];
    fn set_random(&mut self, random: &[u8]) {
        let f = self.exist_finger();
        let buf = self.buffer_mut();
        let mut end = buf.len();
        if f {
            end -= FINGER_RESERVED;
        }
        buf[end - RANDOM_RESERVED..end].copy_from_slice(random);
    }
    fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if self.exist_finger() {
            if finger.len() != FINGER_RESERVED {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "finger.len != 12",
                ));
            }
            let buf = self.buffer_mut();
            let end = buf.len();
            buf[end - FINGER_RESERVED..end].copy_from_slice(finger);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not exist finger",
            ))
        }
    }
}

/* aead加密数据体
  0                                            15                                              31
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                          数据体                                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                          tag(32)                                            |
 |                                          tag(32)                                            |
 |                                          tag(32)                                            |
 |                                          tag(32)                                            |
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
pub struct AEADSecretBody<B> {
    buffer: B,
    exist_finger: bool,
}

impl<B: AsRef<[u8]>> AEADSecretBody<B> {
    pub fn new(buffer: B, exist_finger: bool) -> io::Result<AEADSecretBody<B>> {
        let len = buffer.as_ref().len();
        let min_len = if exist_finger {
            TAG_RESERVED + RANDOM_RESERVED + FINGER_RESERVED
        } else {
            TAG_RESERVED + RANDOM_RESERVED
        };
        // 不能大于udp最大载荷长度
        if len < min_len || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("AEADSecretBody length overflow {}", len),
            ));
        }
        Ok(AEADSecretBody {
            buffer,
            exist_finger,
        })
    }
    pub fn data(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len() - TAG_RESERVED - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &self.buffer.as_ref()[..end]
    }
    pub fn tag(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &self.buffer.as_ref()[end - TAG_RESERVED..end]
    }
}

impl<B: AsRef<[u8]>> SecretTail for AEADSecretBody<B> {
    #[inline]
    fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    #[inline]
    fn exist_finger(&self) -> bool {
        self.exist_finger
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> SecretTailMut for AEADSecretBody<B> {
    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AEADSecretBody<B> {
    /// 数据部分
    pub fn data_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED - TAG_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &mut self.buffer.as_mut()[..end]
    }
    /// 数据和tag部分
    pub fn data_tag_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &mut self.buffer.as_mut()[..end]
    }
    pub fn set_tag(&mut self, tag: &[u8]) -> io::Result<()> {
        if tag.len() != 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tag.len != 16"));
        }
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        self.buffer.as_mut()[end - TAG_RESERVED..end].copy_from_slice(tag);
        Ok(())
    }
}

/* 带随机数的加密数据体
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
pub struct IVSecretBody<B> {
    buffer: B,
    exist_finger: bool,
}

impl<B: AsRef<[u8]>> IVSecretBody<B> {
    pub fn new(buffer: B, exist_finger: bool) -> io::Result<IVSecretBody<B>> {
        let len = buffer.as_ref().len();
        let min_len = if exist_finger {
            FINGER_RESERVED + RANDOM_RESERVED
        } else {
            RANDOM_RESERVED
        };
        // 不能大于udp最大载荷长度
        if len < min_len || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IVSecretBody length overflow {}", len),
            ));
        }
        Ok(IVSecretBody {
            buffer,
            exist_finger,
        })
    }
    pub fn data(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &self.buffer.as_ref()[..end]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IVSecretBody<B> {
    pub fn data_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len() - RANDOM_RESERVED;
        if self.exist_finger {
            end -= FINGER_RESERVED;
        }
        &mut self.buffer.as_mut()[..end]
    }
}

impl<B: AsRef<[u8]>> SecretTail for IVSecretBody<B> {
    #[inline]
    fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    #[inline]
    fn exist_finger(&self) -> bool {
        self.exist_finger
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> SecretTailMut for IVSecretBody<B> {
    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

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
    exist_finger: bool,
}

impl<B: AsRef<[u8]>> SecretBody<B> {
    pub fn new(buffer: B, exist_finger: bool) -> io::Result<SecretBody<B>> {
        let len = buffer.as_ref().len();
        let min_len = if exist_finger { 32 } else { 32 - 12 };
        // 不能大于udp最大载荷长度
        if len < min_len || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SecretBody length overflow",
            ));
        }
        Ok(SecretBody {
            buffer,
            exist_finger,
        })
    }
    pub fn random(&self) -> u32 {
        let mut end = self.buffer.as_ref().len() - 16;
        if self.exist_finger {
            end -= 12;
        }
        u32::from_be_bytes(self.buffer.as_ref()[end - 4..end].try_into().unwrap())
    }
    pub fn body(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len() - 16;
        if self.exist_finger {
            end -= 12;
        }
        &self.buffer.as_ref()[..end]
    }
    pub fn tag(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        &self.buffer.as_ref()[end - 16..end]
    }
    /// 数据部分+tag部分
    pub fn en_body(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        &self.buffer.as_ref()[..end]
    }
    pub fn finger(&self) -> &[u8] {
        if self.exist_finger {
            let end = self.buffer.as_ref().len();
            &self.buffer.as_ref()[end - 12..end]
        } else {
            &[]
        }
    }
    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> SecretBody<B> {
    pub fn set_random(&mut self, random: u32) {
        let mut end = self.buffer.as_ref().len() - 16;
        if self.exist_finger {
            end -= 12;
        }
        self.buffer.as_mut()[end - 4..end].copy_from_slice(&random.to_be_bytes());
    }

    pub fn set_tag(&mut self, tag: &[u8]) -> io::Result<()> {
        if tag.len() != 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "tag.len != 16"));
        }
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        self.buffer.as_mut()[end - 16..end].copy_from_slice(tag);
        Ok(())
    }
    pub fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if self.exist_finger {
            if finger.len() != 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "finger.len != 12",
                ));
            }
            let end = self.buffer.as_ref().len();
            self.buffer.as_mut()[end - 12..end].copy_from_slice(finger);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not exist finger",
            ))
        }
    }

    /// 数据部分
    pub fn body_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len() - 16;
        if self.exist_finger {
            end -= 12;
        }
        &mut self.buffer.as_mut()[..end]
    }
    pub fn tag_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        &mut self.buffer.as_mut()[end - 16..end]
    }
    /// 数据部分+tag部分
    pub fn en_body_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
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
            .field("finger", &self.finger())
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
    exist_finger: bool,
}

impl<B: AsRef<[u8]>> AesCbcSecretBody<B> {
    pub fn new(buffer: B, exist_finger: bool) -> io::Result<AesCbcSecretBody<B>> {
        let len = buffer.as_ref().len();
        let min_len = if exist_finger { 16 } else { 16 - 12 };
        // 不能大于udp最大载荷长度
        if len < min_len || len > 65535 - 20 - 8 - 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AesCbcSecretBody length overflow",
            ));
        }
        Ok(AesCbcSecretBody {
            buffer,
            exist_finger,
        })
    }
    pub fn en_body(&self) -> &[u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        &self.buffer.as_ref()[..end]
    }
    pub fn finger(&self) -> &[u8] {
        if self.exist_finger {
            let end = self.buffer.as_ref().len();
            &self.buffer.as_ref()[end - 12..end]
        } else {
            &[]
        }
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AesCbcSecretBody<B> {
    pub fn set_random(&mut self, random: u32) {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
        self.buffer.as_mut()[end - 4..end].copy_from_slice(&random.to_be_bytes());
    }
    pub fn set_finger(&mut self, finger: &[u8]) -> io::Result<()> {
        if self.exist_finger {
            if finger.len() != 12 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "finger.len != 12",
                ));
            }
            let end = self.buffer.as_ref().len();
            self.buffer.as_mut()[end - 12..end].copy_from_slice(finger);
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cbc not exist finger",
            ))
        }
    }
    pub fn en_body_mut(&mut self) -> &mut [u8] {
        let mut end = self.buffer.as_ref().len();
        if self.exist_finger {
            end -= 12;
        }
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "random.len != 16",
            ));
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
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "finger.len != 16",
            ));
        }
        let end = self.buffer.as_ref().len();
        self.buffer.as_mut()[end - 16..end].copy_from_slice(finger);
        Ok(())
    }
}
