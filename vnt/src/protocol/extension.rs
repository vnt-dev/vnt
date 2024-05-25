/* 扩展协议
  0                                            15                                              31
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                                          扩展数据(n)                                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         扩展数据(n)                                 |          type(8)        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 注：扩展数据的长度由type决定
*/

use anyhow::anyhow;
use std::io;

use crate::protocol::NetPacket;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ExtensionTailType {
    Compression,
    Unknown(u8),
}

impl From<u8> for ExtensionTailType {
    fn from(value: u8) -> Self {
        if value == 0 {
            ExtensionTailType::Compression
        } else {
            ExtensionTailType::Unknown(value)
        }
    }
}

pub enum ExtensionTailPacket<B> {
    Compression(CompressionExtensionTail<B>),
    Unknown,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> NetPacket<B> {
    /// 分离尾部数据
    pub fn split_tail_packet(&mut self) -> anyhow::Result<ExtensionTailPacket<&[u8]>> {
        if self.is_extension() {
            let payload = self.payload();
            if let Some(v) = payload.last() {
                return match ExtensionTailType::from(*v) {
                    ExtensionTailType::Compression => {
                        let data_len = self.data_len - 4;
                        self.set_data_len(data_len)?;
                        self.set_extension_flag(false);
                        Ok(ExtensionTailPacket::Compression(
                            CompressionExtensionTail::new(
                                &self.raw_buffer()[data_len..data_len + 4],
                            ),
                        ))
                    }
                    ExtensionTailType::Unknown(e) => Err(anyhow!("unknown extension {}", e)),
                };
            }
        }
        Err(anyhow!("not extension"))
    }
    /// 追加压缩扩展
    pub fn append_compression_extension_tail(
        &mut self,
    ) -> io::Result<CompressionExtensionTail<&mut [u8]>> {
        let len = self.data_len;
        //增加数据长度
        self.set_data_len(self.data_len + 4)?;
        self.set_extension_flag(true);
        let mut tail = CompressionExtensionTail::new(&mut self.buffer_mut()[len..]);
        tail.init();
        return Ok(tail);
    }
}

/* 扩展协议
  0                                            15                                              31
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |     algorithm(8)     |                                            |          type(8)        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 注：扩展数据的长度由type决定
*/
/// 压缩扩展
pub struct CompressionExtensionTail<B> {
    buffer: B,
}

impl<B: AsRef<[u8]>> CompressionExtensionTail<B> {
    pub fn new(buffer: B) -> CompressionExtensionTail<B> {
        assert_eq!(buffer.as_ref().len(), 4);
        CompressionExtensionTail { buffer }
    }
}

impl<B: AsRef<[u8]>> CompressionExtensionTail<B> {
    pub fn algorithm(&self) -> CompressionAlgorithm {
        self.buffer.as_ref()[0].into()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> CompressionExtensionTail<B> {
    pub fn init(&mut self) {
        self.buffer.as_mut().fill(0);
    }
    pub fn set_algorithm(&mut self, algorithm: CompressionAlgorithm) {
        self.buffer.as_mut()[0] = algorithm.into()
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum CompressionAlgorithm {
    #[cfg(feature = "lz4_compress")]
    Lz4,
    #[cfg(feature = "zstd_compress")]
    Zstd,
    Unknown(u8),
}

impl From<u8> for CompressionAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            #[cfg(feature = "lz4_compress")]
            1 => CompressionAlgorithm::Lz4,
            #[cfg(feature = "zstd_compress")]
            2 => CompressionAlgorithm::Zstd,
            v => CompressionAlgorithm::Unknown(v),
        }
    }
}

impl From<CompressionAlgorithm> for u8 {
    fn from(value: CompressionAlgorithm) -> Self {
        match value {
            #[cfg(feature = "lz4_compress")]
            CompressionAlgorithm::Lz4 => 1,
            #[cfg(feature = "zstd_compress")]
            CompressionAlgorithm::Zstd => 2,
            CompressionAlgorithm::Unknown(val) => val,
        }
    }
}
