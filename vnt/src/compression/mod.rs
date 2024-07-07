use std::str::FromStr;

use anyhow::anyhow;

#[cfg(feature = "lz4_compress")]
use crate::compression::lz4_compress::Lz4Compressor;
#[cfg(feature = "zstd_compress")]
use crate::compression::zstd_compress::ZstdCompressor;
use crate::protocol::extension::CompressionAlgorithm;
#[cfg(feature = "zstd_compress")]
use zstd::zstd_safe::CompressionLevel;

use crate::protocol::NetPacket;

#[cfg(feature = "lz4_compress")]
mod lz4_compress;
#[cfg(feature = "zstd_compress")]
mod zstd_compress;

#[derive(Clone, Copy, Debug)]
pub enum Compressor {
    #[cfg(feature = "lz4_compress")]
    Lz4,
    #[cfg(feature = "zstd_compress")]
    Zstd(CompressionLevel),
    None,
}

impl FromStr for Compressor {
    type Err = String;
    #[cfg(not(any(feature = "lz4_compress", feature = "zstd_compress")))]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Err(format!("not match '{}', Compression not supported", s))
    }
    #[cfg(any(feature = "lz4_compress", feature = "zstd_compress"))]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str = s.trim().to_lowercase();
        match str.as_str() {
            #[cfg(feature = "lz4_compress")]
            "lz4" => Ok(Compressor::Lz4),
            #[cfg(feature = "zstd_compress")]
            "zstd" => Ok(Compressor::Zstd(9)),
            "none" => Ok(Compressor::None),
            _ => {
                #[cfg(feature = "zstd_compress")]
                {
                    let string_array: Vec<String> = str.split(',').map(|s| s.to_string()).collect();
                    if string_array.len() != 2 || string_array[0] != "zstd" {
                        return Err(format!("not match '{}', exp: zstd,10", s));
                    }
                    return match CompressionLevel::from_str(&string_array[1]) {
                        Ok(level) => Ok(Compressor::Zstd(level)),
                        Err(_) => Err(format!("not match '{}', exp: zstd,10", s)),
                    };
                }
                #[cfg(not(feature = "zstd_compress"))]
                #[cfg(feature = "lz4_compress")]
                return Err(format!("not match '{}', exp: lz4", s));
            }
        }
    }
}

#[cfg(not(any(feature = "lz4_compress", feature = "zstd_compress")))]
impl Compressor {
    pub fn compress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        _in_net_packet: &NetPacket<I>,
        _out: &mut NetPacket<O>,
    ) -> anyhow::Result<bool> {
        Ok(false)
    }
    pub fn decompress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        _algorithm: CompressionAlgorithm,
        _in_net_packet: &NetPacket<I>,
        _out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        Err(anyhow!("Unsupported decompress"))
    }
}

#[cfg(any(feature = "lz4_compress", feature = "zstd_compress"))]
impl Compressor {
    pub fn compress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<bool> {
        match self {
            #[cfg(feature = "lz4_compress")]
            Compressor::Lz4 => {
                if in_net_packet.data_len() < 128 {
                    return Ok(false);
                }
                Lz4Compressor::compress(in_net_packet, out)?;
                let mut compression_extension_tail = out.append_compression_extension_tail()?;
                compression_extension_tail.set_algorithm(CompressionAlgorithm::Lz4);
                //压缩没效果，则放弃压缩
                if out.data_len() >= in_net_packet.data_len() - 16 {
                    return Ok(false);
                }
                return Ok(true);
            }
            #[cfg(feature = "zstd_compress")]
            Compressor::Zstd(level) => {
                if in_net_packet.data_len() < 128 {
                    return Ok(false);
                }
                ZstdCompressor::compress(*level, in_net_packet, out)?;
                let mut compression_extension_tail = out.append_compression_extension_tail()?;
                compression_extension_tail.set_algorithm(CompressionAlgorithm::Zstd);
                //压缩没效果，则放弃压缩
                if out.data_len() >= in_net_packet.data_len() - 16 {
                    return Ok(false);
                }
                return Ok(true);
            }
            Compressor::None => {}
        }
        Ok(false)
    }
    pub fn decompress<I: AsRef<[u8]>, O: AsRef<[u8]> + AsMut<[u8]>>(
        algorithm: CompressionAlgorithm,
        in_net_packet: &NetPacket<I>,
        out: &mut NetPacket<O>,
    ) -> anyhow::Result<()> {
        match algorithm {
            #[cfg(feature = "lz4_compress")]
            CompressionAlgorithm::Lz4 => Lz4Compressor::decompress(in_net_packet, out),
            #[cfg(feature = "zstd_compress")]
            CompressionAlgorithm::Zstd => ZstdCompressor::decompress(in_net_packet, out),
            _ => Err(anyhow!("Unknown decompress {:?}", algorithm)),
        }
    }
}

#[test]
#[cfg(feature = "zstd_compress")]
fn test_lz4() {
    use crate::protocol::extension::{CompressionAlgorithm, ExtensionTailPacket};
    let lz4 = Compressor::Lz4;
    let in_packet = NetPacket::new([
        65, 108, 105, 99, 101, 32, 119, 97, 116, 32, 98, 101, 103, 105, 110, 110, 105, 110, 103,
        32, 116, 111, 32, 103, 101, 116, 32, 118, 101, 114, 121, 32, 116, 105, 114, 101, 100, 32,
        111, 102, 32, 115, 105, 116, 116, 105, 110, 103, 32, 98, 121, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 111, 110, 32, 116, 104, 101, 32, 98, 97, 110, 107, 44, 32, 97,
        110, 100, 32, 111, 102, 32, 104, 97, 118, 105, 110, 103, 32, 110, 111, 116, 104, 105, 110,
        103, 32, 116, 111, 32, 100, 111, 58, 32, 111, 110, 99, 101, 32, 111, 114, 32, 116, 119,
        105, 99, 101, 32, 115, 104, 101, 32, 104, 97, 100, 32, 112, 101, 101, 112, 101, 100, 32,
        105, 110, 116, 111, 32, 116, 104, 101, 32, 98, 111, 111, 107, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 119, 97, 115, 32, 114, 101, 97, 100, 105, 110, 103, 44, 32,
        98, 117, 116, 32, 105, 116, 32, 104, 97, 100, 32, 110, 111, 32, 112, 105, 99, 116, 117,
        114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118, 101, 114, 115, 97, 116, 105,
    ])
    .unwrap();
    let mut out_packet = NetPacket::new([0; 1000]).unwrap();
    let mut src_out_packet = NetPacket::new([0; 1000]).unwrap();
    lz4.compress(&in_packet, &mut out_packet).unwrap();
    let tail = out_packet.split_tail_packet().unwrap();
    match tail {
        ExtensionTailPacket::Compression(c) => match c.algorithm() {
            CompressionAlgorithm::Lz4 => {
                Compressor::decompress(CompressionAlgorithm::Lz4, &out_packet, &mut src_out_packet)
                    .unwrap();
            }
            _ => {
                unimplemented!()
            }
        },
        _ => {
            unimplemented!()
        }
    }
    assert!(!out_packet.is_extension());
    assert_eq!(in_packet.payload(), src_out_packet.payload())
}
#[test]
#[cfg(feature = "zstd_compress")]
fn test_zstd() {
    use crate::protocol::extension::{CompressionAlgorithm, ExtensionTailPacket};
    let zstd = Compressor::Zstd(22);
    let in_packet = NetPacket::new([
        65, 108, 105, 99, 101, 32, 119, 97, 115, 32, 98, 101, 103, 105, 110, 110, 105, 110, 103,
        32, 116, 111, 32, 103, 101, 116, 32, 118, 101, 114, 121, 32, 116, 105, 114, 101, 100, 32,
        111, 102, 32, 115, 105, 116, 116, 105, 110, 103, 32, 98, 121, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 111, 110, 32, 116, 104, 101, 32, 98, 97, 110, 107, 44, 32, 97,
        110, 100, 32, 111, 102, 32, 104, 97, 118, 105, 110, 103, 32, 110, 111, 116, 104, 105, 110,
        103, 32, 116, 111, 32, 100, 111, 58, 32, 111, 110, 99, 101, 32, 111, 114, 32, 116, 119,
        105, 99, 101, 32, 115, 104, 101, 32, 104, 97, 100, 32, 112, 101, 101, 112, 101, 100, 32,
        105, 110, 116, 111, 32, 116, 104, 101, 32, 98, 111, 111, 107, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 119, 97, 115, 32, 114, 101, 97, 100, 105, 110, 103, 44, 32,
        98, 117, 116, 32, 105, 116, 32, 104, 97, 100, 32, 110, 111, 32, 112, 105, 99, 116, 117,
        114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118, 101, 114, 115, 97, 116, 105,
    ])
    .unwrap();
    let mut out_packet = NetPacket::new([0; 1000]).unwrap();
    let mut src_out_packet = NetPacket::new([0; 1000]).unwrap();
    zstd.compress(&in_packet, &mut out_packet).unwrap();
    let tail = out_packet.split_tail_packet().unwrap();
    match tail {
        ExtensionTailPacket::Compression(c) => match c.algorithm() {
            CompressionAlgorithm::Zstd => {
                Compressor::decompress(
                    CompressionAlgorithm::Zstd,
                    &out_packet,
                    &mut src_out_packet,
                )
                .unwrap();
            }
            _ => {
                unimplemented!()
            }
        },
        _ => {
            unimplemented!()
        }
    }
    assert!(!out_packet.is_extension());
    assert_eq!(in_packet.payload(), src_out_packet.payload())
}
