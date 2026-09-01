//! ZLIB inflate (spec `04_SERVICES` §4.1, §4.4).
//!
//! C++ anchor: `GView::Decoding::ZLIB::Decompress` /
//! `DecompressStream` (`zlib.cpp`).
//!
//! - [`decompress`] mirrors the one-shot `uncompress` path: the
//!   caller states the exact expected output size, which must exceed
//!   the input size and be produced exactly.
//! - [`decompress_stream`] mirrors the streaming `inflate` loop: the
//!   output grows (2× in C++) until the stream ends, and the number
//!   of consumed input bytes is reported.
//!
//! Both enforce [`ZlibLimits::max_output_size`] **before** allocating
//! (spec §4.4 / §9.2) so a decompression bomb is rejected instead of
//! exhausting memory.

use std::io::Read;

use flate2::read::ZlibDecoder;

/// Output-size policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZlibLimits {
    /// Hard cap on produced bytes.
    pub max_output_size: u64,
}

impl Default for ZlibLimits {
    /// 256 MiB.
    fn default() -> Self {
        Self {
            max_output_size: 256 * 1024 * 1024,
        }
    }
}

/// Inflate failures.
#[derive(Debug)]
pub enum ZlibError {
    /// Empty input (C++ `CHECK(inputSize > 0)`).
    EmptyInput,
    /// `output_size <= input_size` (C++ `CHECK(outputSize > inputSize)`).
    OutputNotLargerThanInput,
    /// The requested or produced output exceeds the limit.
    OutputLimitExceeded {
        /// The configured cap.
        limit: u64,
    },
    /// The produced size differs from the declared size
    /// (C++ `CHECK(outputSize == outputSizeCopy)`).
    SizeMismatch {
        /// Declared output size.
        expected: u64,
        /// Bytes actually produced.
        produced: u64,
    },
    /// Corrupt or truncated stream.
    Io(std::io::Error),
}

impl core::fmt::Display for ZlibError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::OutputNotLargerThanInput => write!(f, "output size must exceed input size"),
            Self::OutputLimitExceeded { limit } => write!(f, "output exceeds {limit} bytes"),
            Self::SizeMismatch { expected, produced } => {
                write!(f, "expected {expected} bytes, produced {produced}")
            }
            Self::Io(e) => write!(f, "zlib error: {e}"),
        }
    }
}

impl std::error::Error for ZlibError {}

impl From<std::io::Error> for ZlibError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Reads at most `cap + 1` bytes from `reader`; `Err(OutputLimitExceeded)`
/// when the stream produces more than `cap`.
fn read_capped(reader: &mut impl Read, cap: u64) -> Result<Vec<u8>, ZlibError> {
    let mut out = Vec::new();
    let mut limited = reader.take(cap.saturating_add(1));
    limited.read_to_end(&mut out)?;
    if out.len() as u64 > cap {
        return Err(ZlibError::OutputLimitExceeded { limit: cap });
    }
    Ok(out)
}

/// C++ `ZLIB::Decompress(input, inputSize, output, outputSize)`.
///
/// # Errors
///
/// See [`ZlibError`]; the declared size must be larger than the
/// input, within the limit, and produced exactly.
pub fn decompress(input: &[u8], output_size: u64, limits: ZlibLimits) -> Result<Vec<u8>, ZlibError> {
    if input.is_empty() {
        return Err(ZlibError::EmptyInput);
    }
    if output_size <= input.len() as u64 {
        return Err(ZlibError::OutputNotLargerThanInput);
    }
    if output_size > limits.max_output_size {
        return Err(ZlibError::OutputLimitExceeded {
            limit: limits.max_output_size,
        });
    }
    let mut decoder = ZlibDecoder::new(input);
    let out = read_capped(&mut decoder, output_size)?;
    if out.len() as u64 != output_size {
        return Err(ZlibError::SizeMismatch {
            expected: output_size,
            produced: out.len() as u64,
        });
    }
    Ok(out)
}

/// Streaming result (C++ `DecompressStream` out-parameters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDecoded {
    /// Inflated bytes.
    pub data: Vec<u8>,
    /// Input bytes consumed (C++ `sizeConsumed` = `total_in`).
    pub size_consumed: u64,
}

/// C++ `ZLIB::DecompressStream(input, output, message, sizeConsumed)`:
/// inflates until the stream ends, growing the output as needed.
///
/// # Errors
///
/// [`ZlibError::EmptyInput`], [`ZlibError::OutputLimitExceeded`], or
/// [`ZlibError::Io`] for a corrupt/truncated stream.
pub fn decompress_stream(input: &[u8], limits: ZlibLimits) -> Result<StreamDecoded, ZlibError> {
    if input.is_empty() {
        return Err(ZlibError::EmptyInput);
    }
    let mut decoder = ZlibDecoder::new(input);
    let data = read_capped(&mut decoder, limits.max_output_size)?;
    Ok(StreamDecoded {
        size_consumed: decoder.total_in(),
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn one_shot_roundtrip_with_exact_size() {
        let plain = b"hello hello hello hello hello zlib world".repeat(20);
        let packed = deflate(&plain);
        let out = decompress(&packed, plain.len() as u64, ZlibLimits::default()).unwrap();
        assert_eq!(out, plain);
        // Wrong declared size → mismatch.
        assert!(matches!(
            decompress(&packed, plain.len() as u64 + 1, ZlibLimits::default()),
            Err(ZlibError::SizeMismatch { .. })
        ));
        // Output must exceed input; empty input rejected.
        assert!(matches!(
            decompress(&packed, packed.len() as u64, ZlibLimits::default()),
            Err(ZlibError::OutputNotLargerThanInput)
        ));
        assert!(matches!(
            decompress(&[], 10, ZlibLimits::default()),
            Err(ZlibError::EmptyInput)
        ));
    }

    #[test]
    fn stream_roundtrip_reports_consumed_bytes() {
        let plain: Vec<u8> = (0..50_000_u32).map(|i| (i % 251) as u8).collect();
        let mut packed = deflate(&plain);
        let consumed_expected = packed.len() as u64;
        packed.extend_from_slice(b"TRAILING GARBAGE");
        let out = decompress_stream(&packed, ZlibLimits::default()).unwrap();
        assert_eq!(out.data, plain);
        assert_eq!(out.size_consumed, consumed_expected);
        // Corrupt stream → error.
        assert!(matches!(
            decompress_stream(b"\x78\x9c\xff\xff\xff", ZlibLimits::default()),
            Err(ZlibError::Io(_))
        ));
    }

    #[test]
    fn zlib_bomb_is_rejected_by_the_output_cap() {
        // 8 MiB of zeros compresses to a few KiB.
        let bomb = deflate(&vec![0_u8; 8 * 1024 * 1024]);
        assert!(bomb.len() < 64 * 1024);
        let limits = ZlibLimits {
            max_output_size: 1024 * 1024,
        };
        assert!(matches!(
            decompress_stream(&bomb, limits),
            Err(ZlibError::OutputLimitExceeded { limit }) if limit == 1024 * 1024
        ));
        // The one-shot path refuses before inflating at all.
        assert!(matches!(
            decompress(&bomb, 8 * 1024 * 1024, limits),
            Err(ZlibError::OutputLimitExceeded { .. })
        ));
        // Within the cap it inflates fine.
        let ok = decompress_stream(&bomb, ZlibLimits::default()).unwrap();
        assert_eq!(ok.data.len(), 8 * 1024 * 1024);
    }
}
