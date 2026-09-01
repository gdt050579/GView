//! `TextViewer` line index
//! (C++ `Instance::RecomputeLineIndexes`,
//! `TextViewer/Instance.cpp:325-441`; encoding/BOM per
//! `CharacterEncoding.cpp`; spec `02_VIEWER_TEXT` §3.1–3.2).
//!
//! C++ parity notes:
//! - The line scan starts at `sizeOfBOM`, not 0.
//! - A line is capped at 2000 characters; the split segment carries
//!   2001 characters (the check runs after the increment).
//! - Partial (non-EOF) chunks larger than 16 bytes are trimmed by 8
//!   bytes so a multi-byte character is never split (§3.1).
//! - **Chunk-boundary quirk (preserved):** the trailing-line push at
//!   the end of each chunk (`Instance.cpp:420-424`) neither resets
//!   the accumulator nor is limited to the final chunk, so a line
//!   spanning a chunk boundary is recorded once truncated and once in
//!   full. Only files larger than the cache size are affected.
//! - The estimation divides by the sample length; an empty file would
//!   divide by zero in C++ — the Rust port returns the additive
//!   constant instead.

use gview_core::cache::DataCache;

/// Text encodings recognized by the viewer
/// (C++ `CharacterEncoding::Encoding`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// 7-bit text.
    Ascii,
    /// UTF-8 (with or without BOM).
    Utf8,
    /// UTF-16 little endian.
    Utf16Le,
    /// UTF-16 big endian.
    Utf16Be,
    /// Anything else: bytes rendered one by one.
    Binary,
}

/// Encoding plus the BOM length to skip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodingInfo {
    /// Detected encoding.
    pub encoding: Encoding,
    /// Bytes of BOM to skip before the first line.
    pub bom_size: u32,
}

/// Detects encoding and BOM from a leading sample
/// (C++ `AnalyzeBufferForEncoding`, spec §3.2).
#[must_use]
pub fn analyze_encoding(sample: &[u8]) -> EncodingInfo {
    if sample.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return EncodingInfo {
            encoding: Encoding::Utf8,
            bom_size: 3,
        };
    }
    if sample.starts_with(&[0xFE, 0xFF]) {
        return EncodingInfo {
            encoding: Encoding::Utf16Be,
            bom_size: 2,
        };
    }
    if sample.starts_with(&[0xFF, 0xFE]) {
        return EncodingInfo {
            encoding: Encoding::Utf16Le,
            bom_size: 2,
        };
    }
    // Heuristic UTF-16: many zero bytes in one half of the pairs.
    let pairs = sample.len() / 2;
    if pairs >= 4 {
        let mut zero_high = 0_usize;
        let mut zero_low = 0_usize;
        for pair in sample.as_chunks::<2>().0 {
            if pair.get(1) == Some(&0) {
                zero_high = zero_high.saturating_add(1);
            }
            if pair.first() == Some(&0) {
                zero_low = zero_low.saturating_add(1);
            }
        }
        if zero_high.saturating_mul(100) >= pairs.saturating_mul(75) {
            return EncodingInfo {
                encoding: Encoding::Utf16Le,
                bom_size: 0,
            };
        }
        if zero_low.saturating_mul(100) >= pairs.saturating_mul(75) {
            return EncodingInfo {
                encoding: Encoding::Utf16Be,
                bom_size: 0,
            };
        }
    }
    // >= 75% printable/UTF-8 → text.
    if !sample.is_empty() {
        let textual = sample
            .iter()
            .filter(|&&b| b == 9 || b == 10 || b == 13 || (0x20..=0x7E).contains(&b) || b >= 0x80)
            .count();
        if textual.saturating_mul(100) >= sample.len().saturating_mul(75) {
            let encoding = if sample.iter().any(|&b| b >= 0x80) {
                Encoding::Utf8
            } else {
                Encoding::Ascii
            };
            return EncodingInfo {
                encoding,
                bom_size: 0,
            };
        }
    }
    EncodingInfo {
        encoding: Encoding::Binary,
        bom_size: 0,
    }
}

/// One logical line (C++ `LineInfo`): start offset, character count,
/// byte size **excluding** the terminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineInfo {
    /// File offset of the first byte of the line.
    pub offset: u64,
    /// Characters in the line.
    pub char_count: u32,
    /// Bytes in the line (terminator excluded).
    pub byte_size: u32,
}

/// Decodes one character; `Some((code, byte_len))` or `None` on a
/// malformed sequence (C++ `ExpandedCharacter::FromEncoding`).
pub(crate) fn decode_char(encoding: Encoding, bytes: &[u8], at: usize) -> Option<(u32, usize)> {
    let first = *bytes.get(at)?;
    match encoding {
        Encoding::Ascii | Encoding::Binary => Some((u32::from(first), 1)),
        Encoding::Utf8 => {
            if first < 0x80 {
                return Some((u32::from(first), 1));
            }
            let len = match first {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => return None,
            };
            let end = at.checked_add(len)?;
            let seq = bytes.get(at..end)?;
            let text = core::str::from_utf8(seq).ok()?;
            let ch = text.chars().next()?;
            Some((ch as u32, len))
        }
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let second = *bytes.get(at.checked_add(1)?)?;
            let unit = if encoding == Encoding::Utf16Le {
                u16::from_le_bytes([first, second])
            } else {
                u16::from_be_bytes([first, second])
            };
            if (0xD800..=0xDBFF).contains(&unit) {
                // High surrogate: needs a low surrogate partner.
                let b3 = *bytes.get(at.checked_add(2)?)?;
                let b4 = *bytes.get(at.checked_add(3)?)?;
                let low = if encoding == Encoding::Utf16Le {
                    u16::from_le_bytes([b3, b4])
                } else {
                    u16::from_be_bytes([b3, b4])
                };
                if (0xDC00..=0xDFFF).contains(&low) {
                    let code = 0x1_0000_u32
                        .saturating_add((u32::from(unit) & 0x3FF) << 10)
                        .saturating_add(u32::from(low) & 0x3FF);
                    return Some((code, 4));
                }
                return None;
            }
            Some((u32::from(unit), 2))
        }
    }
}

/// Line-count estimation (C++ `Instance.cpp:328-337`):
/// `((count('\n' or '\r') + 1) * file_size / sample_len) + 16`.
#[must_use]
pub fn estimate_line_count(sample: &[u8], file_size: u64) -> u64 {
    let crlf_count =
        1_u64.saturating_add(sample.iter().filter(|&&b| b == b'\n' || b == b'\r').count() as u64);
    if sample.is_empty() {
        // C++ would divide by zero here; return the additive tail.
        return 16;
    }
    crlf_count
        .saturating_mul(file_size)
        .checked_div(sample.len() as u64)
        .unwrap_or(0)
        .saturating_add(16)
}

/// Builds the logical-line table
/// (C++ `RecomputeLineIndexes`, `Instance.cpp:325-425`).
#[allow(clippy::arithmetic_side_effects)] // chunk indices bounded by buffer length
pub fn build_line_index(cache: &mut DataCache, encoding: Encoding, bom_size: u32) -> Vec<LineInfo> {
    let file_size = cache.size();
    let sample = cache
        .get(0, 4096, false)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    let estimated = estimate_line_count(&sample, file_size);
    let mut lines: Vec<LineInfo> =
        Vec::with_capacity(usize::try_from(estimated.min(1 << 20)).unwrap_or(16));

    let chunk_size = cache.cache_size() & 0xFFF_FFF0;
    let mut offset = u64::from(bom_size);
    let mut start = u64::from(bom_size);
    let mut char_count = 0_u32;
    let mut last_char = 0_u32;

    while offset < file_size {
        let Ok(buf) = cache.get(offset, chunk_size, false) else {
            return lines;
        };
        let bytes = buf.to_vec(); // chunk snapshot (cache reuse below)
        let len = bytes.len();
        // Partial chunk + more than 16 bytes: trim 8 so no multi-byte
        // character is split (Instance.cpp:358-363).
        let loop_end = if offset.saturating_add(len as u64) < file_size && len > 16 {
            len - 8
        } else {
            len
        };
        let mut p = 0_usize;
        while p < loop_end {
            if let Some((chr, ch_len)) = decode_char(encoding, &bytes, p) {
                p += ch_len;
                let is_lf = chr == u32::from(b'\n');
                let is_cr = chr == u32::from(b'\r');
                if (is_lf && last_char != u32::from(b'\r'))
                    || (is_cr && last_char != u32::from(b'\n'))
                {
                    // Line terminator.
                    lines.push(LineInfo {
                        offset: start,
                        char_count,
                        byte_size: (offset.saturating_sub(start)) as u32,
                    });
                    offset = offset.saturating_add(ch_len as u64);
                    start = offset;
                    char_count = 0;
                    last_char = chr;
                    continue;
                }
                if (is_lf && last_char == u32::from(b'\r'))
                    || (is_cr && last_char == u32::from(b'\n'))
                {
                    // Second half of CRLF / LFCR.
                    offset = offset.saturating_add(ch_len as u64);
                    start = offset;
                    char_count = 0;
                    last_char = 0;
                    continue;
                }
                last_char = 0;
                char_count = char_count.saturating_add(1);
                offset = offset.saturating_add(ch_len as u64);
            } else {
                // Decode failure: one raw byte (Instance.cpp:404-418).
                char_count = char_count.saturating_add(1);
                offset = offset.saturating_add(1);
                p += 1;
            }
            // Both paths cap a line at 2000 characters (the split
            // segment carries 2001 — the check runs post-increment).
            if char_count > 2000 {
                lines.push(LineInfo {
                    offset: start,
                    char_count,
                    byte_size: (offset.saturating_sub(start)) as u32,
                });
                start = offset;
                char_count = 0;
            }
        }
        // C++ quirk (Instance.cpp:420-424): the trailing push runs per
        // chunk without resetting the accumulator — see module docs.
        if char_count > 0 {
            lines.push(LineInfo {
                offset: start,
                char_count,
                byte_size: (offset.saturating_sub(start)) as u32,
            });
        }
    }
    lines
}

/// Gutter width from the line count
/// (C++ tiers, `Instance.cpp:427-441`).
#[must_use]
pub const fn line_number_width(lines: usize) -> u32 {
    let count = lines.saturating_add(1);
    if count < 10 {
        2
    } else if count < 100 {
        3
    } else if count < 1_000 {
        4
    } else if count < 10_000 {
        5
    } else if count < 100_000 {
        6
    } else {
        7
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    fn index_of(data: &[u8]) -> Vec<LineInfo> {
        let mut cache = DataCache::new(Box::new(MemorySource::from_slice(data)), 0);
        let info = analyze_encoding(data.get(..data.len().min(4096)).unwrap_or(data));
        build_line_index(&mut cache, info.encoding, info.bom_size)
    }

    #[test]
    fn crlf_lf_cr_line_endings() {
        // CRLF
        let lines = index_of(b"aa\r\nbbb\r\nc");
        assert_eq!(
            lines,
            vec![
                LineInfo {
                    offset: 0,
                    char_count: 2,
                    byte_size: 2
                },
                LineInfo {
                    offset: 4,
                    char_count: 3,
                    byte_size: 3
                },
                LineInfo {
                    offset: 9,
                    char_count: 1,
                    byte_size: 1
                },
            ]
        );
        // LF only
        let lines = index_of(b"aa\nbbb\nc");
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[1],
            LineInfo {
                offset: 3,
                char_count: 3,
                byte_size: 3
            }
        );
        // CR only
        let lines = index_of(b"aa\rbbb\rc");
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[1],
            LineInfo {
                offset: 3,
                char_count: 3,
                byte_size: 3
            }
        );
        // Consecutive LFs make empty lines.
        let lines = index_of(b"a\n\nb");
        assert_eq!(lines.len(), 3);
        assert_eq!(
            lines[1],
            LineInfo {
                offset: 2,
                char_count: 0,
                byte_size: 0
            }
        );
    }

    #[test]
    fn utf8_bom_skipped() {
        let mut data = vec![0xEF, 0xBB, 0xBF];
        data.extend_from_slice(b"hi\nthere");
        let lines = index_of(&data);
        assert_eq!(
            lines[0],
            LineInfo {
                offset: 3,
                char_count: 2,
                byte_size: 2
            }
        );
        assert_eq!(lines[1].offset, 6);
    }

    #[test]
    fn long_line_capped_at_2001_chars() {
        let data = vec![b'x'; 2500];
        let lines = index_of(&data);
        assert_eq!(lines.len(), 2);
        // The check runs after the increment: 2001-char segment.
        assert_eq!(
            lines[0],
            LineInfo {
                offset: 0,
                char_count: 2001,
                byte_size: 2001
            }
        );
        assert_eq!(
            lines[1],
            LineInfo {
                offset: 2001,
                char_count: 499,
                byte_size: 499
            }
        );
    }

    #[test]
    fn estimate_formula() {
        // 10 terminators in a 100-byte sample of a 1000-byte file:
        // (10 + 1) * 1000 / 100 + 16 = 126.
        let mut sample = vec![b'a'; 90];
        sample.extend_from_slice(&[b'\n'; 10]);
        assert_eq!(estimate_line_count(&sample, 1000), 126);
        assert_eq!(estimate_line_count(&[], 0), 16);
    }

    #[test]
    fn encoding_detection() {
        assert_eq!(
            analyze_encoding(&[0xEF, 0xBB, 0xBF, b'a']),
            EncodingInfo {
                encoding: Encoding::Utf8,
                bom_size: 3
            }
        );
        assert_eq!(
            analyze_encoding(&[0xFF, 0xFE, b'a', 0]),
            EncodingInfo {
                encoding: Encoding::Utf16Le,
                bom_size: 2
            }
        );
        assert_eq!(
            analyze_encoding(&[0xFE, 0xFF, 0, b'a']),
            EncodingInfo {
                encoding: Encoding::Utf16Be,
                bom_size: 2
            }
        );
        // BOM-less UTF-16 LE by zero-high-byte heuristic.
        let wide: Vec<u8> = b"hello world!".iter().flat_map(|&b| [b, 0]).collect();
        assert_eq!(analyze_encoding(&wide).encoding, Encoding::Utf16Le);
        // Plain ASCII.
        assert_eq!(analyze_encoding(b"hello\nworld").encoding, Encoding::Ascii);
        // Mostly non-printable → binary.
        let junk: Vec<u8> = (0..64_u8).map(|i| i % 8).collect();
        assert_eq!(analyze_encoding(&junk).encoding, Encoding::Binary);
    }

    #[test]
    fn utf16_line_endings() {
        // "ab\ncd" as UTF-16 LE with BOM.
        let mut data = vec![0xFF, 0xFE];
        for &b in b"ab\ncd" {
            data.push(b);
            data.push(0);
        }
        let lines = index_of(&data);
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            LineInfo {
                offset: 2,
                char_count: 2,
                byte_size: 4
            }
        );
        assert_eq!(
            lines[1],
            LineInfo {
                offset: 8,
                char_count: 2,
                byte_size: 4
            }
        );
    }

    #[test]
    fn gutter_width_tiers() {
        assert_eq!(line_number_width(5), 2);
        assert_eq!(line_number_width(50), 3);
        assert_eq!(line_number_width(500), 4);
        assert_eq!(line_number_width(5000), 5);
        assert_eq!(line_number_width(50_000), 6);
        assert_eq!(line_number_width(500_000), 7);
    }

    #[test]
    fn multi_chunk_scan_preserves_cpp_boundary_quirk() {
        // File larger than the 64 KiB cache with a line crossing the
        // chunk boundary: the C++ per-chunk trailing push records the
        // truncated prefix in addition to the real lines.
        let mut data = Vec::new();
        for _ in 0..700 {
            data.extend_from_slice(&[b'y'; 99]);
            data.push(b'\n');
        }
        assert!(data.len() > 0x1_0000);
        let lines = index_of(&data);
        // 700 real lines plus one duplicate partial line per chunk
        // boundary crossed mid-line.
        assert!(lines.len() >= 700, "got {}", lines.len());
        let extras = lines.len() - 700;
        assert!(extras <= 2, "unexpected extra lines: {extras}");
        // Real lines are intact around the start and end.
        assert_eq!(
            lines[0],
            LineInfo {
                offset: 0,
                char_count: 99,
                byte_size: 99
            }
        );
        let last = lines.last().expect("lines");
        assert_eq!(last.char_count, 99);
    }
}
