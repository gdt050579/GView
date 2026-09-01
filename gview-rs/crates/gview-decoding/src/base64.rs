//! Base64 (spec `04_SERVICES` §4.1: "RFC-style; decode skips `\r\n`;
//! padding trim").
//!
//! C++ anchor: `GView::Decoding::Base64::Encode` / `Decode`
//! (`Base64.cpp`).
//!
//! Decode semantics preserved from C++: `\r`/`\n` are skipped
//! anywhere; `=` contributes zero bits and counts as padding; input
//! after a completed `=`-terminated group stops decoding with the
//! warning `Ignoring extra bytes after the end of buffer`; any other
//! non-alphabet byte (including bytes `>= 128`) fails; three or more
//! padding characters fail; the trailing `paddingCount` bytes are
//! trimmed from the output; a trailing incomplete group is dropped.
//!
//! Encode is standard RFC 4648 (the spec's "RFC-style"). The C++
//! encoder builds its 24-bit group from `char` values, which are
//! sign-extended for bytes `>= 0x80` and corrupt neighbouring sextets
//! on those platforms — that is a bug, not preserved.

/// Decode failure (C++ `CHECK` → `false`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base64Error {
    /// A byte outside the alphabet / control set.
    InvalidCharacter {
        /// Offset of the offending byte.
        offset: usize,
    },
    /// Three or more `=` characters.
    TooMuchPadding,
}

impl core::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidCharacter { offset } => {
                write!(f, "invalid base64 character at offset {offset}")
            }
            Self::TooMuchPadding => write!(f, "too many padding characters"),
        }
    }
}

impl std::error::Error for Base64Error {}

/// C++ `warningMessage` text.
pub const EXTRA_BYTES_WARNING: &str = "Ignoring extra bytes after the end of buffer";

const ENCODE_TABLE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// C++ `BASE64_DECODE_TABLE` lookup: `None` for non-alphabet bytes.
const fn decode_value(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(byte.wrapping_sub(b'A') as u32),
        b'a'..=b'z' => Some(byte.wrapping_sub(b'a').wrapping_add(26) as u32),
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0').wrapping_add(52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decoded output plus the optional C++ warning.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    /// Decoded bytes.
    pub data: Vec<u8>,
    /// C++ `hasWarning` / `warningMessage`.
    pub warning: Option<&'static str>,
}

/// RFC 4648 encoding with `=` padding.
#[must_use]
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    let (chunks, rest) = input.as_chunks::<3>();
    for chunk in chunks {
        let sequence =
            (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(ENCODE_TABLE[((sequence >> 18) & 0x3F) as usize]);
        out.push(ENCODE_TABLE[((sequence >> 12) & 0x3F) as usize]);
        out.push(ENCODE_TABLE[((sequence >> 6) & 0x3F) as usize]);
        out.push(ENCODE_TABLE[(sequence & 0x3F) as usize]);
    }
    match rest.len() {
        1 => {
            let sequence = u32::from(rest[0]) << 16;
            out.push(ENCODE_TABLE[((sequence >> 18) & 0x3F) as usize]);
            out.push(ENCODE_TABLE[((sequence >> 12) & 0x3F) as usize]);
            out.extend_from_slice(b"==");
        }
        2 => {
            let sequence = (u32::from(rest[0]) << 16) | (u32::from(rest[1]) << 8);
            out.push(ENCODE_TABLE[((sequence >> 18) & 0x3F) as usize]);
            out.push(ENCODE_TABLE[((sequence >> 12) & 0x3F) as usize]);
            out.push(ENCODE_TABLE[((sequence >> 6) & 0x3F) as usize]);
            out.push(b'=');
        }
        _ => {}
    }
    out
}

/// C++ `Decode(view, output, hasWarning, warningMessage)`.
///
/// # Errors
///
/// [`Base64Error::InvalidCharacter`] for a byte outside the alphabet
/// (control characters other than `\r`/`\n`, bytes `>= 128`, ...);
/// [`Base64Error::TooMuchPadding`] for three or more `=`.
pub fn decode(input: &[u8]) -> Result<Decoded, Base64Error> {
    let mut output = Vec::with_capacity(input.len().wrapping_div(4).saturating_mul(3));
    let mut sequence: u32 = 0;
    let mut sequence_index: u32 = 0;
    let mut last_encoded: u8 = 0;
    let mut padding_count: u8 = 0;
    let mut warning = None;

    for (offset, &encoded) in input.iter().enumerate() {
        if encoded >= 128 {
            return Err(Base64Error::InvalidCharacter { offset });
        }
        if encoded == b'\r' || encoded == b'\n' {
            continue;
        }
        if last_encoded == b'=' && sequence_index == 0 {
            warning = Some(EXTRA_BYTES_WARNING);
            break;
        }
        let decoded = if encoded == b'=' {
            padding_count = padding_count.saturating_add(1);
            0
        } else {
            decode_value(encoded).ok_or(Base64Error::InvalidCharacter { offset })?
        };
        // C++: `sequence |= decoded << (2 + (4 - sequenceIndex) * 6)`
        let shift = 2_u32.saturating_add(4_u32.saturating_sub(sequence_index).saturating_mul(6));
        sequence |= decoded.checked_shl(shift).unwrap_or(0);
        sequence_index = sequence_index.saturating_add(1);
        if sequence_index.is_multiple_of(4) {
            output.push(((sequence >> 24) & 0xFF) as u8);
            output.push(((sequence >> 16) & 0xFF) as u8);
            output.push(((sequence >> 8) & 0xFF) as u8);
            sequence = 0;
            sequence_index = 0;
        }
        last_encoded = encoded;
    }

    if padding_count >= 3 {
        return Err(Base64Error::TooMuchPadding);
    }
    let keep = output.len().saturating_sub(usize::from(padding_count));
    output.truncate(keep);
    Ok(Decoded {
        data: output,
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors_roundtrip() {
        let cases: [(&[u8], &[u8]); 7] = [
            (b"", b""),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(encode(plain), encoded);
            assert_eq!(decode(encoded).unwrap().data, plain);
        }
        // Binary (high-bit) bytes roundtrip cleanly.
        let binary: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&binary)).unwrap().data, binary);
    }

    #[test]
    fn decode_skips_crlf_and_warns_on_trailing_bytes() {
        let decoded = decode(b"Zm9v\r\nYmFy\n").unwrap();
        assert_eq!(decoded.data, b"foobar");
        assert_eq!(decoded.warning, None);
        // Data after a completed padded group is ignored with the
        // C++ warning.
        let decoded = decode(b"Zg==Zm9v").unwrap();
        assert_eq!(decoded.data, b"f");
        assert_eq!(decoded.warning, Some(EXTRA_BYTES_WARNING));
    }

    #[test]
    fn decode_rejects_invalid_input() {
        assert_eq!(
            decode(b"Zm9v!"),
            Err(Base64Error::InvalidCharacter { offset: 4 })
        );
        assert_eq!(
            decode(&[0xC3, 0xA9]),
            Err(Base64Error::InvalidCharacter { offset: 0 })
        );
        assert_eq!(decode(b"Z==="), Err(Base64Error::TooMuchPadding));
        // A trailing incomplete group is dropped (C++ parity).
        assert_eq!(decode(b"Zm9vYmF").unwrap().data, b"foo");
    }
}
