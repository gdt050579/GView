//! ZIP `Validate` export (spec `06_TYPE_PLUGINS` §ZIP Validate; C++
//! `zip.cpp:33-51`).
//!
//! ```cpp
//! CHECK(buf.GetLength() >= sizeof(PK), false, "");
//! auto magic = buf.GetObject<Magic>(0);
//! CHECK(magic.IsValid(), false, "");
//! if (magic->value == PK)         return true;   // 0x04034B50 local file header
//! if (magic->value == PK_EMPTY)   return true;   // 0x06054B50 end of central directory
//! if (magic->value == PK_SPANNED) return true;   // 0x08074B50 spanned / data descriptor
//! RETURNERROR(false, "Unknown ZIP format/standard!");
//! ```
//!
//! The magic is compared as a native (little-endian) `u32`, i.e. the
//! on-disk bytes `50 4B 03 04`, `50 4B 05 06` and `50 4B 07 08` — the
//! same three `magic:` patterns `UpdateSettings` registers.

/// `PK` — local file header signature (`PK\x03\x04`).
pub const PK: u32 = 0x0403_4B50;
/// `PK_EMPTY` — end of central directory (`PK\x05\x06`, empty archive).
pub const PK_EMPTY: u32 = 0x0605_4B50;
/// `PK_SPANNED` — spanned archive / data descriptor (`PK\x07\x08`).
pub const PK_SPANNED: u32 = 0x0807_4B50;
/// The magics as on-disk byte sequences, in `UpdateSettings` order.
pub const MAGIC_BYTES: [[u8; 4]; 3] = [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06], [0x50, 0x4B, 0x07, 0x08]];
/// Minimum buffer length (`sizeof(PK)`).
pub const MIN_VALIDATE_LEN: usize = 4;

/// Little-endian `u32` at `at`, bounds-checked.
fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// Whether `magic` is one of the three accepted signatures.
#[must_use]
pub const fn is_zip_magic(magic: u32) -> bool {
    matches!(magic, PK | PK_EMPTY | PK_SPANNED)
}

/// C++ `Validate(buf, extension)`; the extension is ignored.
#[must_use]
pub fn validate(buf: &[u8], _extension: &str) -> bool {
    if buf.len() < MIN_VALIDATE_LEN {
        return false;
    }
    u32_at(buf, 0).is_some_and(is_zip_magic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_pk() {
        assert!(validate(b"PK\x03\x04", ""));
        assert!(validate(b"PK\x03\x04\x14\x00\x00\x00\x08\x00", ".zip"));
        assert!(validate(b"PK\x05\x06\x00\x00", ""), "empty archive");
        assert!(validate(b"PK\x07\x08", ""), "spanned archive");
        for bytes in MAGIC_BYTES {
            assert!(validate(&bytes, ""));
            assert!(is_zip_magic(u32::from_le_bytes(bytes)));
        }
        assert_eq!(PK.to_le_bytes(), MAGIC_BYTES[0]);
        assert_eq!(PK_EMPTY.to_le_bytes(), MAGIC_BYTES[1]);
        assert_eq!(PK_SPANNED.to_le_bytes(), MAGIC_BYTES[2]);
    }

    #[test]
    fn short_or_foreign_buffers_fail() {
        assert!(!validate(b"", ""));
        assert!(!validate(b"PK\x03", ".zip"));
        assert!(!validate(b"PK\x01\x02\x00\x00", ""), "central directory header is not accepted");
        assert!(!validate(b"PK\x04\x03", ""), "byte order matters");
        assert!(!validate(b"MZ\x90\x00", ".exe"));
        assert!(!validate(b"\x7fELF\x02", ""));
        assert!(!validate(b"\xCA\xFE\xBA\xBE\0\0\0\x02", ""));
        assert!(!is_zip_magic(0));
        assert_eq!(MIN_VALIDATE_LEN, 4);
    }
}
