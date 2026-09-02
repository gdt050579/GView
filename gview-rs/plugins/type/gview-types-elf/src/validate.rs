//! ELF `Validate` export (spec `06_TYPE_PLUGINS` §ELF Validate; C++
//! `elf.cpp:14-20`, `elf_types.hpp` `MAGIC`).
//!
//! ```cpp
//! CHECK(buf.GetLength() > sizeof(uint32), false, "");
//! auto magic = *(uint32*) buf.GetData();
//! CHECK(magic == GView::Type::ELF::MAGIC, false, "");
//! ```
//!
//! Parity quirk: the length check is **strictly greater than 4**, so a
//! buffer holding exactly the four magic bytes is rejected. The magic
//! is compared as a native (little-endian) `u32`, i.e. the bytes
//! `7F 45 4C 46` (`\x7fELF`).

/// C++ `GView::Type::ELF::MAGIC` as a little-endian `u32`.
pub const MAGIC: u32 = 0x464C_457F;
/// The magic bytes as they appear in the file.
pub const MAGIC_BYTES: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// Minimum buffer length: strictly more than the magic.
pub const MIN_VALIDATE_LEN: usize = 5;

/// C++ `Validate(buf, extension)`; the extension is ignored.
#[must_use]
pub fn validate(buf: &[u8], _extension: &str) -> bool {
    if buf.len() < MIN_VALIDATE_LEN {
        return false;
    }
    let Some(head) = buf.get(..4) else {
        return false;
    };
    let magic = u32::from_le_bytes([
        head.first().copied().unwrap_or(0),
        head.get(1).copied().unwrap_or(0),
        head.get(2).copied().unwrap_or(0),
        head.get(3).copied().unwrap_or(0),
    ]);
    magic == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_magic_passes() {
        assert!(validate(b"\x7fELF\x02\x01\x01", ""));
        assert!(validate(b"\x7fELF\x00", ".so"));
        assert_eq!(MAGIC.to_le_bytes(), MAGIC_BYTES);
    }

    #[test]
    fn exactly_four_bytes_is_rejected_like_cpp() {
        assert!(!validate(b"\x7fELF", ""));
        assert!(!validate(b"", ""));
        assert!(!validate(b"\x7fEL", ""));
    }

    #[test]
    fn wrong_magic_fails() {
        assert!(!validate(b"ELF\x7f\x00", ""));
        assert!(!validate(b"MZ\x90\x00\x00", ".exe"));
        assert!(!validate(b"\x7fELG\x00", ""));
    }
}
