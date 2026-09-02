//! PE `Validate` export and the header constants it relies on
//! (spec `06_TYPE_PLUGINS` §PE Validate; C++ `pe.cpp:17-28`,
//! `pe.hpp` `Constants`).
//!
//! C++:
//!
//! ```cpp
//! auto dos = buf.GetObject<ImageDOSHeader>();          // 64 bytes at 0
//! if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
//! auto nth32 = buf.GetObject<ImageNTHeaders32>(dos->e_lfanew); // 248 bytes
//! if (!nth32) return false;
//! return nth32->Signature == IMAGE_NT_SIGNATURE;
//! ```
//!
//! `GetObject<T>(offset)` fails when fewer than `sizeof(T)` bytes
//! remain, so a truncated probe (the host passes at most `0x8800`
//! bytes) or an `e_lfanew` past the buffer rejects the file even when
//! the `PE\0\0` signature would be there on disk — replicated. All
//! multi-byte fields are little-endian.

/// `IMAGE_DOS_SIGNATURE` (`MZ`).
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// `IMAGE_NT_SIGNATURE` (`PE\0\0`).
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
/// `__IMAGE_NT_OPTIONAL_HDR32_MAGIC`.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
/// `__IMAGE_NT_OPTIONAL_HDR64_MAGIC`.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
/// `__IMAGE_ROM_OPTIONAL_HDR_MAGIC` (unsupported by `GView`).
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;
/// `__IMAGE_NUMBEROF_DIRECTORY_ENTRIES`.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
/// `__IMAGE_SIZEOF_SHORT_NAME`.
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

/// `sizeof(ImageDOSHeader)`.
pub const IMAGE_DOS_HEADER_SIZE: usize = 64;
/// `sizeof(ImageFileHeader)`.
pub const IMAGE_FILE_HEADER_SIZE: usize = 20;
/// `sizeof(ImageOptionalHeader32)`.
pub const IMAGE_OPTIONAL_HEADER32_SIZE: usize = 224;
/// `sizeof(ImageOptionalHeader64)`.
pub const IMAGE_OPTIONAL_HEADER64_SIZE: usize = 240;
/// `sizeof(ImageNTHeaders32)` = signature + file header + optional32.
pub const IMAGE_NT_HEADERS32_SIZE: usize = 4 + IMAGE_FILE_HEADER_SIZE + IMAGE_OPTIONAL_HEADER32_SIZE;
/// `sizeof(ImageNTHeaders64)`.
pub const IMAGE_NT_HEADERS64_SIZE: usize = 4 + IMAGE_FILE_HEADER_SIZE + IMAGE_OPTIONAL_HEADER64_SIZE;
/// `sizeof(ImageSectionHeader)`.
pub const IMAGE_SECTION_HEADER_SIZE: usize = 40;
/// Offset of `e_lfanew` inside the DOS header.
pub const E_LFANEW_OFFSET: usize = 60;

/// Little-endian `u16` at `offset`, `None` when out of bounds.
#[must_use]
pub fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes = buf.get(offset..end)?;
    Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
}

/// Little-endian `u32` at `offset`, `None` when out of bounds.
#[must_use]
pub fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes = buf.get(offset..end)?;
    Some(u32::from_le_bytes([
        *bytes.first()?,
        *bytes.get(1)?,
        *bytes.get(2)?,
        *bytes.get(3)?,
    ]))
}

/// Little-endian `u64` at `offset`, `None` when out of bounds.
#[must_use]
pub fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let lo = read_u32(buf, offset)?;
    let hi = read_u32(buf, offset.checked_add(4)?)?;
    Some((u64::from(hi) << 32) | u64::from(lo))
}

/// `e_lfanew` of a buffer that holds a full DOS header with the `MZ`
/// magic, else `None`.
#[must_use]
pub fn dos_header_lfanew(buf: &[u8]) -> Option<u32> {
    if buf.len() < IMAGE_DOS_HEADER_SIZE {
        return None;
    }
    if read_u16(buf, 0)? != IMAGE_DOS_SIGNATURE {
        return None;
    }
    read_u32(buf, E_LFANEW_OFFSET)
}

/// C++ `Validate(buf, extension)`: `MZ` at 0, a complete
/// `ImageNTHeaders32` at `e_lfanew`, and `PE\0\0` there. The extension
/// is ignored, as in C++.
#[must_use]
pub fn validate(buf: &[u8], _extension: &str) -> bool {
    let Some(lfanew) = dos_header_lfanew(buf) else {
        return false;
    };
    let nt = lfanew as usize;
    // `GetObject<ImageNTHeaders32>(e_lfanew)`: the whole struct must fit.
    let Some(end) = nt.checked_add(IMAGE_NT_HEADERS32_SIZE) else {
        return false;
    };
    if end > buf.len() {
        return false;
    }
    read_u32(buf, nt) == Some(IMAGE_NT_SIGNATURE)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
pub mod tests {
    use super::*;

    /// A minimal image: DOS header with `e_lfanew`, then NT headers
    /// (signature + file header + optional header) padded to size.
    #[must_use]
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    pub fn minimal_pe(lfanew: u32, nt_magic: u16) -> Vec<u8> {
        let mut image = vec![0_u8; lfanew as usize + IMAGE_NT_HEADERS32_SIZE];
        image[0..2].copy_from_slice(&IMAGE_DOS_SIGNATURE.to_le_bytes());
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&lfanew.to_le_bytes());
        let nt = lfanew as usize;
        image[nt..nt + 4].copy_from_slice(&IMAGE_NT_SIGNATURE.to_le_bytes());
        let opt = nt + 4 + IMAGE_FILE_HEADER_SIZE;
        image[opt..opt + 2].copy_from_slice(&nt_magic.to_le_bytes());
        image
    }

    #[test]
    fn mz_at_zero_with_pe_signature_passes() {
        let image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        assert!(validate(&image, ".exe"));
        assert!(validate(&image, ""));
        // e_lfanew right after the DOS header.
        assert!(validate(&minimal_pe(64, IMAGE_NT_OPTIONAL_HDR64_MAGIC), ".dll"));
    }

    #[test]
    fn wrong_magics_fail() {
        let mut image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        image[0] = b'Z';
        image[1] = b'M';
        assert!(!validate(&image, ".exe"));
        let mut image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        image[0x80] = b'N';
        assert!(!validate(&image, ".exe"));
        // "PE" followed by non-zero bytes is not the signature.
        let mut image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        image[0x82] = 1;
        assert!(!validate(&image, ".exe"));
    }

    #[test]
    fn truncation_and_bad_lfanew_fail_like_get_object() {
        assert!(!validate(b"", ""));
        assert!(!validate(b"MZ", ""));
        assert!(!validate(&[0_u8; 63], ""));
        let image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        // NT headers not fully inside the buffer.
        assert!(!validate(&image[..image.len() - 1], ""));
        assert!(!validate(&image[..0x84], ""));
        // e_lfanew beyond the buffer / overflowing.
        let mut image = minimal_pe(0x80, IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        assert!(!validate(&image, ""));
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!validate(&image, ""));
        // e_lfanew = 0 makes the DOS header double as NT header: no PE signature.
        image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(!validate(&image, ""));
    }

    #[test]
    fn readers_are_bounds_checked() {
        let buf = [0x34_u8, 0x12, 0x78, 0x56, 0xBC, 0x9A, 0xF0, 0xDE];
        assert_eq!(read_u16(&buf, 0), Some(0x1234));
        assert_eq!(read_u32(&buf, 0), Some(0x5678_1234));
        assert_eq!(read_u64(&buf, 0), Some(0xDEF0_9ABC_5678_1234));
        assert_eq!(read_u16(&buf, 7), None);
        assert_eq!(read_u32(&buf, 5), None);
        assert_eq!(read_u64(&buf, 1), None);
        assert_eq!(read_u32(&buf, usize::MAX), None);
        assert_eq!(dos_header_lfanew(&[0; 64]), None);
    }

    #[test]
    fn struct_sizes_match_cpp() {
        assert_eq!(IMAGE_DOS_HEADER_SIZE, 64);
        assert_eq!(IMAGE_NT_HEADERS32_SIZE, 248);
        assert_eq!(IMAGE_NT_HEADERS64_SIZE, 264);
        assert_eq!(IMAGE_SECTION_HEADER_SIZE, 40);
        assert_eq!(IMAGE_DOS_SIGNATURE, 0x5A4D);
        assert_eq!(IMAGE_NT_SIGNATURE, 0x0000_4550);
        assert_eq!(IMAGE_NT_OPTIONAL_HDR32_MAGIC, 0x10B);
        assert_eq!(IMAGE_NT_OPTIONAL_HDR64_MAGIC, 0x20B);
    }
}
