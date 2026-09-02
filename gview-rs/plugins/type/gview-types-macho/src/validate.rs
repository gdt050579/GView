//! Mach-O `Validate` export (spec `06_TYPE_PLUGINS` §Mach-O Validate;
//! C++ `MachO.cpp:33-51`, `Mac.hpp` magic constants).
//!
//! ```cpp
//! auto dword = buf.GetObject<uint32>();
//! CHECK(dword != nullptr, false, "");
//! const uint32 magic = dword;
//! const bool isMacho = magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
//! const bool isFat   = magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
//! CHECK(isMacho || isFat, false, "Magic is [%u]!", magic);
//! if (isFat) {
//!     auto fh = *reinterpret_cast<const fat_header*>(buf.GetData());
//!     if (magic == FAT_CIGAM || magic == FAT_CIGAM_64) Swap(fh);
//!     CHECK(fh.nfat_arch < 0x2D, false, "This is probably a JAR class file!");
//! }
//! return true;
//! ```
//!
//! The magic is read as a native (little-endian) `u32`, so an on-disk
//! big-endian `CA FE BA BE` arrives as [`FAT_CIGAM`] and is swapped
//! before the architecture count is checked. The `nfat_arch < 0x2D`
//! guard rejects Java class files, which share the `CAFEBABE` magic and
//! carry a `major_version >= 45` (`0x2D`) in the same four bytes.
//!
//! Discrepancy: the C++ dereferences the 8-byte `fat_header` with only
//! the 4-byte magic checked; here a fat magic on a buffer shorter than
//! [`FAT_HEADER_SIZE`] is rejected instead of reading past the end.

/// `MH_MAGIC` — 32-bit Mach-O, native byte order.
pub const MH_MAGIC: u32 = 0xFEED_FACE;
/// `MH_CIGAM` — `MH_MAGIC` byte-swapped.
pub const MH_CIGAM: u32 = 0xCEFA_EDFE;
/// `MH_MAGIC_64` — 64-bit Mach-O, native byte order.
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;
/// `MH_CIGAM_64` — `MH_MAGIC_64` byte-swapped.
pub const MH_CIGAM_64: u32 = 0xCFFA_EDFE;
/// `FAT_MAGIC` — fat / universal binary, native byte order.
pub const FAT_MAGIC: u32 = 0xCAFE_BABE;
/// `FAT_CIGAM` — `FAT_MAGIC` byte-swapped (what a real fat file reads
/// as on a little-endian host).
pub const FAT_CIGAM: u32 = 0xBEBA_FECA;
/// `FAT_MAGIC_64` — 64-bit fat header.
pub const FAT_MAGIC_64: u32 = 0xCAFE_BABF;
/// `FAT_CIGAM_64` — `FAT_MAGIC_64` byte-swapped.
pub const FAT_CIGAM_64: u32 = 0xBFBA_FECA;
/// `sizeof(fat_header)`: `magic` + `nfat_arch`.
pub const FAT_HEADER_SIZE: usize = 8;
/// `nfat_arch` values at or above this are "probably a JAR class file".
pub const MAX_FAT_ARCH_EXCLUSIVE: u32 = 0x2D;

/// Little-endian `u32` at `at`, bounds-checked.
fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// `isMacho`: one of the four thin magics.
#[must_use]
pub const fn is_macho_magic(magic: u32) -> bool {
    matches!(magic, MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64)
}

/// `isFat`: one of the four fat magics.
#[must_use]
pub const fn is_fat_magic(magic: u32) -> bool {
    matches!(magic, FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64)
}

/// Whether the fat header must be byte-swapped (`FAT_CIGAM` family).
#[must_use]
pub const fn fat_needs_swap(magic: u32) -> bool {
    matches!(magic, FAT_CIGAM | FAT_CIGAM_64)
}

/// `fat_header.nfat_arch` as the C++ sees it after the optional `Swap`;
/// `None` when the magic is not fat or the header is truncated.
#[must_use]
pub fn fat_arch_count(buf: &[u8]) -> Option<u32> {
    let magic = u32_at(buf, 0)?;
    if !is_fat_magic(magic) {
        return None;
    }
    let raw = u32_at(buf, 4)?;
    Some(if fat_needs_swap(magic) { raw.swap_bytes() } else { raw })
}

/// C++ `Validate(buf, extension)`; the extension is ignored.
#[must_use]
pub fn validate(buf: &[u8], _extension: &str) -> bool {
    let Some(magic) = u32_at(buf, 0) else {
        return false;
    };
    if is_macho_magic(magic) {
        return true;
    }
    if !is_fat_magic(magic) {
        return false;
    }
    fat_arch_count(buf).is_some_and(|nfat_arch| nfat_arch < MAX_FAT_ARCH_EXCLUSIVE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macho_fat() {
        // On-disk big-endian fat header: CA FE BA BE, nfat_arch = 2.
        assert!(validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x02", ""));
        assert_eq!(u32_at(b"\xCA\xFE\xBA\xBE", 0), Some(FAT_CIGAM));
        assert_eq!(fat_arch_count(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x02"), Some(2));
        // FAT_MAGIC_64 on disk.
        assert!(validate(b"\xCA\xFE\xBA\xBF\x00\x00\x00\x03\x00", ""));
        // Native-order fat magic (bytes BE BA FE CA) with LE nfat_arch.
        assert!(validate(&[0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0, 0, 0], ""));
        assert_eq!(fat_arch_count(&[0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0, 0, 0]), Some(2));
        assert!(validate(&[0xBF, 0xBA, 0xFE, 0xCA, 0x2C, 0, 0, 0], ""));
        // Zero architectures still passes (only the upper bound is checked).
        assert!(validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x00", ""));
        assert!(validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x2C", ""));
    }

    #[test]
    fn java_class_files_are_rejected() {
        // CAFEBABE, minor 0, major 0x34 (Java 8): nfat_arch = 0x34 >= 0x2D.
        assert!(!validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x34", ".class"));
        assert!(!validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x2D", ""));
        // Java 1.0 (major 45 = 0x2D) is the boundary — also rejected.
        assert_eq!(fat_arch_count(b"\xCA\xFE\xBA\xBE\x00\x00\x00\x2D"), Some(0x2D));
        // A non-zero minor version lands in the high bytes after the swap.
        assert!(!validate(b"\xCA\xFE\xBA\xBE\x00\x03\x00\x2D", ""));
        // Native-order fat with a huge count.
        assert!(!validate(&[0xBE, 0xBA, 0xFE, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF], ""));
    }

    #[test]
    fn thin_magics_pass_in_both_byte_orders() {
        // MH_MAGIC_64 as a little-endian host reads a native x86_64 file.
        assert!(validate(&[0xCF, 0xFA, 0xED, 0xFE], ""));
        // MH_CIGAM_64 (big-endian on disk).
        assert!(validate(&[0xFE, 0xED, 0xFA, 0xCF], ""));
        assert!(validate(&[0xCE, 0xFA, 0xED, 0xFE], ".dylib"));
        assert!(validate(&[0xFE, 0xED, 0xFA, 0xCE], ""));
        // Longer buffers are fine; only the first dword matters.
        assert!(validate(&[0xCF, 0xFA, 0xED, 0xFE, 0x07, 0, 0, 1, 0xFF], ""));
        for magic in [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64] {
            assert!(is_macho_magic(magic));
            assert!(!is_fat_magic(magic));
            assert!(validate(&magic.to_le_bytes(), ""));
        }
        for magic in [FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64] {
            assert!(is_fat_magic(magic));
            assert!(!is_macho_magic(magic));
        }
        assert!(fat_needs_swap(FAT_CIGAM));
        assert!(fat_needs_swap(FAT_CIGAM_64));
        assert!(!fat_needs_swap(FAT_MAGIC));
        assert!(!fat_needs_swap(FAT_MAGIC_64));
    }

    #[test]
    fn short_or_foreign_buffers_fail() {
        assert!(!validate(b"", ""));
        assert!(!validate(&[0xCF, 0xFA, 0xED], ""));
        // Fat magic without the architecture count: rejected (the C++
        // would read past the buffer).
        assert!(!validate(b"\xCA\xFE\xBA\xBE", ""));
        assert!(!validate(b"\xCA\xFE\xBA\xBE\x00\x00\x00", ""));
        assert_eq!(fat_arch_count(b"\xCA\xFE\xBA\xBE"), None);
        assert_eq!(fat_arch_count(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]), None);
        // Other formats.
        assert!(!validate(b"MZ\x90\x00\x03\x00\x00\x00", ".exe"));
        assert!(!validate(b"\x7fELF\x02\x01\x01\x00", ""));
        assert!(!validate(b"PK\x03\x04\x14\x00\x00\x00", ".zip"));
        assert!(!validate(&[0xCE, 0xFA, 0xED, 0xFF], ""));
        assert_eq!(MAX_FAT_ARCH_EXCLUSIVE, 45);
        assert_eq!(FAT_HEADER_SIZE, 8);
    }
}
