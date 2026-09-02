//! PCAP `Validate` export (spec `06_TYPE_PLUGINS` §PCAP Validate; C++
//! `PCAP.cpp:35-44`, `Internal.hpp` `Magic` / `Header`).
//!
//! ```cpp
//! CHECK(buf.GetLength() > sizeof(PCAP::Header), false, "");   // 24 bytes, strictly greater
//! auto header = buf.GetObject<PCAP::Header>(0);
//! CHECK(header.IsValid(), false, "");
//! CHECK(header->magicNumber == Magic::Identical || header->magicNumber == Magic::Swapped, false, "");
//! ```
//!
//! Parity quirk: the length check is **strictly greater than 24**, so a
//! buffer holding exactly the global header (a capture with no packets)
//! is rejected. The magic is read as a native (little-endian) `u32`:
//! `Identical` (`0xA1B2C3D4`) is the on-disk bytes `D4 C3 B2 A1`, and
//! `Swapped` (`0xD4C3B2A1`) the bytes `A1 B2 C3 D4` — the two `magic:`
//! patterns `UpdateSettings` registers.

/// `Magic::Identical` — fields are in the host byte order.
pub const MAGIC_IDENTICAL: u32 = 0xA1B2_C3D4;
/// `Magic::Swapped` — every following field must be byte-swapped.
pub const MAGIC_SWAPPED: u32 = 0xD4C3_B2A1;
/// `sizeof(PCAP::Header)`.
pub const HEADER_SIZE: usize = 24;
/// Minimum buffer length: strictly more than the global header.
pub const MIN_VALIDATE_LEN: usize = 25;

/// Little-endian `u32` at `at`, bounds-checked.
fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    let b = buf.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?]))
}

/// Whether `magic` is one of the two accepted values.
#[must_use]
pub const fn is_pcap_magic(magic: u32) -> bool {
    matches!(magic, MAGIC_IDENTICAL | MAGIC_SWAPPED)
}

/// C++ `Validate(buf, extension)`; the extension is ignored.
#[must_use]
pub fn validate(buf: &[u8], _extension: &str) -> bool {
    if buf.len() < MIN_VALIDATE_LEN {
        return false;
    }
    u32_at(buf, 0).is_some_and(is_pcap_magic)
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn header(magic_bytes: [u8; 4], extra: usize) -> Vec<u8> {
        let mut h = vec![0_u8; HEADER_SIZE + extra];
        h[..4].copy_from_slice(&magic_bytes);
        h
    }

    #[test]
    fn pcap_header() {
        // Little-endian capture on disk: D4 C3 B2 A1 reads as Identical.
        assert!(validate(&header([0xD4, 0xC3, 0xB2, 0xA1], 16), ".pcap"));
        // Big-endian capture on disk: A1 B2 C3 D4 reads as Swapped.
        assert!(validate(&header([0xA1, 0xB2, 0xC3, 0xD4], 1), ""));
        assert!(is_pcap_magic(MAGIC_IDENTICAL));
        assert!(is_pcap_magic(MAGIC_SWAPPED));
        assert_eq!(MAGIC_IDENTICAL.to_le_bytes(), [0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(MAGIC_SWAPPED.to_le_bytes(), [0xA1, 0xB2, 0xC3, 0xD4]);
    }

    #[test]
    fn exactly_the_header_is_rejected_like_cpp() {
        assert!(!validate(&header([0xD4, 0xC3, 0xB2, 0xA1], 0), ""));
        assert!(!validate(&header([0xD4, 0xC3, 0xB2, 0xA1], 0)[..10], ""));
        assert!(!validate(b"", ""));
        assert_eq!(MIN_VALIDATE_LEN, 25);
    }

    #[test]
    fn foreign_magics_fail() {
        // Nanosecond pcap (0xA1B23C4D) and pcapng are not accepted.
        assert!(!validate(&header([0x4D, 0x3C, 0xB2, 0xA1], 8), ""));
        assert!(!validate(&header([0x0A, 0x0D, 0x0D, 0x0A], 8), ".pcapng"));
        assert!(!validate(&header([0xA1, 0xB2, 0xC3, 0xD5], 8), ""));
        let mut mz = vec![0_u8; 32];
        mz[..2].copy_from_slice(b"MZ");
        assert!(!validate(&mz, ".exe"));
        assert!(!is_pcap_magic(0));
    }
}
