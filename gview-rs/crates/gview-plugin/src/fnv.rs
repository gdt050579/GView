//! Extension hash — FNV-1a 64 (spec `03_DUAL_PLUGIN` §7.2;
//! C++ `Type/Plugin.cpp:7-29` `Plugin::ExtensionToHash`).
//!
//! Type plugins declare extensions in their INI section; the host
//! hashes both those and the opened file's extension so that matching
//! is a `u64` compare (`Plugin::MatchExtension`). The C++ quirks are
//! part of the contract:
//!
//! - an **empty** extension hashes to `0`, not to the FNV offset basis
//!   ([`EXTENSION_EMPTY_HASH`]), so it never matches a plugin;
//! - exactly one leading `.` is skipped (`..exe` keeps one dot);
//! - `A`–`Z` are lower-cased **per byte** (`c |= 0x20`); no other
//!   folding, so `.exe`, `.EXE` and `exe` hash alike while `é` does
//!   not fold;
//! - the UTF-16 overload ([`extension_hash_utf16`]) hashes only the
//!   low byte of every unit (`(*s) & 0xFF`).
//!
//! A plugin without an `Extension` key keeps
//! [`EXTENSION_EMPTY_HASH`] as its single hash and matches nothing
//! by extension (`MatchExtension` returns `false`).

/// FNV-1a 64 offset basis (C++ `EXTENSION_EMPTY_HASH`).
pub const EXTENSION_EMPTY_HASH: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64 prime.
pub const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

/// One FNV-1a step with the C++ per-byte lower-casing.
const fn step(hash: u64, byte: u8) -> u64 {
    let c = if byte >= b'A' && byte <= b'Z' { byte | 0x20 } else { byte };
    (hash ^ c as u64).wrapping_mul(FNV_PRIME)
}

/// C++ `ExtensionToHash(std::string_view)`.
#[must_use]
pub fn extension_hash(ext: &str) -> u64 {
    extension_hash_bytes(ext.as_bytes())
}

/// Byte-slice form of [`extension_hash`].
#[must_use]
pub fn extension_hash_bytes(ext: &[u8]) -> u64 {
    if ext.is_empty() {
        return 0;
    }
    let body = ext.strip_prefix(b".").unwrap_or(ext);
    body.iter().fold(EXTENSION_EMPTY_HASH, |hash, &b| step(hash, b))
}

/// C++ `ExtensionToHash(std::u16string_view)`: same algorithm over the
/// low byte of each UTF-16 unit.
#[must_use]
pub fn extension_hash_utf16(ext: &[u16]) -> u64 {
    if ext.is_empty() {
        return 0;
    }
    let body = ext.strip_prefix(&[u16::from(b'.')]).unwrap_or(ext);
    body.iter().fold(EXTENSION_EMPTY_HASH, |hash, &u| step(hash, (u & 0xFF) as u8))
}

/// Extension of a file name (text after the last `.`), the way the
/// host derives it before hashing (`Instance::IdentifyTypePlugin`
/// `find_last_of('.')`). `None` when there is no dot.
#[must_use]
pub fn extension_of(name: &str) -> Option<&str> {
    name.rfind('.').and_then(|pos| name.get(pos..))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference FNV-1a over already-lower-cased ASCII.
    fn reference(s: &str) -> u64 {
        s.bytes()
            .fold(EXTENSION_EMPTY_HASH, |h, b| (h ^ u64::from(b)).wrapping_mul(FNV_PRIME))
    }

    #[test]
    fn dot_and_case_variants_share_one_hash() {
        let h = extension_hash("exe");
        assert_eq!(extension_hash(".exe"), h);
        assert_eq!(extension_hash(".EXE"), h);
        assert_eq!(extension_hash("ExE"), h);
        assert_eq!(h, reference("exe"));
        assert_ne!(h, 0);
        assert_ne!(h, EXTENSION_EMPTY_HASH);
    }

    #[test]
    fn golden_hashes_match_cpp_algorithm() {
        // Computed with the C++ loop: basis ^ byte, * prime, per byte.
        assert_eq!(extension_hash("a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(extension_hash(".A"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(extension_hash("exe"), reference("exe"));
        assert_eq!(extension_hash("DLL"), reference("dll"));
        assert_eq!(extension_hash("tar.gz"), reference("tar.gz"));
    }

    #[test]
    fn empty_returns_zero_and_only_one_dot_is_skipped() {
        assert_eq!(extension_hash(""), 0);
        assert_eq!(extension_hash_bytes(b""), 0);
        assert_eq!(extension_hash_utf16(&[]), 0);
        // A lone dot hashes the empty body: the offset basis itself.
        assert_eq!(extension_hash("."), EXTENSION_EMPTY_HASH);
        assert_eq!(extension_hash("..exe"), reference(".exe"));
        assert_ne!(extension_hash("..exe"), extension_hash("exe"));
    }

    #[test]
    fn lower_casing_is_ascii_only_and_per_byte() {
        assert_eq!(extension_hash("Ä"), reference("Ä"));
        assert_ne!(extension_hash("Ä"), extension_hash("ä"));
        // Bytes above 'Z' with bit 0x20 already set are untouched.
        assert_eq!(extension_hash("[]"), reference("[]"));
        assert_ne!(extension_hash("[]"), extension_hash("{}"));
    }

    #[test]
    fn utf16_overload_hashes_low_bytes() {
        let ascii: Vec<u16> = ".EXE".encode_utf16().collect();
        assert_eq!(extension_hash_utf16(&ascii), extension_hash(".exe"));
        // Only the low byte counts: U+0165 ('ť') hashes like 'e' (0x65).
        assert_eq!(extension_hash_utf16(&[0x0165]), extension_hash("e"));
        assert_eq!(extension_hash_utf16(&[u16::from(b'.')]), EXTENSION_EMPTY_HASH);
    }

    #[test]
    fn extension_of_takes_the_last_dot() {
        assert_eq!(extension_of("a.tar.gz"), Some(".gz"));
        assert_eq!(extension_of("noext"), None);
        assert_eq!(extension_of("trailing."), Some("."));
        assert_eq!(extension_of(".hidden"), Some(".hidden"));
    }
}
