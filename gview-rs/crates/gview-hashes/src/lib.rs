//! `GView` streaming hash calculators (spec `04_SERVICES` §2).
//!
//! Port of `GViewCore/src/Hashes/`: the table-driven CRC family and
//! Adler-32 ([`crc`]) and the OpenSSL EVP digest set ([`sha`], with
//! MD5 behind the `md5` feature in [`md5`]). Every hasher follows the
//! C++ `Init → Update* → Final / GetHexValue` protocol; hex digests
//! are **uppercase** like the C++ `%.2X` / `%.8X` formatting.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod crc;
#[cfg(feature = "md5")]
pub mod md5;
pub mod sha;

/// Common streaming surface (spec §2.5 `Hasher`).
pub trait Hasher {
    /// Feeds more input (C++ `Update`).
    fn update(&mut self, data: &[u8]);
    /// Produces the digest bytes (big-endian for the integer CRCs).
    fn finalize(&mut self) -> Vec<u8>;
    /// Uppercase hex digest (C++ `GetHexValue`).
    fn hex_digest(&mut self) -> String;
}

/// Uppercase hex of `bytes` (C++ `"%.2X"` per byte).
#[must_use]
pub fn to_upper_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0F)]));
    }
    out
}
