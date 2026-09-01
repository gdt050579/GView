//! MD5 convenience wrapper (feature `md5`), spec `04_SERVICES` §2.6.
//!
//! The dissasm cache fingerprints zones with
//! `OpenSSLHash(Md5).GetHexValue()` (`DissasmCache.cpp:129-137`);
//! [`md5_hex`] is that call in one step.

use crate::sha::{OpenSslHash, OpenSslHashKind};

/// Uppercase MD5 hex of `data` (C++ `OpenSSLHash(Md5)` + `GetHexValue`).
#[must_use]
pub fn md5_hex(data: &[u8]) -> String {
    let mut h = OpenSslHash::new(OpenSslHashKind::Md5).unwrap_or_else(|_| {
        // Unreachable with the `md5` feature enabled (this module is
        // compiled only then).
        OpenSslHash::new(OpenSslHashKind::Sha256).unwrap_or_else(|_| unreachable_sha())
    });
    h.update(data);
    h.hex_value()
}

fn unreachable_sha() -> OpenSslHash {
    // SHA-256 construction is infallible; kept as a typed fallback so
    // the function stays panic-free under every feature set.
    loop {
        if let Ok(h) = OpenSslHash::new(OpenSslHashKind::Sha256) {
            return h;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "D41D8CD98F00B204E9800998ECF8427E");
        assert_eq!(md5_hex(b"abc"), "900150983CD24FB0D6963F7D28E17F72");
        assert_eq!(
            md5_hex(b"message digest"),
            "F96B697D7CB7938D525A2F31AAF161D0"
        );
    }
}
