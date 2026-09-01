//! OpenSSL EVP digest set (spec `04_SERVICES` §2.2, §2.2.1).
//!
//! C++ anchor: `OpenSSLHash` (`OpenSSL.cpp`, `GView.hpp:451-470`).
//!
//! `OpenSSLHash` wraps `EVP_DigestInit/Update/Final` for the
//! `OpenSSLHashKind` set; `Final` runs once (guarded by `size != 0`)
//! and `GetHexValue` prints `%.2X` per byte (uppercase). The SHAKE
//! kinds use OpenSSL's default XOF lengths (16 bytes for SHAKE128,
//! 32 for SHAKE256). MD5 is available only with the `md5` feature —
//! constructing it otherwise returns [`DigestError::Md5Disabled`].

use digest::{Digest, ExtendableOutput, Update, XofReader};

use crate::{to_upper_hex, Hasher};

/// C++ `OpenSSLHashKind` (`GView.hpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpenSslHashKind {
    /// MD5 (feature `md5`).
    Md5,
    /// BLAKE2s-256.
    Blake2s256,
    /// BLAKE2b-512.
    Blake2b512,
    /// SHA-1.
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA-512/224.
    Sha512_224,
    /// SHA-512/256.
    Sha512_256,
    /// SHA3-224.
    Sha3_224,
    /// SHA3-256.
    Sha3_256,
    /// SHA3-384.
    Sha3_384,
    /// SHA3-512.
    Sha3_512,
    /// SHAKE128 (16-byte default output).
    Shake128,
    /// SHAKE256 (32-byte default output).
    Shake256,
}

impl OpenSslHashKind {
    /// Digest length in bytes (OpenSSL `EVP_MD_size`, XOF defaults).
    #[must_use]
    pub const fn digest_size(self) -> usize {
        match self {
            Self::Md5 | Self::Shake128 => 16,
            Self::Sha1 => 20,
            Self::Sha224 | Self::Sha512_224 | Self::Sha3_224 => 28,
            Self::Blake2s256
            | Self::Sha256
            | Self::Sha512_256
            | Self::Sha3_256
            | Self::Shake256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Blake2b512 | Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// Digest construction errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestError {
    /// MD5 requested without the `md5` feature.
    Md5Disabled,
}

impl core::fmt::Display for DigestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Md5Disabled => write!(f, "MD5 support is disabled (feature `md5`)"),
        }
    }
}

impl std::error::Error for DigestError {}

enum Inner {
    #[cfg(feature = "md5")]
    Md5(md5::Md5),
    Blake2s256(blake2::Blake2s256),
    Blake2b512(blake2::Blake2b512),
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha512_224(sha2::Sha512_224),
    Sha512_256(sha2::Sha512_256),
    Sha3_224(sha3::Sha3_224),
    Sha3_256(sha3::Sha3_256),
    Sha3_384(sha3::Sha3_384),
    Sha3_512(sha3::Sha3_512),
    Shake128(sha3::Shake128),
    Shake256(sha3::Shake256),
    /// Already finalized (C++ `size != 0`): further updates are
    /// ignored.
    Done,
}

/// C++ `OpenSSLHash`.
pub struct OpenSslHash {
    kind: OpenSslHashKind,
    inner: Inner,
    /// Digest bytes once `Final` ran (C++ `hash[64]` + `size`).
    hash: Vec<u8>,
}

impl OpenSslHash {
    /// C++ ctor: `EVP_DigestInit_ex` for `kind`.
    ///
    /// # Errors
    ///
    /// [`DigestError::Md5Disabled`] when MD5 is requested without the
    /// `md5` feature.
    pub fn new(kind: OpenSslHashKind) -> Result<Self, DigestError> {
        let inner = match kind {
            #[cfg(feature = "md5")]
            OpenSslHashKind::Md5 => Inner::Md5(md5::Md5::new()),
            #[cfg(not(feature = "md5"))]
            OpenSslHashKind::Md5 => return Err(DigestError::Md5Disabled),
            OpenSslHashKind::Blake2s256 => Inner::Blake2s256(blake2::Blake2s256::new()),
            OpenSslHashKind::Blake2b512 => Inner::Blake2b512(blake2::Blake2b512::new()),
            OpenSslHashKind::Sha1 => Inner::Sha1(sha1::Sha1::new()),
            OpenSslHashKind::Sha224 => Inner::Sha224(sha2::Sha224::new()),
            OpenSslHashKind::Sha256 => Inner::Sha256(sha2::Sha256::new()),
            OpenSslHashKind::Sha384 => Inner::Sha384(sha2::Sha384::new()),
            OpenSslHashKind::Sha512 => Inner::Sha512(sha2::Sha512::new()),
            OpenSslHashKind::Sha512_224 => Inner::Sha512_224(sha2::Sha512_224::new()),
            OpenSslHashKind::Sha512_256 => Inner::Sha512_256(sha2::Sha512_256::new()),
            OpenSslHashKind::Sha3_224 => Inner::Sha3_224(sha3::Sha3_224::new()),
            OpenSslHashKind::Sha3_256 => Inner::Sha3_256(sha3::Sha3_256::new()),
            OpenSslHashKind::Sha3_384 => Inner::Sha3_384(sha3::Sha3_384::new()),
            OpenSslHashKind::Sha3_512 => Inner::Sha3_512(sha3::Sha3_512::new()),
            OpenSslHashKind::Shake128 => Inner::Shake128(sha3::Shake128::default()),
            OpenSslHashKind::Shake256 => Inner::Shake256(sha3::Shake256::default()),
        };
        Ok(Self {
            kind,
            inner,
            hash: Vec::new(),
        })
    }

    /// The configured kind.
    #[must_use]
    pub const fn kind(&self) -> OpenSslHashKind {
        self.kind
    }

    /// C++ `Update` — ignored after `Final` (OpenSSL would fail the
    /// call; the C++ return value is unchecked by callers).
    pub fn update(&mut self, input: &[u8]) {
        match &mut self.inner {
            #[cfg(feature = "md5")]
            Inner::Md5(h) => Digest::update(h, input),
            Inner::Blake2s256(h) => Digest::update(h, input),
            Inner::Blake2b512(h) => Digest::update(h, input),
            Inner::Sha1(h) => Digest::update(h, input),
            Inner::Sha224(h) => Digest::update(h, input),
            Inner::Sha256(h) => Digest::update(h, input),
            Inner::Sha384(h) => Digest::update(h, input),
            Inner::Sha512(h) => Digest::update(h, input),
            Inner::Sha512_224(h) => Digest::update(h, input),
            Inner::Sha512_256(h) => Digest::update(h, input),
            Inner::Sha3_224(h) => Digest::update(h, input),
            Inner::Sha3_256(h) => Digest::update(h, input),
            Inner::Sha3_384(h) => Digest::update(h, input),
            Inner::Sha3_512(h) => Digest::update(h, input),
            Inner::Shake128(h) => Update::update(h, input),
            Inner::Shake256(h) => Update::update(h, input),
            Inner::Done => {}
        }
    }

    /// C++ `Final`: computes the digest once (idempotent).
    pub fn finalize(&mut self) -> &[u8] {
        if !self.hash.is_empty() {
            return &self.hash;
        }
        let inner = std::mem::replace(&mut self.inner, Inner::Done);
        let size = self.kind.digest_size();
        self.hash = match inner {
            #[cfg(feature = "md5")]
            Inner::Md5(h) => h.finalize().to_vec(),
            Inner::Blake2s256(h) => h.finalize().to_vec(),
            Inner::Blake2b512(h) => h.finalize().to_vec(),
            Inner::Sha1(h) => h.finalize().to_vec(),
            Inner::Sha224(h) => h.finalize().to_vec(),
            Inner::Sha256(h) => h.finalize().to_vec(),
            Inner::Sha384(h) => h.finalize().to_vec(),
            Inner::Sha512(h) => h.finalize().to_vec(),
            Inner::Sha512_224(h) => h.finalize().to_vec(),
            Inner::Sha512_256(h) => h.finalize().to_vec(),
            Inner::Sha3_224(h) => h.finalize().to_vec(),
            Inner::Sha3_256(h) => h.finalize().to_vec(),
            Inner::Sha3_384(h) => h.finalize().to_vec(),
            Inner::Sha3_512(h) => h.finalize().to_vec(),
            Inner::Shake128(h) => {
                let mut out = vec![0_u8; size];
                h.finalize_xof().read(&mut out);
                out
            }
            Inner::Shake256(h) => {
                let mut out = vec![0_u8; size];
                h.finalize_xof().read(&mut out);
                out
            }
            Inner::Done => Vec::new(),
        };
        &self.hash
    }

    /// C++ `GetHexValue`: finalizes and formats `%.2X` per byte.
    pub fn hex_value(&mut self) -> String {
        let bytes = self.finalize();
        to_upper_hex(bytes)
    }

    /// C++ `Get()` — the digest bytes (empty before `Final`).
    #[must_use]
    pub fn get(&self) -> &[u8] {
        &self.hash
    }

    /// C++ `GetSize()` — digest length after `Final` (0 before).
    #[must_use]
    pub const fn size(&self) -> usize {
        self.hash.len()
    }
}

impl Hasher for OpenSslHash {
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(&mut self) -> Vec<u8> {
        Self::finalize(self).to_vec()
    }
    fn hex_digest(&mut self) -> String {
        self.hex_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(kind: OpenSslHashKind, data: &[u8]) -> String {
        let mut h = OpenSslHash::new(kind).expect("kind available");
        h.update(data);
        h.hex_value()
    }

    #[test]
    fn sha256_nist_vectors_streaming() {
        assert_eq!(
            digest(OpenSslHashKind::Sha256, b"abc"),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(
            digest(OpenSslHashKind::Sha256, b""),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
        // Streaming update/finalize: two updates equal one.
        let mut h = OpenSslHash::new(OpenSslHashKind::Sha256).unwrap();
        h.update(b"abcdbcdecdefdefgefghfghighijhi");
        h.update(b"jkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            h.hex_value(),
            "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
        );
        // Final is idempotent; size/get reflect the digest.
        assert_eq!(h.size(), 32);
        assert_eq!(h.finalize().len(), 32);
        h.update(b"ignored after final");
        assert_eq!(h.size(), 32);
    }

    #[test]
    fn other_kinds_known_answers() {
        assert_eq!(
            digest(OpenSslHashKind::Sha1, b"abc"),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
        assert_eq!(
            digest(OpenSslHashKind::Sha224, b"abc"),
            "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
        );
        assert_eq!(
            digest(OpenSslHashKind::Sha3_256, b"abc"),
            "3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"
        );
        assert_eq!(
            digest(OpenSslHashKind::Sha512_256, b"abc"),
            "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23"
        );
        // SHAKE128 default 16-byte output of "" (OpenSSL EVP default).
        assert_eq!(
            digest(OpenSslHashKind::Shake128, b""),
            "7F9C2BA4E88F827D616045507605853E"
        );
        assert_eq!(
            digest(OpenSslHashKind::Shake256, b"").len(),
            64
        );
        assert_eq!(digest(OpenSslHashKind::Blake2s256, b"abc").len(), 64);
        assert_eq!(digest(OpenSslHashKind::Blake2b512, b"abc").len(), 128);
        for kind in [
            OpenSslHashKind::Sha384,
            OpenSslHashKind::Sha512,
            OpenSslHashKind::Sha512_224,
            OpenSslHashKind::Sha3_224,
            OpenSslHashKind::Sha3_384,
            OpenSslHashKind::Sha3_512,
        ] {
            assert_eq!(digest(kind, b"x").len(), kind.digest_size() * 2);
        }
    }

    #[cfg(feature = "md5")]
    #[test]
    fn md5_known_answer() {
        assert_eq!(
            digest(OpenSslHashKind::Md5, b""),
            "D41D8CD98F00B204E9800998ECF8427E"
        );
    }

    #[cfg(not(feature = "md5"))]
    #[test]
    fn md5_disabled_without_feature() {
        assert!(matches!(
            OpenSslHash::new(OpenSslHashKind::Md5),
            Err(DigestError::Md5Disabled)
        ));
    }
}
