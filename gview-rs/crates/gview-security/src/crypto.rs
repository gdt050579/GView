//! Crypto primitives (spec `04_SERVICES` §7.4; C++
//! `Security/CryptoGView.cpp`, `Security::Crypto::Internal`).
//!
//! | C++ | Rust |
//! |-----|------|
//! | `EncryptAES256GCM` / `DecryptAES256GCM` | [`encrypt_aes256_gcm`] / [`decrypt_aes256_gcm`] — AES-256-GCM, 12-byte IV, 16-byte tag, optional AAD |
//! | `ComputeSHA256` / `ComputeFileSHA256` | [`compute_sha256`] / [`compute_file_sha256`] — 8 KiB file chunks |
//! | `DeriveKeyHKDF` | [`derive_key_hkdf`] — HKDF-SHA256, `1..=255 * 32` output bytes |
//! | `GenerateRandomBytes` | [`generate_random_bytes`] — OS CSPRNG |
//! | `SecureErase` | [`secure_erase`] — `zeroize` |
//!
//! Input validation mirrors the C++ `GStatus::Error` checks (key must
//! be 32 bytes, plaintext / ciphertext non-empty, IV 12 and tag 16
//! bytes, non-empty IKM, bounded HKDF length, non-zero random length);
//! [`CryptoError`]'s `Display` reproduces those messages. Secrets
//! (derived keys, decrypted plaintext, random bytes) are returned in
//! [`Zeroizing`] buffers so they are wiped on drop; a failed
//! decryption never leaks partial plaintext (the C++ clears the output
//! on failure).

use std::io::Read;
use std::path::Path;

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// AES-256 key length (C++ `AES_256_KEY_SIZE`).
pub const AES_256_KEY_SIZE: usize = 32;
/// GCM IV length (C++ `AES_GCM_IV_SIZE`).
pub const AES_GCM_IV_SIZE: usize = 12;
/// GCM authentication-tag length (C++ `AES_GCM_TAG_SIZE`).
pub const AES_GCM_TAG_SIZE: usize = 16;
/// SHA-256 digest length (OpenSSL `SHA256_DIGEST_LENGTH`).
pub const SHA256_DIGEST_LENGTH: usize = 32;
/// File hashing read size (C++ `char buffer[8192]`).
pub const FILE_HASH_CHUNK_SIZE: usize = 8192;
/// Largest HKDF output (`255 * SHA256_DIGEST_LENGTH`, RFC 5869).
pub const HKDF_MAX_OUTPUT_LENGTH: usize = 255 * SHA256_DIGEST_LENGTH;

/// C++ `Security::Crypto::EncryptedBlob`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EncryptedBlob {
    /// 12-byte GCM nonce.
    pub iv: Vec<u8>,
    /// Ciphertext (same length as the plaintext).
    pub ciphertext: Vec<u8>,
    /// 16-byte authentication tag.
    pub tag: Vec<u8>,
    /// Additional authenticated data bound to the ciphertext
    /// (optional; empty when unused).
    pub aad: Vec<u8>,
}

/// Failures; `Display` reproduces the C++ `GStatus` messages.
#[derive(Debug)]
pub enum CryptoError {
    /// Key is not 32 bytes.
    InvalidKeySize {
        /// Provided length.
        size: usize,
    },
    /// Empty plaintext.
    EmptyPlaintext,
    /// IV is not 12 bytes.
    InvalidIvSize {
        /// Provided length.
        size: usize,
    },
    /// Tag is not 16 bytes.
    InvalidTagSize {
        /// Provided length.
        size: usize,
    },
    /// Empty ciphertext.
    EmptyCiphertext,
    /// Tag verification failed (tampered data, wrong key, wrong AAD).
    DecryptionFailed,
    /// Empty HKDF input keying material.
    EmptyInputKey,
    /// HKDF output length outside `1..=255 * 32`.
    InvalidOutputLength {
        /// Requested length.
        requested: usize,
    },
    /// Random-byte length of zero.
    InvalidLength,
    /// The OS CSPRNG failed.
    RandomFailed(String),
    /// The file could not be opened or read.
    Io {
        /// Path involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeySize { .. } => write!(f, "Invalid key size (expected 32 bytes)"),
            Self::EmptyPlaintext => write!(f, "Empty plaintext"),
            Self::InvalidIvSize { .. } => write!(f, "Invalid IV size"),
            Self::InvalidTagSize { .. } => write!(f, "Invalid tag size"),
            Self::EmptyCiphertext => write!(f, "Empty ciphertext"),
            Self::DecryptionFailed => {
                write!(f, "Decryption verification failed - data may be tampered")
            }
            Self::EmptyInputKey => write!(f, "Empty input key"),
            Self::InvalidOutputLength { .. } => write!(f, "Invalid output length"),
            Self::InvalidLength => write!(f, "Invalid length"),
            Self::RandomFailed(msg) => write!(f, "Random generation failed: {msg}"),
            Self::Io { path, source } => write!(f, "Failed to open file: {path} ({source})"),
        }
    }
}

impl std::error::Error for CryptoError {}

fn cipher_for(key: &[u8]) -> Result<Aes256Gcm, CryptoError> {
    if key.len() != AES_256_KEY_SIZE {
        return Err(CryptoError::InvalidKeySize { size: key.len() });
    }
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)))
}

/// C++ `EncryptAES256GCM` with a caller-supplied IV (deterministic;
/// for known-answer tests and callers that manage nonces themselves).
///
/// # Errors
///
/// [`CryptoError::InvalidKeySize`], [`CryptoError::EmptyPlaintext`],
/// [`CryptoError::InvalidIvSize`].
pub fn encrypt_aes256_gcm_with_iv(plaintext: &[u8], key: &[u8], aad: &[u8], iv: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    let cipher = cipher_for(key)?;
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyPlaintext);
    }
    if iv.len() != AES_GCM_IV_SIZE {
        return Err(CryptoError::InvalidIvSize { size: iv.len() });
    }
    let mut sealed = cipher
        .encrypt(Nonce::from_slice(iv), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EmptyPlaintext)?;
    // `aead` appends the tag to the ciphertext.
    let split = sealed.len().saturating_sub(AES_GCM_TAG_SIZE);
    let tag = sealed.split_off(split);
    Ok(EncryptedBlob {
        iv: iv.to_vec(),
        ciphertext: sealed,
        tag,
        aad: aad.to_vec(),
    })
}

/// C++ `EncryptAES256GCM(plaintext, key, aad, outBlob)`: fresh random
/// 12-byte IV from the OS CSPRNG, AES-256-GCM, 16-byte tag.
///
/// # Errors
///
/// As [`encrypt_aes256_gcm_with_iv`], plus [`CryptoError::RandomFailed`].
pub fn encrypt_aes256_gcm(plaintext: &[u8], key: &[u8], aad: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    // Validate before drawing randomness, like the C++ order.
    cipher_for(key)?;
    if plaintext.is_empty() {
        return Err(CryptoError::EmptyPlaintext);
    }
    let mut iv = [0_u8; AES_GCM_IV_SIZE];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|e| CryptoError::RandomFailed(e.to_string()))?;
    encrypt_aes256_gcm_with_iv(plaintext, key, aad, &iv)
}

/// C++ `DecryptAES256GCM(blob, key, outPlaintext)`: verifies the tag
/// (and AAD) and returns the plaintext in a zeroizing buffer.
///
/// # Errors
///
/// [`CryptoError::InvalidKeySize`], [`CryptoError::InvalidIvSize`],
/// [`CryptoError::InvalidTagSize`], [`CryptoError::EmptyCiphertext`],
/// [`CryptoError::DecryptionFailed`] on any authentication failure.
pub fn decrypt_aes256_gcm(blob: &EncryptedBlob, key: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = cipher_for(key)?;
    if blob.iv.len() != AES_GCM_IV_SIZE {
        return Err(CryptoError::InvalidIvSize { size: blob.iv.len() });
    }
    if blob.tag.len() != AES_GCM_TAG_SIZE {
        return Err(CryptoError::InvalidTagSize { size: blob.tag.len() });
    }
    if blob.ciphertext.is_empty() {
        return Err(CryptoError::EmptyCiphertext);
    }
    let mut sealed = Vec::with_capacity(blob.ciphertext.len().saturating_add(AES_GCM_TAG_SIZE));
    sealed.extend_from_slice(&blob.ciphertext);
    sealed.extend_from_slice(&blob.tag);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&blob.iv),
            Payload {
                msg: &sealed,
                aad: &blob.aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// C++ `ComputeSHA256(data, outHash)`.
#[must_use]
pub fn compute_sha256(data: &[u8]) -> [u8; SHA256_DIGEST_LENGTH] {
    Sha256::digest(data).into()
}

/// C++ `ComputeFileSHA256(path, outHash)`: streams the file in
/// [`FILE_HASH_CHUNK_SIZE`] reads (never loads it whole).
///
/// # Errors
///
/// [`CryptoError::Io`] when the file cannot be opened or read.
pub fn compute_file_sha256(path: &Path) -> Result<[u8; SHA256_DIGEST_LENGTH], CryptoError> {
    let io_err = |source: std::io::Error| CryptoError::Io {
        path: path.display().to_string(),
        source,
    };
    let mut file = std::fs::File::open(path).map_err(io_err)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; FILE_HASH_CHUNK_SIZE];
    loop {
        let read = file.read(&mut buffer).map_err(io_err)?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).unwrap_or(&[]));
    }
    Ok(hasher.finalize().into())
}

/// C++ `DeriveKeyHKDF(inputKey, salt, info, outputLength, outKey)`:
/// HKDF-SHA256 (RFC 5869). An empty `salt` means "no salt" (OpenSSL
/// and RFC 5869 then use `HashLen` zero bytes); `info` may be empty.
///
/// # Errors
///
/// [`CryptoError::EmptyInputKey`], [`CryptoError::InvalidOutputLength`]
/// for `0` or more than [`HKDF_MAX_OUTPUT_LENGTH`].
pub fn derive_key_hkdf(
    input_key: &[u8],
    salt: &[u8],
    info: &[u8],
    output_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if input_key.is_empty() {
        return Err(CryptoError::EmptyInputKey);
    }
    if output_length == 0 || output_length > HKDF_MAX_OUTPUT_LENGTH {
        return Err(CryptoError::InvalidOutputLength {
            requested: output_length,
        });
    }
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hkdf = Hkdf::<Sha256>::new(salt, input_key);
    let mut out = Zeroizing::new(vec![0_u8; output_length]);
    hkdf.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidOutputLength {
            requested: output_length,
        })?;
    Ok(out)
}

/// C++ `GenerateRandomBytes(length, outBytes)` from the OS CSPRNG.
///
/// # Errors
///
/// [`CryptoError::InvalidLength`] for `0`, [`CryptoError::RandomFailed`]
/// when the OS generator fails.
pub fn generate_random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if length == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut out = Zeroizing::new(vec![0_u8; length]);
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|e| CryptoError::RandomFailed(e.to_string()))?;
    Ok(out)
}

/// C++ `SecureErase(ptr, size)`: zeroes `buffer` in a way the
/// optimiser cannot elide.
pub fn secure_erase(buffer: &mut [u8]) {
    buffer.zeroize();
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i.saturating_add(2)], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn aes_256_gcm_nist_test_case_14() {
        // NIST GCM spec test case 14: zero key, zero IV, 16 zero bytes.
        let key = [0_u8; 32];
        let iv = [0_u8; 12];
        let plaintext = [0_u8; 16];
        let blob = encrypt_aes256_gcm_with_iv(&plaintext, &key, &[], &iv).expect("encrypt");
        assert_eq!(blob.ciphertext, hex("cea7403d4d606b6e074ec5d3baf39d18"));
        assert_eq!(blob.tag, hex("d0d1c8a799996bf0265b98b5d48ab919"));
        assert_eq!(blob.iv, iv);
        assert!(blob.aad.is_empty());
        let plain = decrypt_aes256_gcm(&blob, &key).expect("decrypt");
        assert_eq!(&plain[..], &plaintext[..]);
    }

    #[test]
    fn aes_256_gcm_nist_test_case_16_with_aad() {
        // NIST GCM spec test case 16 (AES-256, 60-byte plaintext, AAD).
        let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let iv = hex("cafebabefacedbaddecaf888");
        let plaintext = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let blob = encrypt_aes256_gcm_with_iv(&plaintext, &key, &aad, &iv).expect("encrypt");
        assert_eq!(
            blob.ciphertext,
            hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
        );
        assert_eq!(blob.tag, hex("76fc6ece0f4e1768cddf8853bb2d551b"));
        assert_eq!(blob.aad, aad);
        let plain = decrypt_aes256_gcm(&blob, &key).expect("decrypt");
        assert_eq!(&plain[..], &plaintext[..]);
    }

    #[test]
    fn random_iv_roundtrip_and_iv_uniqueness() {
        let key = generate_random_bytes(32).expect("key");
        let a = encrypt_aes256_gcm(b"secret payload", &key, b"ctx").expect("encrypt");
        let b = encrypt_aes256_gcm(b"secret payload", &key, b"ctx").expect("encrypt");
        assert_eq!(a.iv.len(), AES_GCM_IV_SIZE);
        assert_eq!(a.tag.len(), AES_GCM_TAG_SIZE);
        assert_eq!(a.ciphertext.len(), 14);
        assert_ne!(a.iv, b.iv);
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_eq!(&decrypt_aes256_gcm(&a, &key).expect("a")[..], b"secret payload");
        assert_eq!(&decrypt_aes256_gcm(&b, &key).expect("b")[..], b"secret payload");
    }

    #[test]
    fn tampering_wrong_key_and_wrong_aad_are_rejected() {
        let key = [0x42_u8; 32];
        let blob = encrypt_aes256_gcm(b"hello", &key, b"aad").expect("encrypt");

        let mut ct = blob.clone();
        ct.ciphertext[0] ^= 1;
        assert!(matches!(decrypt_aes256_gcm(&ct, &key), Err(CryptoError::DecryptionFailed)));

        let mut tag = blob.clone();
        tag.tag[15] ^= 1;
        assert!(matches!(decrypt_aes256_gcm(&tag, &key), Err(CryptoError::DecryptionFailed)));

        let mut aad = blob.clone();
        aad.aad = b"other".to_vec();
        assert!(matches!(decrypt_aes256_gcm(&aad, &key), Err(CryptoError::DecryptionFailed)));

        let mut iv = blob.clone();
        iv.iv[0] ^= 1;
        assert!(matches!(decrypt_aes256_gcm(&iv, &key), Err(CryptoError::DecryptionFailed)));

        let other_key = [0x43_u8; 32];
        assert!(matches!(
            decrypt_aes256_gcm(&blob, &other_key),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn input_validation_matches_cpp_checks() {
        let key = [0_u8; 32];
        assert!(matches!(
            encrypt_aes256_gcm(b"x", &[0; 16], &[]),
            Err(CryptoError::InvalidKeySize { size: 16 })
        ));
        assert!(matches!(
            encrypt_aes256_gcm(b"", &key, &[]),
            Err(CryptoError::EmptyPlaintext)
        ));
        assert!(matches!(
            encrypt_aes256_gcm_with_iv(b"x", &key, &[], &[0; 11]),
            Err(CryptoError::InvalidIvSize { size: 11 })
        ));

        let good = encrypt_aes256_gcm(b"x", &key, &[]).expect("encrypt");
        let mut blob = good.clone();
        blob.iv.push(0);
        assert!(matches!(
            decrypt_aes256_gcm(&blob, &key),
            Err(CryptoError::InvalidIvSize { size: 13 })
        ));
        let mut blob = good.clone();
        blob.tag.truncate(15);
        assert!(matches!(
            decrypt_aes256_gcm(&blob, &key),
            Err(CryptoError::InvalidTagSize { size: 15 })
        ));
        let mut blob = good.clone();
        blob.ciphertext.clear();
        assert!(matches!(
            decrypt_aes256_gcm(&blob, &key),
            Err(CryptoError::EmptyCiphertext)
        ));
        assert!(matches!(
            decrypt_aes256_gcm(&good, &[0; 31]),
            Err(CryptoError::InvalidKeySize { size: 31 })
        ));
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            compute_sha256(b"abc").to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(
            compute_sha256(b"").to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn file_sha256_streams_in_chunks() {
        let dir = std::env::temp_dir().join(format!("gview-crypto-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("data.bin");
        // Larger than one 8 KiB chunk and not a multiple of it.
        let data: Vec<u8> = (0..FILE_HASH_CHUNK_SIZE * 3 + 123).map(|i| (i % 253) as u8).collect();
        std::fs::write(&path, &data).expect("write");
        assert_eq!(compute_file_sha256(&path).expect("hash"), compute_sha256(&data));
        assert!(matches!(
            compute_file_sha256(&dir.join("missing.bin")),
            Err(CryptoError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let okm = derive_key_hkdf(&ikm, &salt, &info, 42).expect("hkdf");
        assert_eq!(
            &okm[..],
            &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")[..]
        );
    }

    #[test]
    fn hkdf_rfc5869_test_case_3_empty_salt_and_info() {
        let ikm = [0x0b_u8; 22];
        let okm = derive_key_hkdf(&ikm, &[], &[], 42).expect("hkdf");
        assert_eq!(
            &okm[..],
            &hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")[..]
        );
    }

    #[test]
    fn hkdf_rejects_empty_ikm_and_bad_lengths() {
        assert!(matches!(
            derive_key_hkdf(&[], b"s", b"i", 32),
            Err(CryptoError::EmptyInputKey)
        ));
        assert!(matches!(
            derive_key_hkdf(b"k", b"s", b"i", 0),
            Err(CryptoError::InvalidOutputLength { requested: 0 })
        ));
        assert!(matches!(
            derive_key_hkdf(b"k", b"s", b"i", HKDF_MAX_OUTPUT_LENGTH + 1),
            Err(CryptoError::InvalidOutputLength { .. })
        ));
        assert_eq!(
            derive_key_hkdf(b"k", b"s", b"i", HKDF_MAX_OUTPUT_LENGTH)
                .expect("max")
                .len(),
            HKDF_MAX_OUTPUT_LENGTH
        );
    }

    #[test]
    fn random_bytes_are_fresh_and_length_validated() {
        assert!(matches!(generate_random_bytes(0), Err(CryptoError::InvalidLength)));
        let a = generate_random_bytes(64).expect("a");
        let b = generate_random_bytes(64).expect("b");
        assert_eq!(a.len(), 64);
        assert_ne!(&a[..], &b[..]);
        assert!(a.iter().any(|&x| x != 0));
    }

    #[test]
    fn secure_erase_zeroes_and_secrets_zeroize_on_drop() {
        let mut buf = [0xAA_u8; 40];
        secure_erase(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));

        // `Zeroizing` wipes its contents when dropped; observe through
        // an explicit zeroize before the buffer goes away.
        let mut secret = derive_key_hkdf(b"ikm", b"", b"", 16).expect("hkdf");
        assert!(secret.iter().any(|&b| b != 0));
        secret.zeroize();
        assert!(secret.iter().all(|&b| b == 0));
    }

    #[test]
    fn error_messages_match_cpp() {
        assert_eq!(
            CryptoError::InvalidKeySize { size: 0 }.to_string(),
            "Invalid key size (expected 32 bytes)"
        );
        assert_eq!(
            CryptoError::DecryptionFailed.to_string(),
            "Decryption verification failed - data may be tampered"
        );
        assert_eq!(CryptoError::InvalidLength.to_string(), "Invalid length");
    }
}
