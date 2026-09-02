//! `ComputeHash` (`Hashes.cpp`): the streaming engine behind every
//! command.
//!
//! - `computeForFile = option || selectedZones.empty()`;
//! - the total is the file size, or the sum of `end - start + 1` over
//!   the selection zones;
//! - `ProgressStatus::Init("Computing...", total)`, then per block
//!   `Update(offset, "Reading [0x%.8llX/0x%.8llX] bytes...")` (the
//!   16-digit variant, **without** the `Reading ` prefix, when the
//!   total exceeds `0xFFFFFFFF`); a `true` from `Update` (user cancel)
//!   aborts;
//! - blocks are `GetCacheSize()` bytes, read with
//!   `CopyToBuffer(offset, size, true)` — the loop is a `do … while`,
//!   so a zero-length range performs one zero-byte read, which is
//!   invalid and fails the whole computation;
//! - results are `name → uppercase hex` in `std::map` order.
//!
//! Deviation (documented): the C++ `SHA3_512` branch calls
//! `sha3_384.Final()` by mistake and then prints the *un-finalized*
//! SHA3-512 buffer (an empty string). The port finalizes SHA3-512
//! properly; the matrix note on `generic-hashes-plugin` records this.

use std::collections::BTreeMap;

use gview_core::cache::DataCache;
use gview_hashes::crc::{Adler32, Crc16, Crc32, Crc32Type, Crc64, Crc64Type};
use gview_hashes::sha::{OpenSslHash, OpenSslHashKind};
use gview_hashes::Hasher;
use gview_plugin::type_plugin::SelectionZone;

/// `ProgressStatus::Init` title.
pub const PROGRESS_TITLE: &str = "Computing...";

/// Bit set of selected algorithms (C++ `enum class Hashes`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HashFlags(pub u32);

impl HashFlags {
    /// `Hashes::None`.
    pub const NONE: Self = Self(0);
    /// `Hashes::ALL`.
    pub const ALL: Self = Self(0xFFFF_FFFF);

    /// Whether `kind` is selected.
    #[must_use]
    pub const fn contains(self, kind: HashKind) -> bool {
        self.0 & kind.bit() != 0
    }

    /// Adds `kind`.
    #[must_use]
    pub const fn with(self, kind: HashKind) -> Self {
        Self(self.0 | kind.bit())
    }

    /// Removes `kind`.
    #[must_use]
    pub const fn without(self, kind: HashKind) -> Self {
        Self(self.0 & !kind.bit())
    }

    /// The selected kinds in [`HASH_LIST`] order.
    #[must_use]
    pub fn kinds(self) -> Vec<HashKind> {
        HASH_LIST.iter().copied().filter(|k| self.contains(*k)).collect()
    }
}

impl core::ops::BitOr for HashFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// One algorithm (C++ `Hashes` enumerator).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashKind {
    /// `Hashes::Adler32`.
    Adler32,
    /// `Hashes::CRC16`.
    Crc16,
    /// `Hashes::CRC32_JAMCRC_0`.
    Crc32JamCrc0,
    /// `Hashes::CRC32_JAMCRC`.
    Crc32JamCrc,
    /// `Hashes::CRC64_ECMA_182`.
    Crc64Ecma182,
    /// `Hashes::CRC64_WE`.
    Crc64We,
    /// `Hashes::MD5`.
    Md5,
    /// `Hashes::BLAKE2S256`.
    Blake2s256,
    /// `Hashes::BLAKE2B512`.
    Blake2b512,
    /// `Hashes::SHA1`.
    Sha1,
    /// `Hashes::SHA224`.
    Sha224,
    /// `Hashes::SHA256`.
    Sha256,
    /// `Hashes::SHA384`.
    Sha384,
    /// `Hashes::SHA512`.
    Sha512,
    /// `Hashes::SHA512_224`.
    Sha512_224,
    /// `Hashes::SHA512_256`.
    Sha512_256,
    /// `Hashes::SHA3_224`.
    Sha3_224,
    /// `Hashes::SHA3_256`.
    Sha3_256,
    /// `Hashes::SHA3_384`.
    Sha3_384,
    /// `Hashes::SHA3_512`.
    Sha3_512,
    /// `Hashes::SHAKE128`.
    Shake128,
    /// `Hashes::SHAKE256`.
    Shake256,
}

/// C++ `hashList` order (the 24-slot array holds 22 entries).
pub const HASH_LIST: [HashKind; 22] = [
    HashKind::Adler32,
    HashKind::Crc16,
    HashKind::Crc32JamCrc0,
    HashKind::Crc32JamCrc,
    HashKind::Crc64Ecma182,
    HashKind::Crc64We,
    HashKind::Md5,
    HashKind::Blake2s256,
    HashKind::Blake2b512,
    HashKind::Sha1,
    HashKind::Sha224,
    HashKind::Sha256,
    HashKind::Sha384,
    HashKind::Sha512,
    HashKind::Sha512_224,
    HashKind::Sha512_256,
    HashKind::Sha3_224,
    HashKind::Sha3_256,
    HashKind::Sha3_384,
    HashKind::Sha3_512,
    HashKind::Shake128,
    HashKind::Shake256,
];

impl HashKind {
    /// The `Hashes` enumerator value.
    #[must_use]
    pub const fn bit(self) -> u32 {
        match self {
            Self::Adler32 => 0x0000_0001,
            Self::Crc16 => 0x0000_0002,
            Self::Crc32JamCrc0 => 0x0000_0004,
            Self::Crc32JamCrc => 0x0000_0008,
            Self::Crc64Ecma182 => 0x0000_0010,
            Self::Crc64We => 0x0000_0020,
            Self::Md5 => 0x0000_0100,
            Self::Blake2s256 => 0x0000_0200,
            Self::Blake2b512 => 0x0000_0400,
            Self::Sha1 => 0x0000_0800,
            Self::Sha224 => 0x0000_1000,
            Self::Sha256 => 0x0000_2000,
            Self::Sha384 => 0x0000_4000,
            Self::Sha512 => 0x0000_8000,
            Self::Sha512_224 => 0x0001_0000,
            Self::Sha512_256 => 0x0002_0000,
            Self::Sha3_224 => 0x0004_0000,
            Self::Sha3_256 => 0x0008_0000,
            Self::Sha3_384 => 0x0010_0000,
            Self::Sha3_512 => 0x0020_0000,
            Self::Shake128 => 0x0040_0000,
            Self::Shake256 => 0x0080_0000,
        }
    }

    /// The single-bit [`HashFlags`].
    #[must_use]
    pub const fn flag(self) -> HashFlags {
        HashFlags(self.bit())
    }

    /// Result-list name (`GetName()` for the CRC family, the literal
    /// for the OpenSSL digests).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Adler32 => Adler32::name(),
            Self::Crc16 => Crc16::name(),
            Self::Crc32JamCrc0 => Crc32::name(Crc32Type::JamCrc0),
            Self::Crc32JamCrc => Crc32::name(Crc32Type::JamCrc),
            Self::Crc64Ecma182 => Crc64::name(Crc64Type::Ecma182),
            Self::Crc64We => Crc64::name(Crc64Type::We),
            Self::Md5 => "MD5",
            Self::Blake2s256 => "BLAKE2S256",
            Self::Blake2b512 => "BLAKE2B512",
            Self::Sha1 => "SHA1",
            Self::Sha224 => "SHA224",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::Sha512_224 => "SHA512_224",
            Self::Sha512_256 => "SHA512_256",
            Self::Sha3_224 => "SHA3_224",
            Self::Sha3_256 => "SHA3_256",
            Self::Sha3_384 => "SHA3_384",
            Self::Sha3_512 => "SHA3_512",
            Self::Shake128 => "SHAKE128",
            Self::Shake256 => "SHAKE256",
        }
    }

    /// `[Generic.Hashes]` key (`TYPES_*`).
    #[must_use]
    pub const fn ini_key(self) -> &'static str {
        match self {
            Self::Adler32 => "Types.Adler32",
            Self::Crc16 => "Types.CRC16",
            Self::Crc32JamCrc0 => "Types.CRC32_JAMCRC_0",
            Self::Crc32JamCrc => "Types.CRC32_JAMCRC",
            Self::Crc64Ecma182 => "Types.CRC64_ECMA_182",
            Self::Crc64We => "Types.CRC64_WE",
            Self::Md5 => "Types.MD5",
            Self::Blake2s256 => "Types.BLAKE2S256",
            Self::Blake2b512 => "Types.BLAKE2B512",
            Self::Sha1 => "Types.SHA1",
            Self::Sha224 => "Types.SHA224",
            Self::Sha256 => "Types.SHA256",
            Self::Sha384 => "Types.SHA384",
            Self::Sha512 => "Types.SHA512",
            Self::Sha512_224 => "Types.SHA512_224",
            Self::Sha512_256 => "Types.SHA512_256",
            Self::Sha3_224 => "Types.SHA3_224",
            Self::Sha3_256 => "Types.SHA3_256",
            Self::Sha3_384 => "Types.SHA3_384",
            Self::Sha3_512 => "Types.SHA3_512",
            Self::Shake128 => "Types.SHAKE128",
            Self::Shake256 => "Types.SHAKE256",
        }
    }

    /// The OpenSSL digest for the EVP-backed kinds.
    #[must_use]
    pub const fn openssl_kind(self) -> Option<OpenSslHashKind> {
        Some(match self {
            Self::Md5 => OpenSslHashKind::Md5,
            Self::Blake2s256 => OpenSslHashKind::Blake2s256,
            Self::Blake2b512 => OpenSslHashKind::Blake2b512,
            Self::Sha1 => OpenSslHashKind::Sha1,
            Self::Sha224 => OpenSslHashKind::Sha224,
            Self::Sha256 => OpenSslHashKind::Sha256,
            Self::Sha384 => OpenSslHashKind::Sha384,
            Self::Sha512 => OpenSslHashKind::Sha512,
            Self::Sha512_224 => OpenSslHashKind::Sha512_224,
            Self::Sha512_256 => OpenSslHashKind::Sha512_256,
            Self::Sha3_224 => OpenSslHashKind::Sha3_224,
            Self::Sha3_256 => OpenSslHashKind::Sha3_256,
            Self::Sha3_384 => OpenSslHashKind::Sha3_384,
            Self::Sha3_512 => OpenSslHashKind::Sha3_512,
            Self::Shake128 => OpenSslHashKind::Shake128,
            Self::Shake256 => OpenSslHashKind::Shake256,
            Self::Adler32
            | Self::Crc16
            | Self::Crc32JamCrc0
            | Self::Crc32JamCrc
            | Self::Crc64Ecma182
            | Self::Crc64We => return None,
        })
    }

    /// Fresh hasher (`Init`).
    ///
    /// # Errors
    ///
    /// [`ComputeError::Digest`] when the digest is unavailable (MD5
    /// without the `md5` feature of `gview-hashes`).
    pub fn hasher(self) -> Result<Box<dyn Hasher>, ComputeError> {
        Ok(match self {
            Self::Adler32 => Box::new(Adler32::new()),
            Self::Crc16 => Box::new(Crc16::new()),
            Self::Crc32JamCrc0 => Box::new(Crc32::new(Crc32Type::JamCrc0)),
            Self::Crc32JamCrc => Box::new(Crc32::new(Crc32Type::JamCrc)),
            Self::Crc64Ecma182 => Box::new(Crc64::new(Crc64Type::Ecma182)),
            Self::Crc64We => Box::new(Crc64::new(Crc64Type::We)),
            other => {
                let kind = other.openssl_kind().ok_or(ComputeError::Digest(other))?;
                Box::new(OpenSslHash::new(kind).map_err(|_| ComputeError::Digest(other))?)
            }
        })
    }
}

/// Failures of [`compute_hashes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComputeError {
    /// A digest could not be constructed.
    Digest(HashKind),
    /// `ProgressStatus::Update` reported a cancel.
    Cancelled,
    /// `CopyToBuffer` failed (`buffer.IsValid()` false) at `offset`.
    Read {
        /// Offset of the failed block.
        offset: u64,
        /// Requested length.
        size: u32,
    },
}

impl core::fmt::Display for ComputeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Digest(kind) => write!(f, "cannot initialize {}", kind.display_name()),
            Self::Cancelled => f.write_str("computation cancelled"),
            Self::Read { offset, size } => write!(f, "cannot read {size} bytes at offset 0x{offset:X}"),
        }
    }
}

impl std::error::Error for ComputeError {}

/// `ProgressStatus` as seen by the engine.
pub trait ProgressSink {
    /// `ProgressStatus::Init(title, total)`.
    fn init(&mut self, title: &str, total: u64);

    /// `ProgressStatus::Update(offset, text)`; return `true` to cancel
    /// (the C++ return value).
    fn update(&mut self, offset: u64, text: &str) -> bool;
}

/// Headless sink (never cancels).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn init(&mut self, _title: &str, _total: u64) {}
    fn update(&mut self, _offset: u64, _text: &str) -> bool {
        false
    }
}

/// Sink that records every update (tests, and the "Show progress"
/// log the shell may keep).
#[derive(Clone, Debug, Default)]
pub struct RecordingProgress {
    /// `(title, total)` of the last `init`.
    pub init: Option<(String, u64)>,
    /// `(offset, text)` of every `update`, in order.
    pub updates: Vec<(u64, String)>,
    /// Cancel after this many updates (`None` = never).
    pub cancel_after: Option<usize>,
}

impl ProgressSink for RecordingProgress {
    fn init(&mut self, title: &str, total: u64) {
        self.init = Some((title.to_owned(), total));
    }
    fn update(&mut self, offset: u64, text: &str) -> bool {
        self.updates.push((offset, text.to_owned()));
        self.cancel_after.is_some_and(|n| self.updates.len() > n)
    }
}

/// The C++ progress text for one block (`"Reading [0x%.8llX/0x%.8llX]
/// bytes..."`, or the 16-digit form without `Reading ` past 4 GiB).
#[must_use]
pub fn progress_text(offset: u64, total: u64) -> String {
    if total > 0xFFFF_FFFF {
        format!("[0x{offset:016X}/0x{total:016X}] bytes...")
    } else {
        format!("Reading [0x{offset:08X}/0x{total:08X}] bytes...")
    }
}

/// Total byte count the computation covers.
#[must_use]
pub fn total_size(cache: &DataCache, compute_for_file: bool, zones: &[SelectionZone]) -> u64 {
    if compute_for_file {
        cache.size()
    } else {
        zones.iter().fold(0_u64, |acc, z| {
            acc.saturating_add(z.end.saturating_sub(z.start).saturating_add(1))
        })
    }
}

/// `ComputeHash(outputs, hashFlags, object, computeForFileOption,
/// selectedZones)`.
///
/// # Errors
///
/// See [`ComputeError`]. An empty range (empty file, or a zone that
/// reads nothing) is a [`ComputeError::Read`] like the C++ zero-byte
/// `CopyToBuffer`.
pub fn compute_hashes(
    cache: &mut DataCache,
    flags: HashFlags,
    compute_for_file_option: bool,
    selected_zones: &[SelectionZone],
    progress: &mut dyn ProgressSink,
) -> Result<BTreeMap<String, String>, ComputeError> {
    let compute_for_file = compute_for_file_option || selected_zones.is_empty();
    let object_size = total_size(cache, compute_for_file, selected_zones);
    progress.init(PROGRESS_TITLE, object_size);

    let mut hashers: Vec<(HashKind, Box<dyn Hasher>)> = Vec::new();
    for kind in flags.kinds() {
        hashers.push((kind, kind.hasher()?));
    }

    let block = u64::from(cache.cache_size()).max(1);
    let mut update_block = |cache: &mut DataCache, mut offset: u64, mut left: u64| -> Result<(), ComputeError> {
        loop {
            if progress.update(offset, &progress_text(offset, object_size)) {
                return Err(ComputeError::Cancelled);
            }
            let size_to_read = left.min(block);
            left = left.saturating_sub(size_to_read);
            let size = size_to_read as u32;
            let buffer = cache
                .copy_to_vec(offset, size, true)
                .map_err(|_| ComputeError::Read { offset, size })?;
            for (_, hasher) in &mut hashers {
                hasher.update(&buffer);
            }
            offset = offset.saturating_add(size_to_read);
            if left == 0 {
                return Ok(());
            }
        }
    };

    if compute_for_file {
        update_block(cache, 0, cache.size())?;
    } else {
        for zone in selected_zones {
            let left = zone.end.saturating_sub(zone.start).saturating_add(1);
            update_block(cache, zone.start, left)?;
        }
    }

    let mut outputs = BTreeMap::new();
    for (kind, mut hasher) in hashers {
        outputs.insert(kind.display_name().to_owned(), hasher.hex_digest());
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gview_core::source::MemorySource;

    fn cache_over(data: &[u8], cache_size: u32) -> DataCache {
        DataCache::new(Box::new(MemorySource::from_slice(data)), cache_size)
    }

    #[test]
    fn all_hash_kinds_streaming() {
        // "abc" in one block vs byte-by-byte streaming must agree, and
        // every value is uppercase hex.
        let mut whole = cache_over(b"abc", 0);
        let one = compute_hashes(&mut whole, HashFlags::ALL, true, &[], &mut NoProgress).expect("hashes");
        assert_eq!(one.len(), HASH_LIST.len());
        let mut zones = cache_over(b"abc", 0);
        let per_byte = [
            SelectionZone { start: 0, end: 0 },
            SelectionZone { start: 1, end: 1 },
            SelectionZone { start: 2, end: 2 },
        ];
        let streamed = compute_hashes(&mut zones, HashFlags::ALL, false, &per_byte, &mut NoProgress).expect("hashes");
        assert_eq!(one, streamed);
        for (name, value) in &one {
            assert!(!value.is_empty(), "{name} empty");
            assert!(
                value.bytes().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b)),
                "{name} = {value} is not uppercase hex"
            );
        }
        assert_eq!(one.get("MD5").map(String::as_str), Some("900150983CD24FB0D6963F7D28E17F72"));
        assert_eq!(one.get("SHA1").map(String::as_str), Some("A9993E364706816ABA3E25717850C26C9CD0D89D"));
        assert_eq!(
            one.get("SHA256").map(String::as_str),
            Some("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")
        );
        assert_eq!(
            one.get("SHA3_512").map(String::as_str),
            Some("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0")
        );
        assert_eq!(one.get("CRC32 (JAMCRC(-1))").map(String::as_str), Some("352441C2"));
        assert_eq!(one.get("Adler32").map(String::as_str), Some("024D0127"));
        // std::map order: ASCII, so "Adler32" < "BLAKE2B512" < "CRC16 (CCITT)" ...
        let names: Vec<&str> = one.keys().map(String::as_str).collect();
        assert_eq!(names.first().copied(), Some("Adler32"));
        assert_eq!(names.get(1).copied(), Some("BLAKE2B512"));
    }

    #[test]
    fn block_loop_and_progress_text() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let mut cache = cache_over(&data, 1); // 64 KiB window → 4 blocks
        let mut progress = RecordingProgress::default();
        let out = compute_hashes(&mut cache, HashKind::Sha256.flag(), true, &[], &mut progress).expect("sha256");
        assert_eq!(progress.init, Some(("Computing...".to_owned(), 200_000)));
        assert_eq!(progress.updates.len(), 4);
        assert_eq!(
            progress.updates.first().map(|u| u.1.as_str()),
            Some("Reading [0x00000000/0x00030D40] bytes...")
        );
        assert_eq!(progress.updates.get(1).map(|u| u.0), Some(0x10000));
        let mut whole = cache_over(&data, 0x10_0000);
        let expected = compute_hashes(&mut whole, HashKind::Sha256.flag(), true, &[], &mut NoProgress).expect("sha256");
        assert_eq!(out, expected);
        assert_eq!(progress_text(5, 0x1_0000_0000), "[0x0000000000000005/0x0000000100000000] bytes...");
    }

    #[test]
    fn selection_total_and_file_option_override() {
        let cache = cache_over(b"0123456789", 0);
        let zones = [SelectionZone { start: 2, end: 4 }, SelectionZone { start: 7, end: 7 }];
        assert_eq!(total_size(&cache, false, &zones), 4);
        assert_eq!(total_size(&cache, true, &zones), 10);
        let mut cache = cache_over(b"0123456789", 0);
        // "Compute for the entire file" wins over the zones.
        let file = compute_hashes(&mut cache, HashKind::Md5.flag(), true, &zones, &mut NoProgress).expect("md5");
        let mut plain = cache_over(b"0123456789", 0);
        let plain = compute_hashes(&mut plain, HashKind::Md5.flag(), true, &[], &mut NoProgress).expect("md5");
        assert_eq!(file, plain);
        // Zones concatenate: "234" + "7".
        let mut cache = cache_over(b"0123456789", 0);
        let sel = compute_hashes(&mut cache, HashKind::Md5.flag(), false, &zones, &mut NoProgress).expect("md5");
        let mut cat = cache_over(b"2347", 0);
        let cat = compute_hashes(&mut cat, HashKind::Md5.flag(), true, &[], &mut NoProgress).expect("md5");
        assert_eq!(sel, cat);
    }

    #[test]
    fn empty_input_cancel_and_out_of_range_fail() {
        let mut empty = cache_over(b"", 0);
        assert_eq!(
            compute_hashes(&mut empty, HashKind::Md5.flag(), true, &[], &mut NoProgress),
            Err(ComputeError::Read { offset: 0, size: 0 })
        );
        let mut cache = cache_over(b"abc", 0);
        let mut progress = RecordingProgress {
            cancel_after: Some(0),
            ..RecordingProgress::default()
        };
        assert_eq!(
            compute_hashes(&mut cache, HashKind::Md5.flag(), true, &[], &mut progress),
            Err(ComputeError::Cancelled)
        );
        let mut cache = cache_over(b"abc", 0);
        let past = [SelectionZone { start: 1, end: 10 }];
        assert!(matches!(
            compute_hashes(&mut cache, HashKind::Md5.flag(), false, &past, &mut NoProgress),
            Err(ComputeError::Read { offset: 1, size: 10 })
        ));
        assert_eq!(ComputeError::Cancelled.to_string(), "computation cancelled");
    }

    #[test]
    fn flags_and_kinds() {
        let flags = HashKind::Sha1.flag().with(HashKind::Crc16).without(HashKind::Sha1);
        assert_eq!(flags, HashKind::Crc16.flag());
        assert_eq!(flags.kinds(), vec![HashKind::Crc16]);
        assert_eq!(HashFlags::ALL.kinds().len(), 22);
        assert_eq!(HashFlags::NONE.kinds().len(), 0);
        assert_eq!(HashKind::Crc64We.ini_key(), "Types.CRC64_WE");
        assert_eq!(HashKind::Crc16.display_name(), "CRC16 (CCITT)");
        assert!(HashKind::Adler32.openssl_kind().is_none());
        assert_eq!(HashKind::Shake256.openssl_kind(), Some(OpenSslHashKind::Shake256));
        assert_eq!(HashKind::Shake256.bit(), 0x0080_0000);
    }
}
