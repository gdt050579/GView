//! ZIP archive listing and entry decompression (spec `04_SERVICES`
//! §4.1, §4.4).
//!
//! C++ anchor: `GView::Decoding::ZIP` (`zip.cpp`, on top of
//! minizip-ng): `GetInfo` walks the central directory into a flat
//! entry list — **synthesising missing parent directories** after
//! each entry (`zip.cpp` `GetInfo` loops) — and `Info::Decompress`
//! extracts one `File` entry into a buffer with an optional password.
//!
//! The Rust port uses the `zip` crate (store / deflate / AES and
//! `ZipCrypto` passwords). Field names follow the C++ `Entry` accessors;
//! [`ZipEntry::flag_names`] and [`ZipEntry::compression_method_name`]
//! reproduce the minizip strings, including the C++ quirk that
//! `DEFLATE_NORMAL` (flag value 0) is always listed.
//!
//! Hardening (spec §4.4 / §9.2, `02_VIEWER_CONTAINER` §12):
//!
//! - entry count capped by [`ZipLimits::max_entries`];
//! - an entry's declared size is checked against
//!   [`ZipLimits::max_output_size`] and
//!   [`ZipLimits::max_compression_ratio`] **before** allocating, and
//!   the stream is read with a hard byte limit so a lying header
//!   cannot exceed it;
//! - [`safe_extract_path`] rejects zip-slip names (`..`, absolute
//!   paths, drive letters, NUL) before anything touches the disk.

use std::io::{Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use zip::read::HasZipMetadata;
use zip::ZipArchive;

/// minizip `MZ_ZIP_FLAG_ENCRYPTED`.
pub const MZ_ZIP_FLAG_ENCRYPTED: u16 = 1 << 0;
/// minizip `MZ_ZIP_FLAG_DEFLATE_MAX`.
pub const MZ_ZIP_FLAG_DEFLATE_MAX: u16 = 1 << 1;
/// minizip `MZ_ZIP_FLAG_DEFLATE_NORMAL` (no bits set).
pub const MZ_ZIP_FLAG_DEFLATE_NORMAL: u16 = 0;
/// minizip `MZ_ZIP_FLAG_DEFLATE_FAST`.
pub const MZ_ZIP_FLAG_DEFLATE_FAST: u16 = 1 << 2;
/// minizip `MZ_ZIP_FLAG_DEFLATE_SUPER_FAST` (`MAX | FAST`).
pub const MZ_ZIP_FLAG_DEFLATE_SUPER_FAST: u16 = MZ_ZIP_FLAG_DEFLATE_MAX | MZ_ZIP_FLAG_DEFLATE_FAST;
/// minizip `MZ_ZIP_FLAG_DATA_DESCRIPTOR`.
pub const MZ_ZIP_FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;

/// PKZIP method IDs minizip names (`mz_zip_get_compression_method_string`).
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const METHOD_BZIP2: u16 = 12;
const METHOD_LZMA: u16 = 14;
const METHOD_ZSTD: u16 = 93;
const METHOD_XZ: u16 = 95;
const METHOD_AES: u16 = 99;

/// C++ `ZIP::EntryType`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    /// Not classified.
    #[default]
    Unknown = 0,
    /// Directory (name ends with `/` or directory attribute).
    Directory = 1,
    /// Symbolic link (`S_IFLNK` in the unix mode).
    Symlink = 2,
    /// Regular file.
    File = 3,
}

impl EntryType {
    /// C++ `Entry::GetTypeName`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Directory => "Directory",
            Self::Symlink => "Symlink",
            Self::File => "File",
            Self::Unknown => "Unknown",
        }
    }
}

/// One central-directory entry (C++ `_Entry` / `Entry` accessors).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZipEntry {
    /// UTF-8 name as stored (directories keep their trailing `/`).
    pub filename: String,
    /// General-purpose bit flags.
    pub flags: u16,
    /// PKZIP compression method ID. For AES entries this is the real
    /// method from the AES extra field (minizip-ng overwrites the
    /// header's 99 while parsing it), with [`Self::is_encrypted`] set.
    pub compression_method: u16,
    /// Compressed byte count.
    pub compressed_size: u64,
    /// Declared uncompressed byte count.
    pub uncompressed_size: u64,
    /// CRC-32 of the uncompressed data.
    pub crc: u32,
    /// Disk number (single-volume archives only: always 0).
    pub disk_number: u32,
    /// Offset of the local file header.
    pub disk_offset: u64,
    /// `version made by` (host system in the high byte).
    pub version_made_by: u16,
    /// Classification.
    pub entry_type: EntryType,
    /// Index in the archive's central directory; `None` for parent
    /// directories synthesised by the listing (C++ `parentEntry`).
    pub archive_index: Option<usize>,
}

impl ZipEntry {
    /// C++ `Entry::GetFlagNames`: the matching minizip flag names
    /// joined by `" | "`. Parity quirk preserved: `DEFLATE_NORMAL` is
    /// value 0, so `(0 & flags) == 0` always matches and it is always
    /// listed; the "write only super fast" skip in C++ can never fire.
    #[must_use]
    pub fn flag_names(&self) -> String {
        const FLAGS: [(u16, &str); 6] = [
            (MZ_ZIP_FLAG_ENCRYPTED, "ENCRYPTED"),
            (MZ_ZIP_FLAG_DEFLATE_MAX, "DEFLATE_MAX"),
            (MZ_ZIP_FLAG_DEFLATE_NORMAL, "DEFLATE_NORMAL"),
            (MZ_ZIP_FLAG_DEFLATE_FAST, "DEFLATE_FAST"),
            (MZ_ZIP_FLAG_DEFLATE_SUPER_FAST, "DEFLATE_SUPER_FAST"),
            (MZ_ZIP_FLAG_DATA_DESCRIPTOR, "DATA_DESCRIPTOR"),
        ];
        let mut output = String::new();
        for (bit, name) in FLAGS {
            let flag = bit & self.flags;
            if flag != bit {
                continue;
            }
            if (flag & MZ_ZIP_FLAG_DEFLATE_SUPER_FAST) == MZ_ZIP_FLAG_DEFLATE_SUPER_FAST
                && (flag == MZ_ZIP_FLAG_DEFLATE_MAX || flag == MZ_ZIP_FLAG_DEFLATE_FAST)
            {
                continue;
            }
            if !output.is_empty() {
                output.push_str(" | ");
            }
            output.push_str(name);
        }
        output
    }

    /// C++ `Entry::GetCompressionMethodName`
    /// (`mz_zip_get_compression_method_string`).
    #[must_use]
    pub const fn compression_method_name(&self) -> &'static str {
        match self.compression_method {
            METHOD_STORE => "stored",
            METHOD_DEFLATE => "deflate",
            METHOD_BZIP2 => "bzip2",
            METHOD_LZMA => "lzma",
            METHOD_XZ => "xz",
            METHOD_ZSTD => "zstd",
            METHOD_AES => "aes",
            _ => "?",
        }
    }

    /// C++ `Entry::IsEncrypted` (`flag & MZ_ZIP_FLAG_ENCRYPTED`).
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        (self.flags & MZ_ZIP_FLAG_ENCRYPTED) != 0
    }

    /// C++ `Entry::GetTypeName`.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        self.entry_type.name()
    }
}

/// Hardening policy for listing and extraction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZipLimits {
    /// Maximum entries kept in a listing (including synthesised
    /// parents).
    pub max_entries: usize,
    /// Hard cap on one entry's extracted size.
    pub max_output_size: u64,
    /// Maximum `uncompressed / compressed` ratio accepted before
    /// extraction (bomb guard).
    pub max_compression_ratio: u64,
}

impl Default for ZipLimits {
    /// 1M entries, 256 MiB per entry, 1000:1.
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_output_size: 256 * 1024 * 1024,
            max_compression_ratio: 1000,
        }
    }
}

/// ZIP failures.
#[derive(Debug)]
pub enum ZipError {
    /// Empty input.
    EmptyInput,
    /// The `zip` crate rejected the archive or entry.
    Archive(zip::result::ZipError),
    /// More entries than [`ZipLimits::max_entries`].
    TooManyEntries {
        /// Configured cap.
        limit: usize,
    },
    /// `index >= count` (C++ `CHECK(index < entries.size())`).
    InvalidIndex {
        /// Requested index.
        index: u32,
    },
    /// The entry is not a `File` (C++ `CHECK(entry.type == File)`),
    /// or it has no archive record (synthesised parent).
    NotAFile {
        /// Requested index.
        index: u32,
    },
    /// Declared size exceeds [`ZipLimits::max_output_size`].
    OutputLimitExceeded {
        /// Configured cap.
        limit: u64,
    },
    /// Declared sizes exceed [`ZipLimits::max_compression_ratio`].
    SuspiciousRatio {
        /// Compressed size.
        compressed: u64,
        /// Declared uncompressed size.
        uncompressed: u64,
        /// Configured cap.
        limit: u64,
    },
    /// The stream produced a different byte count than declared.
    SizeMismatch {
        /// Declared uncompressed size.
        expected: u64,
        /// Bytes actually produced (capped at `expected + 1`).
        produced: u64,
    },
    /// A name that would escape the extraction directory.
    UnsafePath(String),
    /// File / stream I/O.
    Io(std::io::Error),
}

impl core::fmt::Display for ZipError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "empty input"),
            Self::Archive(e) => write!(f, "zip: {e}"),
            Self::TooManyEntries { limit } => write!(f, "archive has more than {limit} entries"),
            Self::InvalidIndex { index } => write!(f, "entry index {index} out of range"),
            Self::NotAFile { index } => write!(f, "entry {index} is not a file"),
            Self::OutputLimitExceeded { limit } => write!(f, "entry exceeds {limit} bytes"),
            Self::SuspiciousRatio {
                compressed,
                uncompressed,
                limit,
            } => write!(
                f,
                "compression ratio {uncompressed}:{compressed} exceeds {limit}:1"
            ),
            Self::SizeMismatch { expected, produced } => {
                write!(f, "expected {expected} bytes, produced {produced}")
            }
            Self::UnsafePath(name) => write!(f, "unsafe archive path: {name:?}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for ZipError {}

impl From<zip::result::ZipError> for ZipError {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Archive(e)
    }
}

impl From<std::io::Error> for ZipError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// C++ `ZIP::Info`: the flat entry list of one archive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ZipInfo {
    entries: Vec<ZipEntry>,
}

impl ZipInfo {
    /// C++ `GetInfo(DataCache&, Info&)`: lists an in-memory archive.
    ///
    /// # Errors
    ///
    /// [`ZipError::EmptyInput`], [`ZipError::Archive`] for a malformed
    /// central directory, [`ZipError::TooManyEntries`].
    pub fn from_bytes(input: &[u8], limits: ZipLimits) -> Result<Self, ZipError> {
        if input.is_empty() {
            return Err(ZipError::EmptyInput);
        }
        let archive = ZipArchive::new(Cursor::new(input))?;
        Self::from_archive(archive, limits)
    }

    /// C++ `GetInfo(path, Info&)`: lists an archive on disk.
    ///
    /// # Errors
    ///
    /// [`ZipError::Io`] when the file cannot be opened, otherwise as
    /// [`Self::from_bytes`].
    pub fn from_path(path: &Path, limits: ZipLimits) -> Result<Self, ZipError> {
        let file = std::fs::File::open(path)?;
        let archive = ZipArchive::new(file)?;
        Self::from_archive(archive, limits)
    }

    fn from_archive<R: Read + Seek>(mut archive: ZipArchive<R>, limits: ZipLimits) -> Result<Self, ZipError> {
        let mut entries: Vec<ZipEntry> = Vec::new();
        for index in 0..archive.len() {
            let entry = {
                let file = archive.by_index_raw(index)?;
                convert_entry(&file, index)
            };
            push_entry(&mut entries, entry, limits)?;
            let last = entries.len().saturating_sub(1);
            add_parents(&mut entries, last, limits)?;
        }
        Ok(Self { entries })
    }

    /// C++ `Info::GetCount`.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// C++ `Info::GetEntry(index)`.
    #[must_use]
    pub fn entry(&self, index: u32) -> Option<&ZipEntry> {
        self.entries.get(index as usize)
    }

    /// All entries in listing order (archive order, parents appended
    /// right after the entry that introduced them).
    #[must_use]
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// C++ `Info::Decompress(input, output, index, password)`:
    /// extracts entry `index` of the in-memory archive `input`.
    ///
    /// # Errors
    ///
    /// [`ZipError::InvalidIndex`], [`ZipError::NotAFile`], the bomb
    /// guards ([`ZipError::OutputLimitExceeded`],
    /// [`ZipError::SuspiciousRatio`]), [`ZipError::SizeMismatch`], or
    /// [`ZipError::Archive`] (including a wrong password).
    pub fn decompress(&self, input: &[u8], index: u32, password: &str, limits: ZipLimits) -> Result<Vec<u8>, ZipError> {
        if input.is_empty() {
            return Err(ZipError::EmptyInput);
        }
        let entry = self.file_entry(index)?;
        let archive = ZipArchive::new(Cursor::new(input))?;
        decompress_entry(archive, entry, index, password, limits)
    }

    /// C++ `Info::Decompress(output, index, password)`: extracts entry
    /// `index` of the archive at `path`.
    ///
    /// # Errors
    ///
    /// As [`Self::decompress`], plus [`ZipError::Io`].
    pub fn decompress_from_path(
        &self,
        path: &Path,
        index: u32,
        password: &str,
        limits: ZipLimits,
    ) -> Result<Vec<u8>, ZipError> {
        let entry = self.file_entry(index)?;
        let file = std::fs::File::open(path)?;
        let archive = ZipArchive::new(file)?;
        decompress_entry(archive, entry, index, password, limits)
    }

    fn file_entry(&self, index: u32) -> Result<&ZipEntry, ZipError> {
        let entry = self.entry(index).ok_or(ZipError::InvalidIndex { index })?;
        if entry.entry_type != EntryType::File || entry.archive_index.is_none() {
            return Err(ZipError::NotAFile { index });
        }
        Ok(entry)
    }
}

/// C++ `ConvertZipFileInfoToEntry`.
fn convert_entry<R: Read + ?Sized>(file: &zip::read::ZipFile<'_, R>, index: usize) -> ZipEntry {
    let data = file.get_metadata();
    let (system, version) = file.version_made_by();
    let entry_type = if file.is_dir() {
        EntryType::Directory
    } else if file.is_symlink() {
        EntryType::Symlink
    } else {
        EntryType::File
    };
    ZipEntry {
        filename: file.name().to_owned(),
        flags: data.flags,
        // The crate deprecates the numeric view in favour of matching
        // its constants; GView needs the raw PKZIP method ID.
        #[allow(deprecated)]
        compression_method: data.compression_method.to_u16(),
        compressed_size: file.compressed_size(),
        uncompressed_size: file.size(),
        crc: file.crc32(),
        disk_number: 0,
        disk_offset: file.header_start(),
        version_made_by: (u16::from(system) << 8) | u16::from(version),
        entry_type,
        archive_index: Some(index),
    }
}

fn push_entry(entries: &mut Vec<ZipEntry>, entry: ZipEntry, limits: ZipLimits) -> Result<(), ZipError> {
    if entries.len() >= limits.max_entries {
        return Err(ZipError::TooManyEntries {
            limit: limits.max_entries,
        });
    }
    entries.push(entry);
    Ok(())
}

/// The C++ parent-synthesis loop: for every `/` in the entry name
/// (a directory's trailing `/` excluded), append a `Directory` entry
/// for that prefix unless one with the same name already exists.
fn add_parents(entries: &mut Vec<ZipEntry>, index: usize, limits: ZipLimits) -> Result<(), ZipError> {
    let Some(entry) = entries.get(index) else {
        return Ok(());
    };
    let filename = entry.filename.clone();
    let version_made_by = entry.version_made_by;
    let scan_len = if entry.entry_type == EntryType::Directory {
        filename.strip_suffix('/').map_or(filename.len(), str::len)
    } else {
        filename.len()
    };

    let mut offset = 0_usize;
    while let Some(rel) = filename
        .get(offset..scan_len)
        .and_then(|rest| rest.find('/'))
    {
        let pos = offset.saturating_add(rel);
        let Some(parent) = filename.get(..=pos) else {
            break;
        };
        if !entries.iter().any(|e| e.filename == parent) {
            push_entry(
                entries,
                ZipEntry {
                    filename: parent.to_owned(),
                    version_made_by,
                    entry_type: EntryType::Directory,
                    ..ZipEntry::default()
                },
                limits,
            )?;
        }
        offset = pos.saturating_add(1);
    }
    Ok(())
}

/// Bomb guards on the declared sizes (spec §4.4: before allocating).
fn check_bomb(entry: &ZipEntry, limits: ZipLimits) -> Result<(), ZipError> {
    if entry.uncompressed_size > limits.max_output_size {
        return Err(ZipError::OutputLimitExceeded {
            limit: limits.max_output_size,
        });
    }
    let compressed = entry.compressed_size.max(1);
    let ratio = entry.uncompressed_size.checked_div(compressed).unwrap_or(u64::MAX);
    if ratio > limits.max_compression_ratio {
        return Err(ZipError::SuspiciousRatio {
            compressed: entry.compressed_size,
            uncompressed: entry.uncompressed_size,
            limit: limits.max_compression_ratio,
        });
    }
    Ok(())
}

fn decompress_entry<R: Read + Seek>(
    mut archive: ZipArchive<R>,
    entry: &ZipEntry,
    index: u32,
    password: &str,
    limits: ZipLimits,
) -> Result<Vec<u8>, ZipError> {
    check_bomb(entry, limits)?;
    let archive_index = entry.archive_index.ok_or(ZipError::NotAFile { index })?;
    let expected = entry.uncompressed_size;

    // C++ always installs the (possibly empty) password; the `zip`
    // crate only wants one for encrypted entries.
    let file = if entry.is_encrypted() {
        archive.by_index_decrypt(archive_index, password.as_bytes())?
    } else {
        archive.by_index(archive_index)?
    };

    // Hard read limit: one byte more than declared detects a lying
    // header without ever exceeding `expected + 1` bytes of memory.
    let mut output = Vec::with_capacity(expected as usize);
    let limit = expected.saturating_add(1);
    file.take(limit).read_to_end(&mut output)?;
    let produced = output.len() as u64;
    if produced != expected {
        return Err(ZipError::SizeMismatch { expected, produced });
    }
    Ok(output)
}

/// Zip-slip guard: maps an archive name to a path **inside** `base`.
///
/// (`02_VIEWER_CONTAINER` §12.1/§12.3.) Rejects absolute paths, drive
/// letters, `..` components, and NUL bytes. `\` is treated as a
/// separator and `.` / empty components are dropped.
///
/// # Errors
///
/// [`ZipError::UnsafePath`] with the offending name.
pub fn safe_extract_path(base: &Path, name: &str) -> Result<PathBuf, ZipError> {
    let unsafe_path = || ZipError::UnsafePath(name.to_owned());
    if name.is_empty() || name.contains('\0') {
        return Err(unsafe_path());
    }
    let normalized = name.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(unsafe_path());
    }
    // `C:` / `C:/…` drive-relative or drive-absolute names.
    if normalized.as_bytes().get(1) == Some(&b':') {
        return Err(unsafe_path());
    }
    let mut out = base.to_path_buf();
    let mut depth = 0_usize;
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(unsafe_path()),
            other => {
                if other.contains(':') {
                    return Err(unsafe_path());
                }
                out.push(other);
                depth = depth.saturating_add(1);
            }
        }
    }
    if depth == 0 || !out.starts_with(base) {
        return Err(unsafe_path());
    }
    Ok(out)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};
    use zip::CompressionMethod;

    fn build(
        files: &[(&str, &[u8], SimpleFileOptions)],
        dirs: &[&str],
    ) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for dir in dirs {
            writer.add_directory(*dir, SimpleFileOptions::default()).expect("dir");
        }
        for (name, data, options) in files {
            writer.start_file(*name, *options).expect("start");
            writer.write_all(data).expect("write");
        }
        writer.finish().expect("finish").into_inner()
    }

    fn stored() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
    }

    fn deflated() -> SimpleFileOptions {
        SimpleFileOptions::default().compression_method(CompressionMethod::Deflated)
    }

    #[test]
    fn listing_synthesises_parent_directories_in_cpp_order() {
        let bytes = build(
            &[("dir/sub/file.txt", b"hello", stored()), ("top.bin", b"\x00\x01", deflated())],
            &[],
        );
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let names: Vec<&str> = info.entries().iter().map(|e| e.filename.as_str()).collect();
        assert_eq!(names, ["dir/sub/file.txt", "dir/", "dir/sub/", "top.bin"]);
        assert_eq!(info.count(), 4);

        let file = info.entry(0).expect("entry");
        assert_eq!(file.entry_type, EntryType::File);
        assert_eq!(file.type_name(), "File");
        assert_eq!(file.uncompressed_size, 5);
        assert_eq!(file.compressed_size, 5);
        assert_eq!(file.compression_method, METHOD_STORE);
        assert_eq!(file.compression_method_name(), "stored");
        assert_eq!(file.crc, 0x3610_A686);
        assert_eq!(file.archive_index, Some(0));
        assert!(!file.is_encrypted());

        let parent = info.entry(1).expect("parent");
        assert_eq!(parent.entry_type, EntryType::Directory);
        assert_eq!(parent.archive_index, None);
        assert_eq!(parent.version_made_by, file.version_made_by);
        assert_eq!(parent.uncompressed_size, 0);

        let top = info.entry(3).expect("top");
        assert_eq!(top.compression_method, METHOD_DEFLATE);
        assert_eq!(top.compression_method_name(), "deflate");
        assert_eq!(top.archive_index, Some(1));
    }

    #[test]
    fn explicit_directory_entries_are_not_duplicated() {
        let bytes = build(&[("a/b/c.txt", b"x", stored())], &["a/", "a/b/"]);
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let names: Vec<&str> = info.entries().iter().map(|e| e.filename.as_str()).collect();
        assert_eq!(names, ["a/", "a/b/", "a/b/c.txt"]);
        assert_eq!(info.entry(0).map(|e| e.entry_type), Some(EntryType::Directory));
        assert_eq!(info.entry(1).map(|e| e.archive_index), Some(Some(1)));
    }

    #[test]
    fn decompress_roundtrips_stored_and_deflated_entries() {
        let payload: Vec<u8> = (0..10_000_u32).map(|i| (i % 7) as u8).collect();
        let bytes = build(
            &[("s.bin", &payload, stored()), ("d.bin", &payload, deflated())],
            &[],
        );
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let s = info.decompress(&bytes, 0, "", ZipLimits::default()).expect("stored");
        let d = info.decompress(&bytes, 1, "", ZipLimits::default()).expect("deflated");
        assert_eq!(s, payload);
        assert_eq!(d, payload);
    }

    #[test]
    fn decompress_rejects_bad_index_and_directories() {
        let bytes = build(&[("dir/f.txt", b"abc", stored())], &[]);
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        assert!(matches!(
            info.decompress(&bytes, 9, "", ZipLimits::default()),
            Err(ZipError::InvalidIndex { index: 9 })
        ));
        // Index 1 is the synthesised "dir/".
        assert!(matches!(
            info.decompress(&bytes, 1, "", ZipLimits::default()),
            Err(ZipError::NotAFile { index: 1 })
        ));
        assert!(matches!(
            info.decompress(&[], 0, "", ZipLimits::default()),
            Err(ZipError::EmptyInput)
        ));
    }

    #[test]
    fn aes_password_roundtrip_and_wrong_password() {
        let options = deflated().with_aes_encryption(zip::AesMode::Aes256, "s3cret");
        let bytes = build(&[("secret.txt", b"top secret", options)], &[]);
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let entry = info.entry(0).expect("entry");
        assert!(entry.is_encrypted());
        // minizip-ng resolves the AES extra field to the real method.
        assert_eq!(entry.compression_method, METHOD_DEFLATE);
        assert_eq!(entry.compression_method_name(), "deflate");
        assert!(entry.flag_names().contains("ENCRYPTED"));

        let out = info.decompress(&bytes, 0, "s3cret", ZipLimits::default()).expect("decrypt");
        assert_eq!(out, b"top secret");
        assert!(info.decompress(&bytes, 0, "wrong", ZipLimits::default()).is_err());
    }

    #[test]
    fn output_limit_is_enforced_before_extraction() {
        let payload = vec![7_u8; 4096];
        let bytes = build(&[("big.bin", &payload, stored())], &[]);
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let limits = ZipLimits {
            max_output_size: 4095,
            ..ZipLimits::default()
        };
        assert!(matches!(
            info.decompress(&bytes, 0, "", limits),
            Err(ZipError::OutputLimitExceeded { limit: 4095 })
        ));
    }

    #[test]
    fn compression_ratio_cap_rejects_bombs() {
        let zeros = vec![0_u8; 64 * 1024];
        let bytes = build(&[("bomb.bin", &zeros, deflated())], &[]);
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let entry = info.entry(0).expect("entry");
        assert!(entry.compressed_size * 10 < entry.uncompressed_size);
        let limits = ZipLimits {
            max_compression_ratio: 10,
            ..ZipLimits::default()
        };
        assert!(matches!(
            info.decompress(&bytes, 0, "", limits),
            Err(ZipError::SuspiciousRatio { limit: 10, .. })
        ));
        // Default 1000:1 admits this ~64 KiB entry.
        let out = info.decompress(&bytes, 0, "", ZipLimits::default()).expect("ok");
        assert_eq!(out.len(), zeros.len());
    }

    #[test]
    fn lying_header_size_is_a_size_mismatch() {
        let bytes = build(&[("f.txt", b"0123456789", stored())], &[]);
        let mut info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        info.entries[0].uncompressed_size = 4;
        assert!(matches!(
            info.decompress(&bytes, 0, "", ZipLimits::default()),
            Err(ZipError::SizeMismatch { expected: 4, produced: 5 })
        ));
        info.entries[0].uncompressed_size = 20;
        assert!(matches!(
            info.decompress(&bytes, 0, "", ZipLimits::default()),
            Err(ZipError::SizeMismatch { expected: 20, produced: 10 })
        ));
    }

    #[test]
    fn entry_cap_counts_synthesised_parents() {
        let bytes = build(&[("a/b/c.txt", b"x", stored())], &[]);
        let limits = ZipLimits {
            max_entries: 2,
            ..ZipLimits::default()
        };
        assert!(matches!(
            ZipInfo::from_bytes(&bytes, limits),
            Err(ZipError::TooManyEntries { limit: 2 })
        ));
        let limits = ZipLimits {
            max_entries: 3,
            ..ZipLimits::default()
        };
        assert_eq!(ZipInfo::from_bytes(&bytes, limits).expect("info").count(), 3);
    }

    #[test]
    fn malformed_and_empty_input_are_rejected() {
        assert!(matches!(
            ZipInfo::from_bytes(&[], ZipLimits::default()),
            Err(ZipError::EmptyInput)
        ));
        assert!(matches!(
            ZipInfo::from_bytes(b"PK\x03\x04garbage", ZipLimits::default()),
            Err(ZipError::Archive(_))
        ));
    }

    #[test]
    fn flag_names_follow_the_cpp_quirks() {
        let plain = ZipEntry::default();
        assert_eq!(plain.flag_names(), "DEFLATE_NORMAL");
        let e = ZipEntry {
            flags: MZ_ZIP_FLAG_ENCRYPTED | MZ_ZIP_FLAG_DATA_DESCRIPTOR,
            ..ZipEntry::default()
        };
        assert_eq!(e.flag_names(), "ENCRYPTED | DEFLATE_NORMAL | DATA_DESCRIPTOR");
        let e = ZipEntry {
            flags: MZ_ZIP_FLAG_DEFLATE_SUPER_FAST,
            ..ZipEntry::default()
        };
        assert_eq!(
            e.flag_names(),
            "DEFLATE_MAX | DEFLATE_NORMAL | DEFLATE_FAST | DEFLATE_SUPER_FAST"
        );
    }

    #[test]
    fn compression_method_names_match_minizip() {
        let name = |m: u16| ZipEntry {
            compression_method: m,
            ..ZipEntry::default()
        }
        .compression_method_name();
        assert_eq!(name(0), "stored");
        assert_eq!(name(8), "deflate");
        assert_eq!(name(12), "bzip2");
        assert_eq!(name(14), "lzma");
        assert_eq!(name(93), "zstd");
        assert_eq!(name(95), "xz");
        assert_eq!(name(99), "aes");
        assert_eq!(name(9), "?");
    }

    #[test]
    fn zip_slip_paths_are_rejected() {
        let base = Path::new("out");
        for bad in [
            "../evil.txt",
            "a/../../evil.txt",
            "/etc/passwd",
            "\\windows\\system32",
            "C:\\evil.txt",
            "C:evil.txt",
            "..",
            "",
            "a\0b",
            "./",
            "dir/..\\x",
        ] {
            assert!(
                matches!(safe_extract_path(base, bad), Err(ZipError::UnsafePath(_))),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn safe_paths_stay_inside_base() {
        let base = Path::new("out");
        assert_eq!(
            safe_extract_path(base, "a/b.txt").expect("ok"),
            Path::new("out").join("a").join("b.txt")
        );
        assert_eq!(
            safe_extract_path(base, "./a//.\\c.bin").expect("ok"),
            Path::new("out").join("a").join("c.bin")
        );
        assert_eq!(
            safe_extract_path(base, "dir/").expect("ok"),
            Path::new("out").join("dir")
        );
    }

    #[test]
    fn archive_entry_named_with_traversal_is_listed_but_guarded() {
        let mut bytes = build(&[("aa/evil.txt", b"x", stored())], &[]);
        // Rewrite the (same-length) name in both headers.
        let from = b"aa/evil.txt";
        let to = b"../evil.txt";
        let mut i = 0;
        while i + from.len() <= bytes.len() {
            if &bytes[i..i + from.len()] == from {
                bytes[i..i + from.len()].copy_from_slice(to);
            }
            i += 1;
        }
        let info = ZipInfo::from_bytes(&bytes, ZipLimits::default()).expect("info");
        let entry = info.entry(0).expect("entry");
        assert_eq!(entry.filename, "../evil.txt");
        assert!(matches!(
            safe_extract_path(Path::new("out"), &entry.filename),
            Err(ZipError::UnsafePath(_))
        ));
        // The bytes are still extractable into memory.
        assert_eq!(info.decompress(&bytes, 0, "", ZipLimits::default()).expect("ok"), b"x");
    }

    #[test]
    fn from_path_and_decompress_from_path() {
        let bytes = build(&[("f.txt", b"disk", deflated())], &[]);
        let dir = std::env::temp_dir().join(format!("gview-zip-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("t.zip");
        std::fs::write(&path, &bytes).expect("write");
        let info = ZipInfo::from_path(&path, ZipLimits::default()).expect("info");
        assert_eq!(info.count(), 1);
        let out = info
            .decompress_from_path(&path, 0, "", ZipLimits::default())
            .expect("extract");
        assert_eq!(out, b"disk");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(
            ZipInfo::from_path(&dir.join("missing.zip"), ZipLimits::default()),
            Err(ZipError::Io(_))
        ));
    }
}
