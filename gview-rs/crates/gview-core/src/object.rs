//! Analyzed object (C++ `GView::Object`, `GView.hpp`; creation in
//! `Instance.cpp:369-422`).
//!
//! An `Object` owns the [`DataCache`] over its backing data plus its
//! identity (name, path, type). The C++ `contentType` back-pointer is
//! **not** stored here: the `TypePlugin` trait lives in a dependent
//! crate (`gview-plugin`, task `plugin-native-traits`), and window
//! wiring attaches the content type there — avoiding the raw
//! back-pointer pattern per spec §2.5's invariant.

use std::path::{Path, PathBuf};

use crate::cache::DataCache;
use crate::source::{FileSource, MemorySource};

/// Kind of data backing an [`Object`]
/// (C++ `Object::Type`, spec §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    /// Data comes from a file on disk.
    File,
    /// A folder view; the cache stays empty (C++ parity: `DataCache`
    /// is default-constructed and never initialized).
    Folder,
    /// Data was copied from an in-memory buffer.
    MemoryBuffer,
    /// Reserved: the enum value exists in C++ but no process backend
    /// is implemented there either.
    Process,
}

/// One opened object: data cache plus identity
/// (C++ `GView::Object` minus the non-owning `contentType` pointer —
/// see module docs).
pub struct Object {
    cache: DataCache,
    name: String,
    path: PathBuf,
    pid: u32,
    kind: ObjectType,
}

impl Object {
    /// Opens `path` as a [`ObjectType::File`] object with a cache of
    /// `cache_size` bytes (rounded per `DataCache` Init; pass
    /// [`crate::constants::DEFAULT_CACHE_SIZE`] for the C++ default —
    /// `Instance::Add`, `Instance.cpp:386-399`).
    ///
    /// The object's `name` is the file-name component of `path` (the
    /// C++ caller passes the file name separately; this constructor
    /// derives it).
    ///
    /// # Errors
    /// Any I/O error from opening the file or reading its metadata.
    pub fn open_file(path: &Path, cache_size: u32) -> std::io::Result<Self> {
        let source = FileSource::open(path)?;
        let cache = DataCache::new(Box::new(source), cache_size);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(Self {
            cache,
            name,
            path: path.to_path_buf(),
            pid: 0,
            kind: ObjectType::File,
        })
    }

    /// Creates a [`ObjectType::MemoryBuffer`] object by **copying**
    /// `buf` into an owned allocation.
    ///
    /// Copy policy (C++ `MemoryFile::Create(buffer, size)`,
    /// `MemoryFile.cpp:63-73`): the input is copied at creation time,
    /// so later mutation or deallocation of the caller's buffer never
    /// affects the object. The C++ 32-byte over-allocation
    /// (`(size | 0x1F) + 1`) is an allocator detail, not behavior, and
    /// is not replicated; the logical size equals `buf.len()`.
    #[must_use]
    pub fn from_buffer(buf: &[u8], name: impl Into<String>, cache_size: u32) -> Self {
        let source = MemorySource::from_slice(buf);
        let cache = DataCache::new(Box::new(source), cache_size);
        Self {
            cache,
            name: name.into(),
            path: PathBuf::new(),
            pid: 0,
            kind: ObjectType::MemoryBuffer,
        }
    }

    /// Data access (C++ `GetData` returns a mutable `DataCache&`;
    /// reads mutate the sliding window).
    pub const fn data_mut(&mut self) -> &mut DataCache {
        &mut self.cache
    }

    /// Read-only cache access (size queries, `get_from_cache`).
    #[must_use]
    pub const fn data(&self) -> &DataCache {
        &self.cache
    }

    /// Display name (C++ `GetName`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Full path (C++ `GetPath`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Process id — meaningful only for [`ObjectType::Process`]
    /// (C++ `GetPID`).
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Kind of backing data (C++ `GetObjectType`).
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        self.kind
    }
}

#[cfg(test)]
mod file {
    use super::*;

    fn write_temp(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("golden.bin");
        std::fs::write(&path, data).expect("write temp file");
        (dir, path)
    }

    #[test]
    fn open_file_size_matches_filesystem() {
        let data: Vec<u8> = (0..=255).collect();
        let (_dir, path) = write_temp(&data);
        let fs_size = std::fs::metadata(&path).expect("metadata").len();

        let mut obj = Object::open_file(&path, crate::constants::DEFAULT_CACHE_SIZE).expect("open");
        assert_eq!(obj.data().size(), fs_size);
        assert_eq!(obj.object_type(), ObjectType::File);
        assert_eq!(obj.name(), "golden.bin");
        assert_eq!(obj.path(), path.as_path());
        assert_eq!(obj.pid(), 0);

        // Reads through the object see the file bytes.
        let bytes = obj.data_mut().get(0, 256, true).expect("read");
        assert_eq!(bytes, &data[..]);
    }

    #[test]
    fn open_empty_file() {
        let (_dir, path) = write_temp(&[]);
        let obj = Object::open_file(&path, 0).expect("open");
        assert_eq!(obj.data().size(), 0);
    }

    #[test]
    fn open_missing_file_errors() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let missing = dir.path().join("does-not-exist.bin");
        assert!(Object::open_file(&missing, 0).is_err());
    }
}

#[cfg(test)]
mod memory {
    use super::*;

    #[test]
    fn from_buffer_copies_input() {
        let mut original = vec![0x11_u8, 0x22, 0x33, 0x44];
        let mut obj = Object::from_buffer(&original, "buf", 0);
        assert_eq!(obj.object_type(), ObjectType::MemoryBuffer);
        assert_eq!(obj.name(), "buf");
        assert_eq!(obj.path(), Path::new(""));
        assert_eq!(obj.data().size(), 4);

        // Mutating the original after creation must not affect the
        // object (MemoryFile::Create copy semantics).
        original[0] = 0xFF;
        original.clear();
        let bytes = obj.data_mut().get(0, 4, true).expect("read");
        assert_eq!(bytes, &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn from_buffer_empty() {
        let obj = Object::from_buffer(&[], "empty", 0);
        assert_eq!(obj.data().size(), 0);
    }
}
