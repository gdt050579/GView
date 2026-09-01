//! Data sources backing a [`crate::cache::DataCache`].
//!
//! Port of the C++ `AppCUI::OS::DataObject` interface (`File`,
//! `MemoryFile`) consumed by `DataCache.cpp`. The Rust trait replaces
//! the stateful `SetCurrentPos` + `Read` pair with a stateless
//! [`DataSource::read_at`], per `specs/01_CORE_DATA_MODEL_AND_CACHE.md`
//! §4.10.

mod file;
mod memory;

pub use file::FileSource;
pub use memory::MemorySource;

/// Read-only random-access byte source (file, memory buffer, …).
///
/// Implementations must be safe against hostile access patterns:
/// out-of-range offsets are not errors — they simply read zero bytes.
pub trait DataSource: Send + Sync {
    /// Total size of the underlying data in bytes.
    fn size(&self) -> u64;

    /// Reads up to `buf.len()` bytes starting at `offset` into `buf`,
    /// returning the number of bytes read.
    ///
    /// A return value smaller than `buf.len()` means end-of-data was
    /// reached; an `offset` at or past the end reads `Ok(0)`.
    ///
    /// # Errors
    /// Only genuine I/O failures return `Err`; out-of-range reads are
    /// reported as `Ok(0)` or a short count instead.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
}
