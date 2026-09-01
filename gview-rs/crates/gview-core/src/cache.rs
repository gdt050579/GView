//! Sliding-window data cache (C++ `GView::Utils::DataCache` parity).
//!
//! Single window `[start, end)` over a [`DataSource`]; no LRU, no
//! multi-chunk map, no mmap (`specs/01_CORE_DATA_MODEL_AND_CACHE.md`
//! §4.1–4.2, `DataCache.cpp`).

use crate::constants::MAX_CACHE_SIZE;
use crate::offset::try_slice;
use crate::source::DataSource;

/// Failure modes of [`DataCache`] operations.
///
/// C++ signals every failure as an empty `BufferView`; the Rust port
/// distinguishes the causes (`specs/01_CORE_DATA_MODEL_AND_CACHE.md`
/// §4.10).
#[derive(Debug)]
pub enum CacheError {
    /// `requested_size` was 0 (C++ `CHECK(requestedSize > 0)`).
    ZeroSizeRequest,
    /// The requested offset lies at or past the end of the data, or
    /// `offset + size` overflows `u64`.
    OffsetOutOfRange {
        /// Requested offset.
        offset: u64,
        /// Size of the underlying data.
        file_size: u64,
    },
    /// `fail_if_cannot_read` was set and fewer than `requested` bytes
    /// are available at `offset`.
    CannotReadRequestedSize {
        /// Requested offset.
        offset: u64,
        /// Number of bytes requested.
        requested: u32,
    },
    /// The underlying source reported an I/O error; the cache window
    /// has been invalidated.
    Io(std::io::Error),
    /// The source returned fewer bytes than the window required; the
    /// cache window has been invalidated.
    ShortRead {
        /// Window start offset of the failed read.
        offset: u64,
        /// Bytes the window required.
        expected: u64,
        /// Bytes actually read.
        got: u64,
    },
    /// Internal invariant violation (defensive; should not occur).
    Internal(&'static str),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroSizeRequest => write!(f, "requested size must be bigger than 0"),
            Self::OffsetOutOfRange { offset, file_size } => {
                write!(f, "offset {offset} outside data of size {file_size}")
            }
            Self::CannotReadRequestedSize { offset, requested } => {
                write!(f, "unable to read {requested} bytes from offset {offset}")
            }
            Self::Io(e) => write!(f, "I/O error while filling cache: {e}"),
            Self::ShortRead {
                offset,
                expected,
                got,
            } => write!(
                f,
                "only {got} bytes read of {expected} required at offset {offset}"
            ),
            Self::Internal(msg) => write!(f, "internal cache error: {msg}"),
        }
    }
}

impl std::error::Error for CacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Rounds a requested cache size to the size actually allocated,
/// replicating `DataCache::Init` (`DataCache.cpp:52-55`):
///
/// ```text
/// cacheSize = (requested | 0xFFFF) + 1   // 64 KiB granularity, u32 wrap
/// if cacheSize == 0: cacheSize = MAX_CACHE_SIZE
/// cacheSize = min(cacheSize, MAX_CACHE_SIZE)
/// ```
///
/// The `+ 1` wraps for `requested >= 0xFFFF_0000` exactly as the C++
/// `uint32` addition does, which is what makes the `== 0` guard
/// reachable.
#[must_use]
pub const fn align_cache_size(requested: u32) -> u32 {
    let aligned = (requested | 0xFFFF).wrapping_add(1);
    if aligned == 0 || aligned > MAX_CACHE_SIZE {
        MAX_CACHE_SIZE
    } else {
        aligned
    }
}

/// Sliding-window cache over a [`DataSource`].
///
/// Owns its source (C++ `DataCache` owns and closes `fileObj`) and a
/// single pre-allocated buffer of `cache_size` bytes; the window
/// `[start, end)` marks which file range the buffer currently holds.
pub struct DataCache {
    source: Box<dyn DataSource>,
    file_size: u64,
    start: u64,
    end: u64,
    current_pos: u64,
    cache_size: u32,
    buffer: Vec<u8>,
}

impl DataCache {
    /// Creates a cache over `source`, rounding `requested_cache_size`
    /// per [`align_cache_size`] and snapshotting the source size
    /// (C++ `DataCache::Init`, `DataCache.cpp:47-65`).
    #[must_use]
    pub fn new(source: Box<dyn DataSource>, requested_cache_size: u32) -> Self {
        let cache_size = align_cache_size(requested_cache_size);
        let file_size = source.size();
        Self {
            source,
            file_size,
            start: 0,
            end: 0,
            current_pos: 0,
            cache_size,
            buffer: vec![0_u8; cache_size as usize],
        }
    }

    /// Total size of the underlying data (C++ `GetSize`).
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.file_size
    }

    /// Allocated cache size after Init rounding (C++ `GetCacheSize`).
    #[must_use]
    pub const fn cache_size(&self) -> u32 {
        self.cache_size
    }

    /// End offset of the last successful `get` (C++ `GetCurrentPos`).
    #[must_use]
    pub const fn current_pos(&self) -> u64 {
        self.current_pos
    }

    /// Overrides the tracked position (C++ `SetCurrentPos`).
    pub const fn set_current_pos(&mut self, pos: u64) {
        self.current_pos = pos;
    }

    /// O(1) peek at a single byte if it is already in the window,
    /// else `default`; performs **no I/O** (C++ `GetFromCache`,
    /// spec §4.7).
    #[must_use]
    pub fn get_from_cache(&self, offset: u64, default: u8) -> u8 {
        if offset >= self.start && offset < self.end {
            let rel = offset.saturating_sub(self.start);
            usize::try_from(rel)
                .ok()
                .and_then(|i| self.buffer.get(i).copied())
                .unwrap_or(default)
        } else {
            default
        }
    }

    /// Reads `requested_size` bytes at `offset`, sliding the cache
    /// window if needed (C++ `DataCache::Get`, `DataCache.cpp:66-143`;
    /// spec §4.3 state machine).
    ///
    /// With `fail_if_cannot_read == false`, a request crossing the end
    /// of the data returns the available prefix (possibly shorter than
    /// requested). The returned slice borrows the cache window and is
    /// invalidated by the next call.
    ///
    /// # Errors
    /// - [`CacheError::ZeroSizeRequest`] for a zero `requested_size`.
    /// - [`CacheError::OffsetOutOfRange`] when `offset` is at/past the
    ///   end of data, or `offset + requested_size` overflows `u64`
    ///   with nothing readable.
    /// - [`CacheError::CannotReadRequestedSize`] when
    ///   `fail_if_cannot_read` is set and the request crosses the end
    ///   of the data.
    /// - [`CacheError::Io`] / [`CacheError::ShortRead`] when the
    ///   source fails; the window is invalidated (C++ resets
    ///   `start = end = 0`).
    pub fn get(
        &mut self,
        offset: u64,
        requested_size: u32,
        fail_if_cannot_read: bool,
    ) -> Result<&[u8], CacheError> {
        if requested_size == 0 {
            return Err(CacheError::ZeroSizeRequest);
        }
        let req = u64::from(requested_size);
        // C++ computes `offset + requestedSize` in wrapping u64; a
        // wrapped comparison there can index out of bounds. The Rust
        // port treats overflow as "cannot satisfy in full" instead.
        let req_end = offset.checked_add(req);

        if offset >= self.start {
            // Cache hit: whole request inside the window.
            if let Some(re) = req_end {
                if re <= self.end {
                    self.current_pos = re;
                    return self.window_slice(offset, req);
                }
            }
            // Window already ends at EOF: serve the available tail.
            // C++ omits the `offset < end` guard and would compute an
            // underflowed length for offset >= end; Rust falls through
            // to the out-of-range check instead.
            if self.end == self.file_size && offset < self.end {
                if fail_if_cannot_read {
                    return Err(CacheError::CannotReadRequestedSize {
                        offset,
                        requested: requested_size,
                    });
                }
                self.current_pos = self.file_size;
                let len = self.end.saturating_sub(offset);
                return self.window_slice(offset, len);
            }
        }

        // Request outside the data.
        if offset >= self.file_size {
            return Err(CacheError::OffsetOutOfRange {
                offset,
                file_size: self.file_size,
            });
        }

        // Cache miss: compute the new window (DataCache.cpp:92-115).
        let cache_size = u64::from(self.cache_size);
        let (new_start, new_end) = if self.file_size <= cache_size {
            (0, self.file_size)
        } else {
            // offset < file_size here, so the subtraction is exact.
            let mut sz = req;
            let remaining = self.file_size.saturating_sub(offset);
            if sz > remaining {
                sz = remaining;
            }
            if sz > cache_size {
                sz = cache_size;
            }
            let diff = cache_size.saturating_sub(sz);
            let new_start = if diff <= offset {
                offset.saturating_sub(diff)
            } else {
                0
            };
            let new_end = u64::min(new_start.saturating_add(cache_size), self.file_size);
            (new_start, new_end)
        };

        // Fill the window from the source (DataCache.cpp:117-124).
        let window_len = new_end.saturating_sub(new_start);
        let window_len_usize = usize::try_from(window_len)
            .map_err(|_| CacheError::Internal("window exceeds usize"))?;
        let dst = self
            .buffer
            .get_mut(..window_len_usize)
            .ok_or(CacheError::Internal("window exceeds cache buffer"))?;
        match self.source.read_at(new_start, dst) {
            Ok(n) if n == window_len_usize => {}
            Ok(n) => {
                self.start = 0;
                self.end = 0;
                return Err(CacheError::ShortRead {
                    offset: new_start,
                    expected: window_len,
                    got: n as u64,
                });
            }
            Err(e) => {
                self.start = 0;
                self.end = 0;
                return Err(CacheError::Io(e));
            }
        }
        self.start = new_start;
        self.end = new_end;

        // Serve from the fresh window (DataCache.cpp:126-142).
        if let Some(re) = req_end {
            if re <= self.end {
                self.current_pos = re;
                return self.window_slice(offset, req);
            }
        }
        if fail_if_cannot_read {
            return Err(CacheError::CannotReadRequestedSize {
                offset,
                requested: requested_size,
            });
        }
        // Partial: offset < end is guaranteed by the window formula.
        self.current_pos = self.end;
        let len = self.end.saturating_sub(offset);
        self.window_slice(offset, len)
    }

    /// Copies `requested_size` bytes at `offset` into an owned vector,
    /// reading in chunks of `cache_size / 2` (C++ `CopyToBuffer`,
    /// `DataCache.cpp:152-200`; spec §4.4).
    ///
    /// With `fail_if_cannot_read == false`, the result is trimmed to
    /// the bytes actually readable (possibly empty).
    ///
    /// # Errors
    /// - [`CacheError::ZeroSizeRequest`] for a zero `requested_size`.
    /// - [`CacheError::OffsetOutOfRange`] when `offset > size()`.
    /// - [`CacheError::CannotReadRequestedSize`] when
    ///   `fail_if_cannot_read` is set and `offset + requested_size`
    ///   exceeds the data size (or overflows).
    /// - Any error from [`Self::get`] when `fail_if_cannot_read` is
    ///   set.
    pub fn copy_to_vec(
        &mut self,
        offset: u64,
        requested_size: u32,
        fail_if_cannot_read: bool,
    ) -> Result<Vec<u8>, CacheError> {
        if requested_size == 0 {
            return Err(CacheError::ZeroSizeRequest);
        }
        if offset > self.file_size {
            return Err(CacheError::OffsetOutOfRange {
                offset,
                file_size: self.file_size,
            });
        }
        if fail_if_cannot_read
            && offset
                .checked_add(u64::from(requested_size))
                .is_none_or(|end| end > self.file_size)
        {
            return Err(CacheError::CannotReadRequestedSize {
                offset,
                requested: requested_size,
            });
        }

        let mut out = Vec::with_capacity(requested_size as usize);
        let chunk = self.cache_size >> 1;
        let mut cur = offset;
        let mut remaining = requested_size;
        while remaining > 0 {
            let to_read = u32::min(chunk, remaining);
            // C++ always calls Get with fail=false here and handles
            // trimming itself.
            match self.get(cur, to_read, false) {
                Ok(bytes) => {
                    let got = bytes.len() as u32;
                    out.extend_from_slice(bytes);
                    if got != to_read {
                        if fail_if_cannot_read {
                            return Err(CacheError::CannotReadRequestedSize {
                                offset: cur,
                                requested: to_read,
                            });
                        }
                        return Ok(out); // trimmed to what was read
                    }
                    cur = cur.saturating_add(u64::from(to_read));
                    remaining = remaining.saturating_sub(to_read);
                }
                Err(e) => {
                    if fail_if_cannot_read {
                        return Err(e);
                    }
                    return Ok(out); // trimmed to what was read
                }
            }
        }
        Ok(out)
    }

    /// Reads a plain-data value of type `T` at `offset` (C++
    /// `Copy<T>` → `CopyObject`, `DataCache.cpp:144-151`; spec §4.8).
    ///
    /// # Errors
    /// - [`CacheError::ZeroSizeRequest`] for zero-sized `T`.
    /// - [`CacheError::CannotReadRequestedSize`] /
    ///   [`CacheError::OffsetOutOfRange`] when `size_of::<T>()` bytes
    ///   cannot be fully read at `offset` (C++ passes
    ///   `failIfRequestedSizeCanNotBeRead = true`).
    /// - [`CacheError::Internal`] if `T` is larger than `u32::MAX`
    ///   bytes.
    pub fn copy_object<T: zerocopy::FromBytes>(&mut self, offset: u64) -> Result<T, CacheError> {
        let size = u32::try_from(core::mem::size_of::<T>())
            .map_err(|_| CacheError::Internal("type larger than u32::MAX bytes"))?;
        let bytes = self.get(offset, size, true)?;
        T::read_from_bytes(bytes).map_err(|_| CacheError::Internal("size mismatch reading object"))
    }

    /// Streams `size` bytes starting at `offset` into `output` in
    /// chunks of `cache_size / 2` (C++ `WriteTo`,
    /// `DataCache.cpp:201-220`; spec §4.9).
    ///
    /// `size == 0` writes nothing and succeeds. Unlike C++, the
    /// generic `output` has no `SetSize`/`SetCurrentPos`; the caller
    /// positions the writer.
    ///
    /// # Errors
    /// Any error from [`Self::get`] (every chunk must be fully
    /// readable), or [`CacheError::Io`] if writing to `output` fails.
    pub fn write_to<W: std::io::Write + ?Sized>(
        &mut self,
        output: &mut W,
        offset: u64,
        size: u32,
    ) -> Result<(), CacheError> {
        if size == 0 {
            return Ok(()); // nothing to write
        }
        let chunk = self.cache_size >> 1;
        let mut cur = offset;
        let mut remaining = size;
        while remaining > 0 {
            let to_read = u32::min(chunk, remaining);
            let bytes = self.get(cur, to_read, true)?;
            output.write_all(bytes).map_err(CacheError::Io)?;
            cur = cur.saturating_add(u64::from(to_read));
            remaining = remaining.saturating_sub(to_read);
        }
        Ok(())
    }

    /// Returns `len` bytes of the window starting at file offset
    /// `offset`; both must already be validated against the window.
    fn window_slice(&self, offset: u64, len: u64) -> Result<&[u8], CacheError> {
        let rel = offset
            .checked_sub(self.start)
            .ok_or(CacheError::Internal("offset before window start"))?;
        try_slice(&self.buffer, rel, len).ok_or(CacheError::Internal("slice outside cache window"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    #[test]
    fn align_rounds_up_to_64k() {
        assert_eq!(align_cache_size(0), 0x1_0000);
        assert_eq!(align_cache_size(1), 0x1_0000);
        assert_eq!(align_cache_size(0xFFFF), 0x1_0000);
        assert_eq!(align_cache_size(0x1_0000), 0x2_0000);
        assert_eq!(align_cache_size(0x1_0001), 0x2_0000);
        assert_eq!(align_cache_size(0x9_FFFF), 0xA_0000);
    }

    #[test]
    fn align_default_cache_size() {
        // (0xA00000 | 0xFFFF) + 1 = 0xA10000 — the C++ default 10 MiB
        // request actually allocates 0xA10000 bytes.
        assert_eq!(
            align_cache_size(crate::constants::DEFAULT_CACHE_SIZE),
            0xA1_0000
        );
    }

    #[test]
    fn align_wrap_to_zero_yields_max() {
        // (r | 0xFFFF) + 1 wraps to 0 for r >= 0xFFFF0000 in u32.
        assert_eq!(align_cache_size(0xFFFF_0000), MAX_CACHE_SIZE);
        assert_eq!(align_cache_size(u32::MAX), MAX_CACHE_SIZE);
    }

    #[test]
    fn align_clamps_to_max() {
        assert_eq!(align_cache_size(MAX_CACHE_SIZE), MAX_CACHE_SIZE);
        assert_eq!(align_cache_size(MAX_CACHE_SIZE - 1), MAX_CACHE_SIZE);
        assert_eq!(align_cache_size(0x2000_1234), MAX_CACHE_SIZE);
    }

    #[test]
    fn new_initializes_per_spec() {
        let data = vec![0xAA_u8; 300];
        let cache = DataCache::new(Box::new(MemorySource::new(data)), 0);
        assert_eq!(cache.cache_size(), crate::constants::MIN_CACHE_SIZE);
        assert_eq!(cache.size(), 300);
        assert_eq!(cache.current_pos(), 0);
        assert_eq!(cache.start, 0);
        assert_eq!(cache.end, 0);
        assert_eq!(cache.buffer.len(), cache.cache_size() as usize);
    }

    #[test]
    fn current_pos_roundtrip() {
        let mut cache = DataCache::new(Box::new(MemorySource::new(vec![0_u8; 10])), 0);
        cache.set_current_pos(7);
        assert_eq!(cache.current_pos(), 7);
    }
}

#[cfg(test)]
mod get_tests {
    use super::*;
    use crate::source::MemorySource;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// Deterministic golden pattern shared with the source tests.
    fn golden(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(7).wrapping_add(3) & 0xFF) as u8)
            .collect()
    }

    fn expected(data: &[u8], offset: u64, len: usize) -> &[u8] {
        let start = usize::try_from(offset).expect("offset fits");
        &data[start..start.saturating_add(len)]
    }

    /// Wraps a source and counts `read_at` calls, to prove cache hits
    /// perform no I/O.
    struct CountingSource {
        inner: MemorySource,
        reads: Arc<AtomicU32>,
    }

    impl DataSource for CountingSource {
        fn size(&self) -> u64 {
            self.inner.size()
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.read_at(offset, buf)
        }
    }

    /// A source that always fails, to exercise the window-reset path.
    struct FailingSource {
        size: u64,
    }

    impl DataSource for FailingSource {
        fn size(&self) -> u64 {
            self.size
        }
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected failure"))
        }
    }

    fn counting_cache(data: Vec<u8>, cache_size: u32) -> (DataCache, Arc<AtomicU32>) {
        let reads = Arc::new(AtomicU32::new(0));
        let source = CountingSource {
            inner: MemorySource::new(data),
            reads: Arc::clone(&reads),
        };
        (DataCache::new(Box::new(source), cache_size), reads)
    }

    #[test]
    fn get_zero_size_rejected() {
        let mut cache = DataCache::new(Box::new(MemorySource::new(golden(16))), 0);
        assert!(matches!(
            cache.get(0, 0, true),
            Err(CacheError::ZeroSizeRequest)
        ));
    }

    #[test]
    fn get_hit_serves_from_window_without_io() {
        let data = golden(1024);
        let (mut cache, reads) = counting_cache(data.clone(), 0);

        // First read loads the whole (small) file into the window.
        let got = cache.get(0, 100, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0, 100));
        assert_eq!(cache.current_pos(), 100);
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // Subsequent reads inside the window are pure cache hits.
        let got = cache.get(500, 24, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 500, 24));
        assert_eq!(cache.current_pos(), 524);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_miss_slides_window() {
        // File larger than the 64 KiB cache forces window management.
        let data = golden(0x4_0000);
        let (mut cache, reads) = counting_cache(data.clone(), 0);
        assert_eq!(cache.cache_size(), 0x1_0000);

        let got = cache.get(0, 16, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0, 16));
        assert_eq!(reads.load(Ordering::SeqCst), 1);

        // Far miss: reload.
        let got = cache.get(0x2_0000, 16, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0x2_0000, 16));
        assert_eq!(reads.load(Ordering::SeqCst), 2);

        // Hit inside the new window: no additional read.
        let got = cache.get(0x2_0000, 16, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0x2_0000, 16));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn get_window_formula_matches_cpp() {
        // cache=0x10000, file=0x40000, offset=0x25000, size=0x100:
        // sz=0x100, diff=0xFF00, start=0x15100, end=0x25100.
        let data = golden(0x4_0000);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data.clone())), 0);
        let got = cache.get(0x2_5000, 0x100, true).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0x2_5000, 0x100));
        assert_eq!(cache.start, 0x1_5100);
        assert_eq!(cache.end, 0x2_5100);
        // The window content is byte-accurate at its boundaries.
        assert_eq!(cache.get_from_cache(0x1_5100, 0), data[0x1_5100]);
        assert_eq!(cache.get_from_cache(0x2_50FF, 0), data[0x2_50FF]);
        assert_eq!(cache.get_from_cache(0x2_5100, 0xEE), 0xEE);
        assert_eq!(cache.get_from_cache(0x1_50FF, 0xEE), 0xEE);
    }

    #[test]
    fn get_eof_partial_fail_false_truncates() {
        let data = golden(100);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data.clone())), 0);
        let got = cache.get(90, 20, false).expect("read").to_vec();
        assert_eq!(got, expected(&data, 90, 10));
        assert_eq!(cache.current_pos(), 100);
    }

    #[test]
    fn get_eof_partial_fail_true_errors() {
        let data = golden(100);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data)), 0);
        assert!(matches!(
            cache.get(90, 20, true),
            Err(CacheError::CannotReadRequestedSize {
                offset: 90,
                requested: 20
            })
        ));
    }

    #[test]
    fn get_eof_partial_after_window_slide() {
        // Large file, window slid to the tail, partial at real EOF.
        let data = golden(0x3_0000);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data.clone())), 0);
        let got = cache.get(0x2_FF00, 0x200, false).expect("read").to_vec();
        assert_eq!(got, expected(&data, 0x2_FF00, 0x100));
        assert_eq!(cache.current_pos(), 0x3_0000);
    }

    #[test]
    fn get_out_of_range() {
        let data = golden(100);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data)), 0);
        assert!(matches!(
            cache.get(100, 1, false),
            Err(CacheError::OffsetOutOfRange { .. })
        ));
        assert!(matches!(
            cache.get(u64::MAX, 1, false),
            Err(CacheError::OffsetOutOfRange { .. })
        ));
        // Overflowing offset + size with the offset itself in range is
        // impossible for u32 sizes unless offset is near u64::MAX,
        // which is already past EOF — covered above.
    }

    #[test]
    fn get_empty_file_always_out_of_range() {
        let mut cache = DataCache::new(Box::new(MemorySource::new(Vec::new())), 0);
        assert!(matches!(
            cache.get(0, 1, false),
            Err(CacheError::OffsetOutOfRange { .. })
        ));
    }

    #[test]
    fn get_one_byte_file() {
        let mut cache = DataCache::new(Box::new(MemorySource::new(vec![0x42])), 0);
        assert_eq!(cache.get(0, 1, true).expect("read"), &[0x42]);
        assert_eq!(cache.get(0, 5, false).expect("read"), &[0x42]);
        assert!(cache.get(1, 1, false).is_err());
    }

    #[test]
    fn get_read_failure_invalidates_window() {
        let mut cache = DataCache::new(Box::new(FailingSource { size: 1000 }), 0);
        assert!(matches!(cache.get(10, 4, true), Err(CacheError::Io(_))));
        assert_eq!(cache.start, 0);
        assert_eq!(cache.end, 0);
        assert_eq!(cache.get_from_cache(10, 0x7F), 0x7F);
    }

    #[test]
    fn get_golden_sweep() {
        // Golden check across many (offset, size) pairs vs the raw data.
        let data = golden(0x2_0800);
        let mut cache = DataCache::new(Box::new(MemorySource::new(data.clone())), 0);
        for &offset in &[
            0_u64, 1, 0xFFFF, 0x1_0000, 0x1_0001, 0x1_FFFF, 0x2_0000, 0x2_07FF,
        ] {
            for &size in &[1_u32, 2, 255, 4096] {
                let end = offset.saturating_add(u64::from(size));
                let got = cache.get(offset, size, false).expect("read").to_vec();
                let expect_len = u64::min(end, data.len() as u64).saturating_sub(offset);
                let expect_len = usize::try_from(expect_len).expect("fits");
                assert_eq!(
                    got,
                    expected(&data, offset, expect_len),
                    "off {offset} sz {size}"
                );
            }
        }
    }

    #[test]
    fn get_from_cache_no_io() {
        let data = golden(256);
        let (mut cache, reads) = counting_cache(data.clone(), 0);
        // Nothing cached yet: default, no I/O.
        assert_eq!(cache.get_from_cache(0, 0x11), 0x11);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
        cache.get(0, 16, true).expect("read");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert_eq!(cache.get_from_cache(200, 0), data[200]);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod copy_tests {
    use super::*;
    use crate::source::MemorySource;

    fn golden(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(7).wrapping_add(3) & 0xFF) as u8)
            .collect()
    }

    fn cache_over(data: Vec<u8>) -> DataCache {
        // 64 KiB cache → copy chunk size 0x8000, forcing multi-chunk
        // loops on files bigger than the window.
        DataCache::new(Box::new(MemorySource::new(data)), 0)
    }

    #[test]
    fn copy_to_vec_multi_chunk_exact() {
        // 0x30000 bytes through a 64 KiB window = 6 chunks of 0x8000.
        let data = golden(0x3_0000);
        let mut cache = cache_over(data.clone());
        let copied = cache.copy_to_vec(0, 0x3_0000, true).expect("copy");
        assert_eq!(copied, data);
    }

    #[test]
    fn copy_to_vec_mid_range() {
        let data = golden(0x2_0000);
        let mut cache = cache_over(data.clone());
        let copied = cache.copy_to_vec(0x1234, 0x9000, true).expect("copy");
        assert_eq!(copied, &data[0x1234..0x1234 + 0x9000]);
    }

    #[test]
    fn copy_to_vec_zero_size_rejected() {
        let mut cache = cache_over(golden(16));
        assert!(matches!(
            cache.copy_to_vec(0, 0, false),
            Err(CacheError::ZeroSizeRequest)
        ));
    }

    #[test]
    fn copy_to_vec_offset_past_size_rejected() {
        let mut cache = cache_over(golden(16));
        assert!(matches!(
            cache.copy_to_vec(17, 1, false),
            Err(CacheError::OffsetOutOfRange { .. })
        ));
    }

    #[test]
    fn copy_to_vec_cross_eof_fail_true_errors() {
        let mut cache = cache_over(golden(100));
        assert!(matches!(
            cache.copy_to_vec(90, 20, true),
            Err(CacheError::CannotReadRequestedSize { .. })
        ));
        // Overflow of offset + size is also "cannot read".
        assert!(matches!(
            cache.copy_to_vec(1, u32::MAX, true),
            Err(CacheError::CannotReadRequestedSize { .. })
        ));
    }

    #[test]
    fn copy_to_vec_cross_eof_fail_false_trims() {
        let data = golden(100);
        let mut cache = cache_over(data.clone());
        let copied = cache.copy_to_vec(90, 20, false).expect("copy");
        assert_eq!(copied, &data[90..]);
        // offset == fileSize with fail=false: C++ trims to zero bytes.
        let copied = cache.copy_to_vec(100, 20, false).expect("copy");
        assert!(copied.is_empty());
    }

    #[test]
    fn copy_object_reads_native_endian() {
        let data = vec![0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let mut cache = cache_over(data);
        let v: u32 = cache.copy_object(1).expect("copy");
        assert_eq!(v, u32::from_ne_bytes([0x02, 0x03, 0x04, 0x05]));
        let v: u64 = cache.copy_object(0).expect("copy");
        assert_eq!(
            v,
            u64::from_ne_bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }

    #[test]
    fn copy_object_past_eof_errors() {
        let mut cache = cache_over(vec![0_u8; 3]);
        assert!(cache.copy_object::<u32>(0).is_err());
        assert!(cache.copy_object::<u32>(100).is_err());
    }

    #[test]
    fn write_to_streams_chunks() {
        let data = golden(0x2_8000);
        let mut cache = cache_over(data.clone());
        let mut out = Vec::new();
        cache.write_to(&mut out, 0, 0x2_8000).expect("write");
        assert_eq!(out, data);

        let mut out = Vec::new();
        cache.write_to(&mut out, 0x100, 0x40).expect("write");
        assert_eq!(out, &data[0x100..0x140]);
    }

    #[test]
    fn write_to_zero_size_is_noop() {
        let mut cache = cache_over(golden(16));
        let mut out = Vec::new();
        cache.write_to(&mut out, 0, 0).expect("write");
        assert!(out.is_empty());
    }

    #[test]
    fn write_to_past_eof_errors() {
        let mut cache = cache_over(golden(16));
        let mut out = Vec::new();
        assert!(cache.write_to(&mut out, 10, 10).is_err());
    }
}
