//! Integration test for `cache-copy-to-buffer`: a 10 MiB file copied
//! through a small sliding window must be byte-identical to
//! `std::fs::read` (matrix task `cache-copy-to-buffer`).

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

use gview_core::cache::DataCache;
use gview_core::source::FileSource;

const TEN_MIB: usize = 10 * 1024 * 1024;

/// Deterministic xorshift-style pattern so the file is incompressible
/// enough to catch windowing mistakes, yet reproducible.
fn pattern(len: usize) -> Vec<u8> {
    let mut state = 0x1234_5678_9ABC_DEF0_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect()
}

#[test]
fn ten_mib_file_copy_matches_fs_read() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("ten_mib.bin");
    std::fs::write(&path, pattern(TEN_MIB)).expect("write 10 MiB file");

    // 64 KiB cache: the 10 MiB copy must slide the window many times.
    let source = FileSource::open(&path).expect("open");
    let mut cache = DataCache::new(Box::new(source), 0);
    assert_eq!(cache.size(), TEN_MIB as u64);

    let copied = cache
        .copy_to_vec(0, TEN_MIB as u32, true)
        .expect("copy 10 MiB");
    let direct = std::fs::read(&path).expect("fs::read");
    assert_eq!(copied.len(), direct.len());
    assert_eq!(copied, direct, "cache copy differs from std::fs::read");

    // write_to must produce the identical stream as well.
    let mut streamed = Vec::with_capacity(TEN_MIB);
    cache
        .write_to(&mut streamed, 0, TEN_MIB as u32)
        .expect("write_to 10 MiB");
    assert_eq!(streamed, direct);
}
