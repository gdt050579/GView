//! Core constants shared across the `GView` data model.
//!
//! Values are ported verbatim from the C++ sources cited per constant
//! (see `specs/01_CORE_DATA_MODEL_AND_CACHE.md` §1). Do not change them
//! without re-checking the C++ anchor.

/// Sentinel for "no offset" / "unset offset" (`GView.hpp:90`).
pub const INVALID_OFFSET: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Sentinel for "no selection zone" (`GView.hpp:91`).
pub const INVALID_SELECTION_INDEX: i32 = -1;

/// Default `DataCache` size: 10 MiB (`Instance.cpp:13`).
pub const DEFAULT_CACHE_SIZE: u32 = 0x00A0_0000;

/// Minimum `DataCache` size: 64 KiB (`Instance.cpp:14`).
pub const MIN_CACHE_SIZE: u32 = 0x0001_0000;

/// Maximum `DataCache` size: 512 MiB (`DataCache.cpp:5`).
///
/// The C++ source comment reads "16 M" but the value is `0x20000000`
/// (512 MiB); the value is authoritative.
pub const MAX_CACHE_SIZE: u32 = 0x2000_0000;

/// Maximum number of simultaneous selection zones (`Internal.hpp:20`).
pub const MAX_SELECTION_ZONES: usize = 4;

/// Number of bytes read from the start of a file when probing for type
/// identification (`Instance.cpp`).
pub const TYPE_IDENTIFICATION_PROBE_SIZE: u32 = 0x8800;

/// `GetEntireFile()` requires `file_size < 0xFFFF_FFFF`, so the largest
/// file it can return is this many bytes (`GView.hpp`).
pub const MAX_ENTIRE_FILE_SIZE: u64 = 0xFFFF_FFFE;

const _: () = assert!(MIN_CACHE_SIZE <= DEFAULT_CACHE_SIZE);
const _: () = assert!(DEFAULT_CACHE_SIZE <= MAX_CACHE_SIZE);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_offset_is_u64_max() {
        assert_eq!(INVALID_OFFSET, u64::MAX);
    }

    #[test]
    fn invalid_selection_index_is_minus_one() {
        assert_eq!(INVALID_SELECTION_INDEX, -1);
    }

    #[test]
    fn cache_size_bounds() {
        assert_eq!(DEFAULT_CACHE_SIZE, 10 * 1024 * 1024);
        assert_eq!(MIN_CACHE_SIZE, 64 * 1024);
        assert_eq!(MAX_CACHE_SIZE, 512 * 1024 * 1024);
    }

    #[test]
    fn selection_zone_count() {
        assert_eq!(MAX_SELECTION_ZONES, 4);
    }

    #[test]
    fn type_probe_size() {
        assert_eq!(TYPE_IDENTIFICATION_PROBE_SIZE, 0x8800);
    }

    #[test]
    fn entire_file_limit_below_u32_max() {
        assert_eq!(MAX_ENTIRE_FILE_SIZE, u64::from(u32::MAX) - 1);
    }
}
