//! Checked offset arithmetic for file-coordinate math.
//!
//! Analyzed binaries are hostile: offsets and sizes may be crafted to
//! overflow `u64` or run past the end of a buffer. Every offset
//! computation in the data model goes through these helpers so that
//! malformed input yields `None` instead of a wrap-around or a panic
//! (see `specs/01_CORE_DATA_MODEL_AND_CACHE.md` §4.8, §4.10).

use core::ops::Range;

/// Adds `delta` to `base` in file coordinates.
///
/// Returns `None` on `u64` overflow.
#[must_use]
pub const fn checked_add(base: u64, delta: u64) -> Option<u64> {
    base.checked_add(delta)
}

/// Validates the half-open range `[offset, offset + size)` against an
/// exclusive upper bound `limit` (typically the file or buffer size).
///
/// Returns `Some(offset..offset + size)` only when the addition does
/// not overflow and the range end does not exceed `limit`. A zero
/// `size` is accepted (empty range), but `offset` must still satisfy
/// `offset <= limit`.
#[must_use]
pub const fn checked_range(offset: u64, size: u64, limit: u64) -> Option<Range<u64>> {
    match offset.checked_add(size) {
        Some(end) if end <= limit => Some(offset..end),
        _ => None,
    }
}

/// Bounded slice access using file-coordinate (`u64`) offsets.
///
/// Returns the sub-slice `buf[offset..offset + size]` when it lies
/// fully inside `buf`, `None` otherwise. Never panics.
#[must_use]
pub fn try_slice(buf: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let range = checked_range(offset, size, buf.len() as u64)?;
    let start = usize::try_from(range.start).ok()?;
    let end = usize::try_from(range.end).ok()?;
    buf.get(start..end)
}

#[cfg(test)]
// Test-only arithmetic: u128 sums of u64 values cannot overflow, and
// `start + size` is exercised only after the bounds check above it.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn checked_add_max_edges() {
        assert_eq!(checked_add(u64::MAX, 0), Some(u64::MAX));
        assert_eq!(checked_add(u64::MAX, 1), None);
        assert_eq!(checked_add(u64::MAX - 1, 1), Some(u64::MAX));
        assert_eq!(checked_add(1, u64::MAX), None);
        assert_eq!(checked_add(0, 0), Some(0));
    }

    #[test]
    fn checked_range_max_edges() {
        assert_eq!(checked_range(0, u64::MAX, u64::MAX), Some(0..u64::MAX));
        assert_eq!(checked_range(u64::MAX, 1, u64::MAX), None);
        assert_eq!(
            checked_range(u64::MAX, 0, u64::MAX),
            Some(u64::MAX..u64::MAX)
        );
        assert_eq!(checked_range(1, u64::MAX, u64::MAX), None);
    }

    #[test]
    fn checked_range_rejects_end_past_limit() {
        assert_eq!(checked_range(0, 11, 10), None);
        assert_eq!(checked_range(10, 1, 10), None);
        assert_eq!(checked_range(9, 1, 10), Some(9..10));
    }

    #[test]
    fn checked_range_empty_needs_offset_within_limit() {
        assert_eq!(checked_range(10, 0, 10), Some(10..10));
        assert_eq!(checked_range(11, 0, 10), None);
    }

    #[test]
    fn try_slice_empty_buffer() {
        assert_eq!(try_slice(&[], 0, 0), Some(&[][..]));
        assert_eq!(try_slice(&[], 0, 1), None);
        assert_eq!(try_slice(&[], 1, 0), None);
    }

    #[test]
    fn try_slice_one_byte_buffer() {
        let buf = [0xAB_u8];
        assert_eq!(try_slice(&buf, 0, 1), Some(&buf[..]));
        assert_eq!(try_slice(&buf, 0, 0), Some(&[][..]));
        assert_eq!(try_slice(&buf, 1, 0), Some(&[][..]));
        assert_eq!(try_slice(&buf, 0, 2), None);
        assert_eq!(try_slice(&buf, 1, 1), None);
        assert_eq!(try_slice(&buf, u64::MAX, 1), None);
        assert_eq!(try_slice(&buf, 1, u64::MAX), None);
    }

    proptest! {
        /// Roundtrip: for any buffer and any `(offset, size)` pair,
        /// `try_slice` succeeds exactly when the range fits, and the
        /// returned bytes equal the directly-indexed sub-slice.
        #[test]
        fn try_slice_roundtrip(
            data in proptest::collection::vec(any::<u8>(), 0..512),
            offset in 0_u64..1024,
            size in 0_u64..1024,
        ) {
            let got = try_slice(&data, offset, size);
            let fits = offset
                .checked_add(size)
                .is_some_and(|end| end <= data.len() as u64);
            if fits {
                let start = offset as usize;
                let end = start + size as usize;
                prop_assert_eq!(got, Some(&data[start..end]));
            } else {
                prop_assert_eq!(got, None);
            }
        }

        /// `checked_add` agrees with wide (u128) arithmetic on the
        /// full `u64` domain.
        #[test]
        fn checked_add_matches_u128(a in any::<u64>(), b in any::<u64>()) {
            let wide = u128::from(a) + u128::from(b);
            match checked_add(a, b) {
                Some(sum) => prop_assert_eq!(u128::from(sum), wide),
                None => prop_assert!(wide > u128::from(u64::MAX)),
            }
        }

        /// `checked_range` agrees with wide arithmetic and always
        /// returns a range of exactly `size` elements starting at
        /// `offset`.
        #[test]
        fn checked_range_matches_u128(
            offset in any::<u64>(),
            size in any::<u64>(),
            limit in any::<u64>(),
        ) {
            let wide_end = u128::from(offset) + u128::from(size);
            match checked_range(offset, size, limit) {
                Some(range) => {
                    prop_assert_eq!(range.start, offset);
                    prop_assert_eq!(u128::from(range.end), wide_end);
                    prop_assert!(range.end <= limit);
                }
                None => prop_assert!(wide_end > u128::from(limit)),
            }
        }
    }
}
