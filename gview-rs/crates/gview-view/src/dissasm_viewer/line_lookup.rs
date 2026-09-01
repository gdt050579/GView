//! `DissasmViewer` closest-anchor binary searches
//! (spec `02_VIEWER_DISSASM` §4.2–§4.3).
//!
//! C++ anchors: `SearchForClosestAsmOffsetLineByLine`
//! (`DissasmFunctionUtils.cpp:203-228`),
//! `SearchForClosestAsmOffsetLineByOffset`
//! (`DissasmFunctionUtils.cpp:134-152`),
//! `GetCurrentInstructionByOffset` zone repositioning
//! (`DissasmFunctionUtils.cpp:154-160`).
//!
//! Both searches binary-search the sorted anchor table and, when the
//! searched value falls between anchors, return the **lower** anchor
//! (the C++ `values[left - 1]` fallback). The C++ functions `assert`
//! on an empty table and would underflow `right = mid - 1` for a
//! search below the first anchor (unreachable with well-formed
//! tables, where `values[0].line == 0`); the Rust port returns
//! `None` for an empty table and clamps the underflow to the first
//! anchor instead of invoking undefined behavior.

use super::zone::{AsmOffsetLine, DissasmCodeZone};

/// C++ `SearchForClosestAsmOffsetLineByLine`
/// (`DissasmFunctionUtils.cpp:203-228`).
///
/// Returns the anchor whose `line` is the greatest value
/// `<= searched_line` (last anchor when beyond the table) together
/// with its table index (the C++ `index` out-parameter); `None` for
/// an empty table (C++ `assert`).
#[must_use]
pub fn search_for_closest_asm_offset_line_by_line(
    values: &[AsmOffsetLine],
    searched_line: u64,
) -> Option<(AsmOffsetLine, u32)> {
    if values.is_empty() {
        return None;
    }
    let mut left: u32 = 0;
    let mut right: u32 = (values.len() as u32).saturating_sub(1);
    while left < right {
        let mid = left.saturating_add(right) / 2;
        let mid_entry = values.get(mid as usize)?;
        if searched_line == u64::from(mid_entry.line) {
            return Some((*mid_entry, mid));
        }
        if searched_line < u64::from(mid_entry.line) {
            right = mid.saturating_sub(1); // clamped (C++ would wrap)
        } else {
            left = mid.saturating_add(1);
        }
    }
    let entry = values.get(left as usize)?;
    if left > 0 && u64::from(entry.line) > searched_line {
        let prev = left.saturating_sub(1);
        return values.get(prev as usize).map(|e| (*e, prev));
    }
    Some((*entry, left))
}

/// C++ `SearchForClosestAsmOffsetLineByOffset`
/// (`DissasmFunctionUtils.cpp:134-152`): same lookup keyed on the
/// anchor `offset`.
#[must_use]
pub fn search_for_closest_asm_offset_line_by_offset(
    values: &[AsmOffsetLine],
    searched_offset: u64,
) -> Option<AsmOffsetLine> {
    if values.is_empty() {
        return None;
    }
    let mut left: u32 = 0;
    let mut right: u32 = (values.len() as u32).saturating_sub(1);
    while left < right {
        let mid = left.saturating_add(right) / 2;
        let mid_entry = values.get(mid as usize)?;
        if searched_offset == mid_entry.offset {
            return Some(*mid_entry);
        }
        if searched_offset < mid_entry.offset {
            right = mid.saturating_sub(1); // clamped (C++ would wrap)
        } else {
            left = mid.saturating_add(1);
        }
    }
    let entry = values.get(left as usize)?;
    if left > 0 && entry.offset > searched_offset {
        return values.get(left.saturating_sub(1) as usize).copied();
    }
    Some(*entry)
}

/// The zone repositioning of `GetCurrentInstructionByOffset`
/// (`DissasmFunctionUtils.cpp:157-160`).
///
/// Looks up the closest anchor for `offset_to_reach` and points the
/// zone's decode cursor at it — `lastClosestLine`, `asmAddress`
/// (relative to the first anchor) and `asmSize` (bytes remaining).
/// Returns the anchor, or `None` when the table is empty. The
/// capstone re-decode from that point belongs to the disassembler
/// tasks.
pub fn reposition_zone_to_offset(
    zone: &mut DissasmCodeZone,
    offset_to_reach: u64,
) -> Option<AsmOffsetLine> {
    let closest =
        search_for_closest_asm_offset_line_by_offset(&zone.cached_code_offsets, offset_to_reach)?;
    let base = zone.cached_code_offsets.first()?.offset;
    zone.last_closest_line = closest.line;
    zone.asm_address = closest.offset.saturating_sub(base);
    zone.asm_size = zone.zone_details.size.saturating_sub(zone.asm_address);
    Some(closest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissasm_viewer::zone::DisassemblyZone;

    /// Anchors at lines 0/50/100/150, offsets 1000/1500/2000/2500.
    fn table() -> Vec<AsmOffsetLine> {
        vec![
            AsmOffsetLine {
                offset: 1000,
                line: 0,
            },
            AsmOffsetLine {
                offset: 1500,
                line: 50,
            },
            AsmOffsetLine {
                offset: 2000,
                line: 100,
            },
            AsmOffsetLine {
                offset: 2500,
                line: 150,
            },
        ]
    }

    #[test]
    fn by_line_golden_vectors() {
        let values = table();
        // Exact hits return the entry and its index.
        for (line, index) in [(0_u64, 0_u32), (50, 1), (100, 2), (150, 3)] {
            let (entry, idx) = search_for_closest_asm_offset_line_by_line(&values, line)
                .expect("non-empty table");
            assert_eq!(u64::from(entry.line), line);
            assert_eq!(idx, index);
        }
        // Between anchors → the lower anchor.
        let (entry, idx) = search_for_closest_asm_offset_line_by_line(&values, 73).unwrap();
        assert_eq!((entry.line, idx), (50, 1));
        let (entry, idx) = search_for_closest_asm_offset_line_by_line(&values, 149).unwrap();
        assert_eq!((entry.line, idx), (100, 2));
        // Edge indices: just above an anchor, just below the next.
        let (entry, _) = search_for_closest_asm_offset_line_by_line(&values, 1).unwrap();
        assert_eq!(entry.line, 0);
        let (entry, _) = search_for_closest_asm_offset_line_by_line(&values, 99).unwrap();
        assert_eq!(entry.line, 50);
        // Beyond the last anchor → the last anchor.
        let (entry, idx) = search_for_closest_asm_offset_line_by_line(&values, 10_000).unwrap();
        assert_eq!((entry.line, idx), (150, 3));
    }

    #[test]
    fn by_offset_golden_vectors() {
        let values = table();
        for offset in [1000_u64, 1500, 2000, 2500] {
            let entry =
                search_for_closest_asm_offset_line_by_offset(&values, offset).expect("hit");
            assert_eq!(entry.offset, offset);
        }
        let entry = search_for_closest_asm_offset_line_by_offset(&values, 1750).unwrap();
        assert_eq!(entry.offset, 1500);
        let entry = search_for_closest_asm_offset_line_by_offset(&values, 2499).unwrap();
        assert_eq!(entry.offset, 2000);
        let entry = search_for_closest_asm_offset_line_by_offset(&values, 99_999).unwrap();
        assert_eq!(entry.offset, 2500);
    }

    #[test]
    fn single_entry_and_empty_tables() {
        let single = vec![AsmOffsetLine {
            offset: 42,
            line: 0,
        }];
        let (entry, idx) = search_for_closest_asm_offset_line_by_line(&single, 500).unwrap();
        assert_eq!((entry.offset, idx), (42, 0));
        assert_eq!(
            search_for_closest_asm_offset_line_by_offset(&single, 41).unwrap().offset,
            42 // below-first clamps to the first anchor (Rust guard)
        );
        assert!(search_for_closest_asm_offset_line_by_line(&[], 5).is_none());
        assert!(search_for_closest_asm_offset_line_by_offset(&[], 5).is_none());
    }

    #[test]
    fn reposition_zone_updates_decode_cursor() {
        let mut zone = DissasmCodeZone {
            cached_code_offsets: table(),
            zone_details: DisassemblyZone {
                starting_zone_point: 1000,
                size: 4000,
                entry_point: 1000,
                ..DisassemblyZone::default()
            },
            ..DissasmCodeZone::default()
        };
        let closest = reposition_zone_to_offset(&mut zone, 2100).expect("anchor");
        assert_eq!(closest.offset, 2000);
        assert_eq!(zone.last_closest_line, 100);
        // asmAddress relative to the first anchor's offset.
        assert_eq!(zone.asm_address, 1000);
        // asmSize = zone size - asmAddress.
        assert_eq!(zone.asm_size, 3000);
        // Empty table → None, zone untouched.
        zone.cached_code_offsets.clear();
        assert!(reposition_zone_to_offset(&mut zone, 2100).is_none());
    }
}
