//! `DissasmViewer` structure-zone collapse (spec `02_VIEWER_DISSASM`
//! §3.2).
//!
//! C++ anchors: `Instance::ChangeZoneCollapseState`
//! (`Instance.cpp:1453-1488`), structure init
//! (`Instance.cpp:1026-1044`), `DissasmStructureType::GetExpandedSize`
//! (`UserDefinedTypes.cpp:151-157`), `UpdateLayoutTotalLines`
//! (`Instance.cpp:1169-1173`).
//!
//! Toggling a zone's collapse state shifts every **subsequent** zone
//! by the zone's `extended_size` (added when expanding, subtracted
//! when collapsing) and adjusts the toggled zone's own
//! `ending_line_index`; its `start_line_index` never moves. The size
//! delta uses `extended_size`, **not** `ending - start` (spec §3.2).
//!
//! The C++ routine also special-cases a nested code-zone toggle
//! (`zoneType == DissasmCodeParseZone && startLineIndex != line`),
//! which delegates to `CollapseOrExtendZone` — that path is the
//! `dissasm-code-zone-collapse` task. Here [`change_zone_collapse_state`]
//! reports it via [`CollapseOutcome::NestedCodeZone`] so the next task
//! can drive it; the whole-zone shift is done for every other case.

use super::zone::{total_lines, DissasmParseZoneType, ZoneEntry};

/// C++ `structuresInitialCollapsedState` (`Instance.cpp:192`).
pub const STRUCTURES_INITIAL_COLLAPSED_STATE: bool = true;

/// Recursive expanded line count (C++
/// `DissasmStructureType::GetExpandedSize`,
/// `UserDefinedTypes.cpp:151-157`): `1 + Σ children`.
#[must_use]
pub fn get_expanded_size(internal_types: &[StructureType]) -> u32 {
    let mut result = 1_u32;
    for child in internal_types {
        result = result.saturating_add(get_expanded_size(&child.internal_types));
    }
    result
}

/// A minimal structure-type node carrying only what
/// [`get_expanded_size`] needs (C++ `DissasmStructureType` subset).
#[derive(Clone, Debug, Default)]
pub struct StructureType {
    /// Field name (unused by the size recurrence; kept for parity).
    pub name: String,
    /// Nested fields.
    pub internal_types: Vec<Self>,
}

/// Result of [`change_zone_collapse_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollapseOutcome {
    /// The whole-zone shift was applied; carries the new total line
    /// count (C++ `UpdateLayoutTotalLines`).
    Structure { total_lines: u32 },
    /// The target is a code zone toggled at an inner line: the
    /// `dissasm-code-zone-collapse` task must run `CollapseOrExtendZone`
    /// for `inside_line`. No shift was applied.
    NestedCodeZone { inside_line: u32 },
    /// `target_index` was out of range.
    NotFound,
}

/// Initializes a structure zone's collapse bookkeeping (C++
/// `Instance.cpp:1029-1044`).
///
/// `ending = start + 1`, `extended_size = expanded_size - 1`, and —
/// when created expanded — `ending += extended_size`. Returns the
/// zone's `ending_line_index`.
pub const fn init_structure_zone(
    zone: &mut super::zone::ParseZone,
    start_line: u32,
    expanded_size: u32,
    initial_collapsed: bool,
) -> u32 {
    zone.start_line_index = start_line;
    zone.ending_line_index = start_line.saturating_add(1);
    zone.is_collapsed = initial_collapsed;
    zone.extended_size = expanded_size.saturating_sub(1);
    if !initial_collapsed {
        zone.ending_line_index = zone.ending_line_index.saturating_add(zone.extended_size);
    }
    zone.ending_line_index
}

/// C++ `Instance::ChangeZoneCollapseState` (`Instance.cpp:1453-1488`).
///
/// Toggles the zone at `target_index`. `line` is the document line
/// the toggle was requested on: for a code zone whose
/// `start_line_index != line` this is a nested toggle and the shift
/// is deferred to the code-zone task (see
/// [`CollapseOutcome::NestedCodeZone`]). Otherwise every later zone
/// is shifted by ±`extended_size`, the target's collapse flag flips
/// and its `ending_line_index` is adjusted, and the recomputed total
/// line count is returned.
pub fn change_zone_collapse_state(
    zones: &mut [ZoneEntry],
    target_index: usize,
    line: u32,
) -> CollapseOutcome {
    let Some(target) = zones.get(target_index) else {
        return CollapseOutcome::NotFound;
    };
    let header = target.header();

    // Nested code-zone toggle → defer to CollapseOrExtendZone.
    if header.zone_type == DissasmParseZoneType::DissasmCodeParseZone
        && header.start_line_index != line
    {
        let inside_line = line
            .saturating_sub(header.start_line_index)
            .saturating_sub(2);
        return CollapseOutcome::NestedCodeZone { inside_line };
    }

    // sizeToAdjust: +extended_size when expanding (currently
    // collapsed), -extended_size when collapsing.
    let extended = header.extended_size;
    let size_to_adjust: i32 = if header.is_collapsed {
        i32::try_from(extended).unwrap_or(i32::MAX)
    } else {
        i32::try_from(extended).unwrap_or(i32::MAX).saturating_neg()
    };

    // Shift every zone after the target.
    for entry in zones.iter_mut().skip(target_index.saturating_add(1)) {
        let h = entry.header_mut();
        h.start_line_index = h.start_line_index.wrapping_add_signed(size_to_adjust);
        h.ending_line_index = h.ending_line_index.wrapping_add_signed(size_to_adjust);
    }

    // Flip the target and adjust its own ending line.
    if let Some(target) = zones.get_mut(target_index) {
        let h = target.header_mut();
        h.is_collapsed = !h.is_collapsed;
        h.ending_line_index = h.ending_line_index.wrapping_add_signed(size_to_adjust);
    }

    CollapseOutcome::Structure {
        total_lines: total_lines(zones),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissasm_viewer::zone::{
        DissasmCodeZone, DissasmParseStructureZone, ParseZone,
    };

    fn structure_entry(id: u16, start: u32, end: u32, extended: u32, collapsed: bool) -> ZoneEntry {
        let mut z = DissasmParseStructureZone::default();
        z.zone.zone_id = id;
        z.zone.start_line_index = start;
        z.zone.ending_line_index = end;
        z.zone.extended_size = extended;
        z.zone.is_collapsed = collapsed;
        ZoneEntry::Structure(z)
    }

    fn code_entry(id: u16, start: u32, end: u32) -> ZoneEntry {
        let mut z = DissasmCodeZone::default();
        z.zone.zone_id = id;
        z.zone.start_line_index = start;
        z.zone.ending_line_index = end;
        ZoneEntry::Code(Box::new(z))
    }

    #[test]
    fn get_expanded_size_recurrence() {
        // Flat struct with 3 leaf fields: 1 + 3 * (1) = 4.
        let flat = vec![
            StructureType::default(),
            StructureType::default(),
            StructureType::default(),
        ];
        assert_eq!(get_expanded_size(&flat), 4);
        // Nested: root + child(with 2 leaves) + leaf.
        let nested = vec![
            StructureType {
                name: "inner".to_owned(),
                internal_types: vec![StructureType::default(), StructureType::default()],
            },
            StructureType::default(),
        ];
        // top 1 + (1 + 2) + 1 = 5.
        assert_eq!(get_expanded_size(&nested), 5);
        // No fields → 1.
        assert_eq!(get_expanded_size(&[]), 1);
    }

    #[test]
    fn init_structure_zone_collapsed_and_expanded() {
        let mut collapsed = ParseZone::new(DissasmParseZoneType::StructureParseZone);
        // expanded_size 5 → extended_size 4; collapsed → ending = start + 1.
        let end = init_structure_zone(&mut collapsed, 10, 5, true);
        assert_eq!(collapsed.extended_size, 4);
        assert_eq!(collapsed.start_line_index, 10);
        assert_eq!(end, 11);

        let mut expanded = ParseZone::new(DissasmParseZoneType::StructureParseZone);
        // Expanded init adds extended_size to the ending line.
        let end = init_structure_zone(&mut expanded, 10, 5, false);
        assert_eq!(end, 15); // 10 + 1 + 4
    }

    #[test]
    fn expand_collapsed_structure_shifts_following_zones() {
        // zone0 collapsed (extended 4) at [0,1), zone1 [1,10), zone2 [10,20).
        let mut zones = vec![
            structure_entry(0, 0, 1, 4, true),
            structure_entry(1, 1, 10, 0, false),
            code_entry(2, 10, 20),
        ];
        // Toggle zone0 on its own start line → expand: +4.
        let outcome = change_zone_collapse_state(&mut zones, 0, 0);
        assert_eq!(outcome, CollapseOutcome::Structure { total_lines: 23 });
        // Target: start unchanged, ending += 4, now expanded.
        assert_eq!(zones[0].header().start_line_index, 0);
        assert_eq!(zones[0].header().ending_line_index, 5);
        assert!(!zones[0].header().is_collapsed);
        // Following zones shifted +4.
        assert_eq!(zones[1].header().start_line_index, 5);
        assert_eq!(zones[1].header().ending_line_index, 14);
        assert_eq!(zones[2].header().start_line_index, 14);
        assert_eq!(zones[2].header().ending_line_index, 24);
        // total = last ending - 1 = 24 - 1 = 23.
    }

    #[test]
    fn collapse_expanded_structure_shifts_negative() {
        // zone0 expanded (extended 4) at [0,5), zone1 [5,14).
        let mut zones = vec![
            structure_entry(0, 0, 5, 4, false),
            structure_entry(1, 5, 14, 0, false),
        ];
        let outcome = change_zone_collapse_state(&mut zones, 0, 0);
        // Collapse: -4. zone0 ending 5 → 1; zone1 [1,10).
        assert_eq!(zones[0].header().ending_line_index, 1);
        assert!(zones[0].header().is_collapsed);
        assert_eq!(zones[1].header().start_line_index, 1);
        assert_eq!(zones[1].header().ending_line_index, 10);
        assert_eq!(outcome, CollapseOutcome::Structure { total_lines: 9 });
    }

    #[test]
    fn toggling_middle_zone_leaves_earlier_zones_untouched() {
        let mut zones = vec![
            structure_entry(0, 0, 5, 0, false),
            structure_entry(1, 5, 6, 3, true), // collapsed, extended 3
            structure_entry(2, 6, 16, 0, false),
        ];
        change_zone_collapse_state(&mut zones, 1, 5);
        // zone0 untouched.
        assert_eq!(zones[0].header().start_line_index, 0);
        assert_eq!(zones[0].header().ending_line_index, 5);
        // zone1 expanded: ending 6 → 9.
        assert_eq!(zones[1].header().ending_line_index, 9);
        // zone2 shifted +3.
        assert_eq!(zones[2].header().start_line_index, 9);
        assert_eq!(zones[2].header().ending_line_index, 19);
    }

    #[test]
    fn nested_code_zone_toggle_is_deferred() {
        // Code zone at start line 10; toggle requested at line 15
        // (inner) → NestedCodeZone with inside_line = 15 - 10 - 2 = 3.
        let mut zones = vec![code_entry(0, 10, 30)];
        let outcome = change_zone_collapse_state(&mut zones, 0, 15);
        assert_eq!(outcome, CollapseOutcome::NestedCodeZone { inside_line: 3 });
        // No shift applied (ending unchanged).
        assert_eq!(zones[0].header().ending_line_index, 30);
        // Toggling a code zone ON its own start line takes the
        // structure path instead.
        let outcome = change_zone_collapse_state(&mut zones, 0, 10);
        assert!(matches!(outcome, CollapseOutcome::Structure { .. }));
    }

    #[test]
    fn out_of_range_target_reports_not_found() {
        let mut zones = vec![structure_entry(0, 0, 5, 0, false)];
        assert_eq!(
            change_zone_collapse_state(&mut zones, 9, 0),
            CollapseOutcome::NotFound
        );
    }
}
