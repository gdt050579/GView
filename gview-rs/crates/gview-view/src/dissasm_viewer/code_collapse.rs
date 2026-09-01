//! `DissasmViewer` nested code-zone collapse
//! (spec `02_VIEWER_DISSASM` §3.3).
//!
//! C++ anchors: `GetRecursiveZoneByLine` (`DissasmX86.cpp:1349-1393`),
//! `DissasmCodeZone::CollapseOrExtendZone` (`DissasmX86.cpp:1395-1406`).
//!
//! Collapsing a named leaf region shrinks its `index_zone_end` by
//! `working span - 1` (the collapsed view shows a single line) and
//! shifts every later sibling — including their annotation and
//! comment keys — by the same difference; expanding does the reverse.
//! `NegateCurrentState` resolves to the opposite of the region's
//! current state. Parity quirks preserved: the resolved collapse mode
//! carries over to later siblings in the same frame, a nested hit
//! only bubbles its difference into the enclosing region's end, and
//! the sibling re-key rebuilds annotations **without** their rename
//! link maps (the C++ container is reset before re-insertion).

use super::zone::{CollapseExpandType, DissasmCodeInternalType, DissasmCodeZone};

/// C++ `GetRecursiveZoneByLine` (`DissasmX86.cpp:1349-1393`).
///
/// Walks `parent`'s regions looking for the one containing `line`;
/// toggles the innermost eligible named leaf and propagates
/// `difference` (the line delta) to enclosing ends and later
/// siblings. Returns `true` when a difference was produced.
pub fn get_recursive_zone_by_line(
    parent: &mut DissasmCodeInternalType,
    line: u32,
    collapse: CollapseExpandType,
    difference: &mut i32,
) -> bool {
    let mut collapse = collapse;
    for zone in &mut parent.internal_types {
        if zone.index_zone_start <= line && line < zone.index_zone_end {
            if get_recursive_zone_by_line(zone, line, collapse, difference) {
                zone.index_zone_end = zone.index_zone_end.wrapping_add_signed(*difference);
                continue;
            }
            if !zone.internal_types.is_empty() || zone.name.is_empty() {
                return false;
            }
            if (collapse == CollapseExpandType::Collapse && zone.is_collapsed)
                || (collapse == CollapseExpandType::Expand && !zone.is_collapsed)
            {
                return false;
            }
            if collapse == CollapseExpandType::NegateCurrentState {
                collapse = if zone.is_collapsed {
                    CollapseExpandType::Expand
                } else {
                    CollapseExpandType::Collapse
                };
            }
            let span = zone
                .working_index_zone_end
                .saturating_sub(zone.working_index_zone_start)
                .saturating_sub(1);
            *difference = i32::try_from(span).unwrap_or(i32::MAX);
            if collapse == CollapseExpandType::Collapse {
                *difference = difference.saturating_neg();
            }
            zone.is_collapsed = collapse == CollapseExpandType::Collapse;
            zone.index_zone_end = zone.index_zone_end.wrapping_add_signed(*difference);
            continue;
        }
        if *difference != 0 && line < zone.index_zone_start {
            zone.index_zone_start = zone.index_zone_start.wrapping_add_signed(*difference);
            zone.index_zone_end = zone.index_zone_end.wrapping_add_signed(*difference);
            zone.annotations
                .shift_mappings_dropping_name_links(*difference);
            zone.comments_data.shift_stored_keys(*difference);
        }
    }
    *difference != 0
}

/// C++ `DissasmCodeZone::CollapseOrExtendZone`
/// (`DissasmX86.cpp:1395-1406`).
///
/// Runs the recursive toggle on the zone's root region and, when
/// lines changed, returns the difference biased by the root's
/// `index_zone_end - 1` (the C++ out-parameter); `None` when no
/// region could be toggled.
pub fn collapse_or_extend_zone(
    zone: &mut DissasmCodeZone,
    zone_line: u32,
    collapse: CollapseExpandType,
) -> Option<i32> {
    let mut difference = 0_i32;
    if !get_recursive_zone_by_line(&mut zone.dissasm_type, zone_line, collapse, &mut difference) {
        return None;
    }
    if difference != 0 {
        let root_end = i32::try_from(zone.dissasm_type.index_zone_end).unwrap_or(i32::MAX);
        difference = difference.saturating_add(root_end.saturating_sub(1));
    }
    Some(difference)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str, start: u32, end: u32) -> DissasmCodeInternalType {
        DissasmCodeInternalType {
            name: name.to_owned(),
            index_zone_start: start,
            index_zone_end: end,
            working_index_zone_start: start,
            working_index_zone_end: end,
            ..DissasmCodeInternalType::default()
        }
    }

    /// Root [0,100) with leaf regions fnA [10,30) and fnB [40,60);
    /// fnB carries an annotation at 45 and a comment at display line
    /// 50 (stored key 49).
    fn zone_fixture() -> DissasmCodeZone {
        let mut root = region("", 0, 100);
        let mut fn_b = region("fnB", 40, 60);
        fn_b.annotations
            .mappings
            .insert(45, ("sub_0x00000002d".to_owned(), 0x2d));
        fn_b.annotations.add_initial_name("sub_0x00000002d");
        fn_b.comments_data
            .add_or_update_comment(50, "note".to_owned());
        root.internal_types = vec![region("fnA", 10, 30), fn_b];
        DissasmCodeZone {
            dissasm_type: root,
            ..DissasmCodeZone::default()
        }
    }

    #[test]
    fn negate_current_state_collapses_then_expands() {
        let mut zone = zone_fixture();
        // Collapse fnA (line 15 inside it): difference = -(20 - 1).
        let diff = collapse_or_extend_zone(&mut zone, 15, CollapseExpandType::NegateCurrentState);
        assert_eq!(diff, Some(-19 + 99)); // biased by root end - 1
        let fn_a = &zone.dissasm_type.internal_types[0];
        assert!(fn_a.is_collapsed);
        assert_eq!(fn_a.index_zone_end, 11);
        assert_eq!(fn_a.working_index_zone_end, 30); // working span kept
        // Toggle again on the collapsed line → expand back.
        let diff = collapse_or_extend_zone(&mut zone, 10, CollapseExpandType::NegateCurrentState);
        assert_eq!(diff, Some(19 + 99));
        let fn_a = &zone.dissasm_type.internal_types[0];
        assert!(!fn_a.is_collapsed);
        assert_eq!(fn_a.index_zone_end, 30);
    }

    #[test]
    fn difference_propagates_to_later_siblings_and_rekeys() {
        let mut zone = zone_fixture();
        collapse_or_extend_zone(&mut zone, 15, CollapseExpandType::Collapse);
        let fn_b = &zone.dissasm_type.internal_types[1];
        // fnB shifted up by 19.
        assert_eq!((fn_b.index_zone_start, fn_b.index_zone_end), (21, 41));
        // Annotation re-keyed 45 → 26; rename link maps dropped
        // (C++ resets the container before re-inserting mappings).
        assert!(fn_b.annotations.mappings.contains_key(&26));
        assert!(!fn_b.annotations.mappings.contains_key(&45));
        assert!(fn_b.annotations.initial_name_to_current_name.is_empty());
        // Comment stored key 49 → 30, i.e. display line 31.
        assert_eq!(fn_b.comments_data.get_comment(31), Some("note"));
        assert_eq!(fn_b.comments_data.get_comment(50), None);
        // Expanding restores the original keys.
        collapse_or_extend_zone(&mut zone, 10, CollapseExpandType::Expand);
        let fn_b = &zone.dissasm_type.internal_types[1];
        assert_eq!((fn_b.index_zone_start, fn_b.index_zone_end), (40, 60));
        assert!(fn_b.annotations.mappings.contains_key(&45));
        assert_eq!(fn_b.comments_data.get_comment(50), Some("note"));
    }

    #[test]
    fn explicit_modes_reject_no_op_and_unnamed_regions() {
        let mut zone = zone_fixture();
        // Expand on an already-expanded region → false.
        assert_eq!(
            collapse_or_extend_zone(&mut zone, 15, CollapseExpandType::Expand),
            None
        );
        // Collapse twice: second is a no-op.
        assert!(collapse_or_extend_zone(&mut zone, 15, CollapseExpandType::Collapse).is_some());
        assert_eq!(
            collapse_or_extend_zone(&mut zone, 10, CollapseExpandType::Collapse),
            None
        );
        // A line outside every region → nothing toggled.
        assert_eq!(
            collapse_or_extend_zone(&mut zone, 5, CollapseExpandType::NegateCurrentState),
            None
        );
        // Unnamed regions cannot collapse.
        let mut unnamed = zone_fixture();
        unnamed.dissasm_type.internal_types[0].name.clear();
        assert_eq!(
            collapse_or_extend_zone(&mut unnamed, 15, CollapseExpandType::Collapse),
            None
        );
    }

    #[test]
    fn nested_hit_bubbles_difference_into_enclosing_region() {
        // outer [10,60) containing inner "fnI" [20,30); sibling "fnS" [70,80).
        let mut root = region("", 0, 100);
        let mut outer = region("outer", 10, 60);
        outer.internal_types = vec![region("fnI", 20, 30)];
        root.internal_types = vec![outer, region("fnS", 70, 80)];
        let mut zone = DissasmCodeZone {
            dissasm_type: root,
            ..DissasmCodeZone::default()
        };
        let diff = collapse_or_extend_zone(&mut zone, 25, CollapseExpandType::Collapse);
        assert_eq!(diff, Some(-9 + 99));
        let outer = &zone.dissasm_type.internal_types[0];
        assert_eq!(outer.index_zone_end, 51); // enclosing end shrinks by 9
        assert!(!outer.is_collapsed); // outer itself untouched
        assert_eq!(outer.internal_types[0].index_zone_end, 21);
        let sibling = &zone.dissasm_type.internal_types[1];
        assert_eq!((sibling.index_zone_start, sibling.index_zone_end), (61, 71));
    }
}
