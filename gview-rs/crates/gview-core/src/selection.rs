//! Selection zones (C++ `GView::Utils::Selection` parity,
//! `Selection.cpp`, `Internal.hpp:20-25`).
//!
//! Up to [`MAX_SELECTION_ZONES`] closed intervals `[start, end]` in
//! file coordinates. A zone is empty when `start == INVALID_OFFSET`.
//! Mode is single (only zone 0 usable) or multi (all four).

use crate::constants::{INVALID_OFFSET, MAX_SELECTION_ZONES};

/// One selection interval; all offsets are inclusive.
///
/// `original_point` is the anchor from which drags grow
/// (C++ `originalPoint`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionZone {
    /// Inclusive interval start; `INVALID_OFFSET` marks an empty zone.
    pub start: u64,
    /// Inclusive interval end.
    pub end: u64,
    /// Drag anchor.
    pub original_point: u64,
}

impl Default for SelectionZone {
    fn default() -> Self {
        Self {
            start: INVALID_OFFSET,
            end: INVALID_OFFSET,
            original_point: INVALID_OFFSET,
        }
    }
}

/// Selection state: four zones plus the single/multi mode flag.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    zones: [SelectionZone; MAX_SELECTION_ZONES],
    multi_mode: bool,
}

impl Selection {
    /// All zones empty, single-selection mode
    /// (C++ ctor, `Selection.cpp:5-14`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when in multi-zone mode (C++ `IsMultiSelectionEnabled`).
    #[must_use]
    pub const fn is_multi_selection_enabled(&self) -> bool {
        self.multi_mode
    }

    /// Number of zone slots — always [`MAX_SELECTION_ZONES`]
    /// (C++ `GetCount`).
    #[must_use]
    pub const fn count(&self) -> usize {
        MAX_SELECTION_ZONES
    }

    /// Empties every zone by resetting **only** `start`; `end` and
    /// `original_point` keep their stale values (C++ `Clear()`,
    /// `Selection.cpp:15-19` — intentional parity).
    pub fn clear(&mut self) {
        for zone in &mut self.zones {
            zone.start = INVALID_OFFSET;
        }
    }

    /// Empties one zone (`start` only, like [`Self::clear`]); `false`
    /// for an out-of-range index (C++ `Clear(int)`).
    pub fn clear_zone(&mut self, index: usize) -> bool {
        let Some(zone) = self.zones.get_mut(index) else {
            return false;
        };
        zone.start = INVALID_OFFSET;
        true
    }

    /// `true` if `zones[index]` holds a selection
    /// (C++ `HasSelection`).
    #[must_use]
    pub fn has_selection(&self, index: usize) -> bool {
        self.zones
            .get(index)
            .is_some_and(|z| z.start != INVALID_OFFSET)
    }

    /// `true` if any zone holds a selection (C++ `HasAnySelection`).
    #[must_use]
    pub fn has_any_selection(&self) -> bool {
        self.zones.iter().any(|z| z.start != INVALID_OFFSET)
    }

    /// Returns `(start, end)` (inclusive) of `zones[index]`, or `None`
    /// for an out-of-range index, an empty zone, or `index > 0` in
    /// single mode (C++ `GetSelection`, `Selection.cpp:31-46`).
    #[must_use]
    pub fn get_selection(&self, index: usize) -> Option<(u64, u64)> {
        if !self.multi_mode && index > 0 {
            return None;
        }
        let zone = self.zones.get(index)?;
        if zone.start == INVALID_OFFSET {
            return None;
        }
        Some((zone.start, zone.end))
    }

    /// Starts (or resizes) a selection at `position`, returning the
    /// zone index used, or `None` when every zone is occupied and
    /// `position` falls outside all of them (C++ `BeginSelection`,
    /// `Selection.cpp:138-179`).
    ///
    /// Single mode: clicking inside the current zone moves its `end`
    /// in place (anchor unchanged); anywhere else restarts zone 0 as
    /// a point selection.
    ///
    /// Multi mode: clicking inside an occupied zone resizes it
    /// (anchor unchanged, does **not** update `original_point`);
    /// otherwise the lowest-index free slot becomes a new point
    /// selection.
    pub fn begin_selection(&mut self, position: u64) -> Option<usize> {
        if !self.multi_mode {
            let zone = self.zones.first_mut()?;
            if position >= zone.start && position <= zone.end && zone.start != INVALID_OFFSET {
                zone.end = position;
                return Some(0);
            }
            // A totally new selection.
            zone.start = position;
            zone.original_point = position;
            zone.end = position;
            return Some(0);
        }
        // Multi mode: find the lowest free slot while scanning for a
        // zone containing `position`.
        let mut free: Option<usize> = None;
        for (index, zone) in self.zones.iter_mut().enumerate() {
            if zone.start == INVALID_OFFSET {
                if free.is_none() {
                    free = Some(index);
                }
                continue;
            }
            if position >= zone.start && position <= zone.end {
                zone.end = position;
                return Some(index);
            }
        }
        if let Some(index) = free {
            if let Some(zone) = self.zones.get_mut(index) {
                zone.start = position;
                zone.original_point = position;
                zone.end = position;
            }
            return Some(index);
        }
        None
    }

    /// Grows/shrinks `zones[index]` so it spans between its anchor and
    /// `position`, keeping `start <= end`; `false` for an out-of-range
    /// index or `index > 0` in single mode (C++ `UpdateSelection`,
    /// `Selection.cpp:116-137`).
    pub fn update_selection(&mut self, index: usize, position: u64) -> bool {
        if !self.multi_mode && index > 0 {
            return false;
        }
        let Some(zone) = self.zones.get_mut(index) else {
            return false;
        };
        if position < zone.original_point {
            zone.start = position;
            zone.end = zone.original_point;
        } else {
            zone.start = zone.original_point;
            zone.end = position;
        }
        true
    }

    /// Returns `(index, start, end)` of the first zone containing
    /// `position`, scanning in index order — first match wins, no
    /// overlap resolution (C++ `OffsetToSelection`,
    /// `Selection.cpp:75-100`; C++ returns `-1` → `None`).
    ///
    /// Like C++, no explicit emptiness check: an empty zone cannot
    /// match because `position >= INVALID_OFFSET` requires
    /// `position == u64::MAX`.
    #[must_use]
    pub fn offset_to_selection(&self, position: u64) -> Option<(usize, u64, u64)> {
        if !self.multi_mode {
            let zone = self.zones.first()?;
            if position >= zone.start && position <= zone.end {
                return Some((0, zone.start, zone.end));
            }
            return None;
        }
        for (index, zone) in self.zones.iter().enumerate() {
            if position >= zone.start && position <= zone.end {
                return Some((index, zone.start, zone.end));
            }
        }
        None
    }

    /// `true` if any active zone contains `position`
    /// (C++ `Contains`, `Selection.cpp:101-115`).
    #[must_use]
    pub fn contains(&self, position: u64) -> bool {
        if !self.multi_mode {
            return self
                .zones
                .first()
                .is_some_and(|z| position >= z.start && position <= z.end);
        }
        self.zones
            .iter()
            .any(|z| position >= z.start && position <= z.end)
    }

    /// Sets `zones[index]` to span `[start, end]` (normalized so
    /// `start <= end`), anchoring at `start`; `false` for an invalid
    /// index, `index > 0` in single mode, or an `INVALID_OFFSET`
    /// bound (C++ `SetSelection`, `Selection.cpp:180-199`).
    pub fn set_selection(&mut self, index: usize, start: u64, end: u64) -> bool {
        if !self.multi_mode && index > 0 {
            return false;
        }
        if start == INVALID_OFFSET || end == INVALID_OFFSET {
            return false;
        }
        let Some(zone) = self.zones.get_mut(index) else {
            return false;
        };
        zone.original_point = start;
        if start <= end {
            zone.start = start;
            zone.end = end;
        } else {
            zone.start = end;
            zone.end = start;
        }
        true
    }

    /// Switches between single and multi mode (C++
    /// `EnableMultiSelection`, `Selection.cpp:47-73`).
    ///
    /// Single → multi fully clears zones 1..3; multi → single fully
    /// clears all zones. Same-mode calls are no-ops.
    pub fn enable_multi_selection(&mut self, enable: bool) {
        if !self.multi_mode && enable {
            for zone in self.zones.iter_mut().skip(1) {
                *zone = SelectionZone::default();
            }
            self.multi_mode = true;
        } else if self.multi_mode && !enable {
            for zone in &mut self.zones {
                *zone = SelectionZone::default();
            }
            self.multi_mode = false;
        }
    }

    /// Toggles the mode (C++ `InvertMultiSelectionMode`).
    pub fn invert_multi_selection_mode(&mut self) {
        self.enable_multi_selection(!self.multi_mode);
    }

    /// `"Offset:0x{start}  Size:0x{size}"` for an active zone,
    /// `"NO SELECTION"` for an empty/unreachable one, `""` for an
    /// out-of-range index (C++ `GetStringRepresentation`,
    /// `Selection.cpp:201-215`).
    #[must_use]
    pub fn string_representation(&self, index: usize) -> String {
        let Some(zone) = self.zones.get(index) else {
            return String::new();
        };
        if zone.start == INVALID_OFFSET || (!self.multi_mode && index > 0) {
            return "NO SELECTION".to_owned();
        }
        let size = zone.end.saturating_sub(zone.start).saturating_add(1);
        format!("Offset:0x{:X}  Size:0x{:X}", zone.start, size)
    }
}

#[cfg(test)]
mod single {
    use super::*;

    #[test]
    fn new_is_empty_single_mode() {
        let sel = Selection::new();
        assert!(!sel.is_multi_selection_enabled());
        assert_eq!(sel.count(), MAX_SELECTION_ZONES);
        assert!(!sel.has_any_selection());
        for i in 0..MAX_SELECTION_ZONES {
            assert!(!sel.has_selection(i));
            assert_eq!(sel.get_selection(i), None);
        }
    }

    #[test]
    fn begin_creates_new_point_zone() {
        let mut sel = Selection::new();
        assert_eq!(sel.begin_selection(100), Some(0));
        assert_eq!(sel.get_selection(0), Some((100, 100)));
        assert!(sel.has_selection(0));
    }

    #[test]
    fn begin_inside_resizes_in_place() {
        let mut sel = Selection::new();
        assert!(sel.set_selection(0, 100, 200));
        // Position inside [100, 200]: end moves, anchor stays at 100.
        assert_eq!(sel.begin_selection(150), Some(0));
        assert_eq!(sel.get_selection(0), Some((100, 150)));
        // Anchor unchanged: an update drags relative to 100.
        assert!(sel.update_selection(0, 50));
        assert_eq!(sel.get_selection(0), Some((50, 100)));
    }

    #[test]
    fn begin_outside_restarts_zone() {
        let mut sel = Selection::new();
        assert!(sel.set_selection(0, 100, 200));
        assert_eq!(sel.begin_selection(500), Some(0));
        assert_eq!(sel.get_selection(0), Some((500, 500)));
    }

    #[test]
    fn empty_zone_never_matches_begin_resize() {
        // start == INVALID_OFFSET forces the "new selection" branch
        // even though position <= end could hold for stale end.
        let mut sel = Selection::new();
        assert!(sel.set_selection(0, 100, 200));
        assert!(sel.clear_zone(0)); // start = INVALID, end stale = 200
        assert_eq!(sel.begin_selection(150), Some(0));
        assert_eq!(sel.get_selection(0), Some((150, 150)));
    }

    #[test]
    fn index_above_zero_rejected_in_single_mode() {
        let mut sel = Selection::new();
        assert!(!sel.update_selection(1, 5));
        assert!(!sel.set_selection(1, 0, 5));
        assert_eq!(sel.get_selection(1), None);
        assert_eq!(sel.string_representation(1), "NO SELECTION");
    }

    #[test]
    fn clear_resets_start_only() {
        let mut sel = Selection::new();
        assert!(sel.set_selection(0, 10, 20));
        sel.clear();
        assert!(!sel.has_selection(0));
        assert_eq!(sel.get_selection(0), None);
        assert!(!sel.has_any_selection());
    }

    #[test]
    fn string_representation_formats() {
        let mut sel = Selection::new();
        assert_eq!(sel.string_representation(0), "NO SELECTION");
        assert!(sel.set_selection(0, 0x10, 0x1F));
        assert_eq!(sel.string_representation(0), "Offset:0x10  Size:0x10");
        assert_eq!(sel.string_representation(99), "");
    }
}

#[cfg(test)]
mod multi {
    use super::*;

    fn multi_selection() -> Selection {
        let mut sel = Selection::new();
        sel.enable_multi_selection(true);
        sel
    }

    #[test]
    fn four_zone_ring_then_full() {
        let mut sel = multi_selection();
        // Four disjoint selections fill slots 0..3 in order.
        assert_eq!(sel.begin_selection(100), Some(0));
        assert_eq!(sel.begin_selection(200), Some(1));
        assert_eq!(sel.begin_selection(300), Some(2));
        assert_eq!(sel.begin_selection(400), Some(3));
        // All full and position outside every zone → None (C++ -1).
        assert_eq!(sel.begin_selection(500), None);
        // Inside an existing zone: resizes that zone instead.
        assert!(sel.update_selection(1, 250)); // zone 1 = [200, 250]
        assert_eq!(sel.begin_selection(240), Some(1));
        assert_eq!(sel.get_selection(1), Some((200, 240)));
    }

    #[test]
    fn begin_reuses_lowest_free_slot() {
        let mut sel = multi_selection();
        assert_eq!(sel.begin_selection(100), Some(0));
        assert_eq!(sel.begin_selection(200), Some(1));
        assert_eq!(sel.begin_selection(300), Some(2));
        assert!(sel.clear_zone(1));
        // Lowest free slot (1) wins for a new selection.
        assert_eq!(sel.begin_selection(999), Some(1));
        assert_eq!(sel.get_selection(1), Some((999, 999)));
    }

    #[test]
    fn drag_protocol_begin_then_update() {
        let mut sel = multi_selection();
        assert_eq!(sel.begin_selection(100), Some(0));
        // Drag right: [anchor, pos].
        assert!(sel.update_selection(0, 150));
        assert_eq!(sel.get_selection(0), Some((100, 150)));
        // Drag left past the anchor: [pos, anchor].
        assert!(sel.update_selection(0, 40));
        assert_eq!(sel.get_selection(0), Some((40, 100)));
        // Back to the anchor itself.
        assert!(sel.update_selection(0, 100));
        assert_eq!(sel.get_selection(0), Some((100, 100)));
    }

    #[test]
    fn update_selection_invalid_index() {
        let mut sel = multi_selection();
        assert!(!sel.update_selection(MAX_SELECTION_ZONES, 5));
    }

    #[test]
    fn offset_to_selection_first_match_wins() {
        let mut sel = multi_selection();
        assert!(sel.set_selection(0, 100, 200));
        assert!(sel.set_selection(1, 150, 300)); // overlaps zone 0
        assert_eq!(sel.offset_to_selection(175), Some((0, 100, 200)));
        assert_eq!(sel.offset_to_selection(250), Some((1, 150, 300)));
        assert_eq!(sel.offset_to_selection(400), None);
        assert!(sel.contains(175));
        assert!(!sel.contains(400));
    }

    #[test]
    fn mode_switch_clears_per_spec() {
        // Single → multi clears zones 1..3 (zone 0 preserved).
        let mut sel = Selection::new();
        assert!(sel.set_selection(0, 10, 20));
        sel.enable_multi_selection(true);
        assert_eq!(sel.get_selection(0), Some((10, 20)));
        assert!(sel.set_selection(1, 30, 40));
        // Multi → single clears everything.
        sel.enable_multi_selection(false);
        assert!(!sel.has_any_selection());
        assert!(!sel.is_multi_selection_enabled());
    }

    #[test]
    fn invert_mode_round_trip() {
        let mut sel = Selection::new();
        sel.invert_multi_selection_mode();
        assert!(sel.is_multi_selection_enabled());
        sel.invert_multi_selection_mode();
        assert!(!sel.is_multi_selection_enabled());
    }

    #[test]
    fn set_selection_normalizes_and_validates() {
        let mut sel = multi_selection();
        assert!(sel.set_selection(2, 300, 100)); // reversed bounds
        assert_eq!(sel.get_selection(2), Some((100, 300)));
        // Anchor is the `start` argument (300): dragging to 400 grows
        // from 300.
        assert!(sel.update_selection(2, 400));
        assert_eq!(sel.get_selection(2), Some((300, 400)));
        assert!(!sel.set_selection(2, INVALID_OFFSET, 5));
        assert!(!sel.set_selection(2, 5, INVALID_OFFSET));
        assert!(!sel.set_selection(MAX_SELECTION_ZONES, 1, 2));
    }
}
