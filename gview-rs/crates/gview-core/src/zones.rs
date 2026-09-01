//! Colored zone intervals (C++ `GView::Utils::ZonesList` parity,
//! `ZonesList.cpp`, `GView.hpp:204-218`).
//!
//! Zones are **inclusive** intervals `[low, high]` used to color
//! regions of a file. `set_viewport_cache` pre-filters the zones that
//! overlap the visible viewport so the paint loop scans a short list.

use appcui::graphics::CharAttribute;

/// One colored interval; bounds are inclusive
/// (C++ `Utils::Zone`: `interval`, `color`, `name`).
#[derive(Clone, Debug)]
pub struct Zone {
    /// Inclusive interval start.
    pub low: u64,
    /// Inclusive interval end.
    pub high: u64,
    /// Paint color for the zone (C++ `ColorPair`).
    pub color: CharAttribute,
    /// Display name (C++ `FixSizeString<25>` caps it at 25 chars).
    pub name: String,
}

/// Zone collection plus the viewport paint cache
/// (C++ `ZonesList` with its `zones` / `cache` vectors).
#[derive(Default)]
pub struct ZonesList {
    zones: Vec<Zone>,
    viewport_cache: Vec<Zone>,
}

impl ZonesList {
    /// Empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a zone spanning `[low, high]` (C++ `Add`,
    /// `ZonesList.cpp:23-29`). Does **not** rebuild the viewport
    /// cache.
    pub fn add(&mut self, low: u64, high: u64, color: CharAttribute, name: impl Into<String>) {
        self.zones.push(Zone {
            low,
            high,
            color,
            name: name.into(),
        });
    }

    /// Appends a copy of `zone` (C++ `Add(const Zone&)`).
    pub fn add_zone(&mut self, zone: Zone) {
        self.zones.push(zone);
    }

    /// Appends a zone from `(start, size)` — `[start, start + size - 1]`
    /// with checked arithmetic; `size == 0` is a no-op (C++
    /// `BufferViewer::Settings::AddZone`, `Settings.cpp:27-32`; spec
    /// §6.5).
    pub fn add_sized(
        &mut self,
        start: u64,
        size: u64,
        color: CharAttribute,
        name: impl Into<String>,
    ) {
        let Some(high) = start.checked_add(size).and_then(|e| e.checked_sub(1)) else {
            return;
        };
        if size == 0 {
            return;
        }
        self.add(start, high, color, name);
    }

    /// Clears both the zone list and the viewport cache
    /// (C++ `Clear`).
    pub fn clear(&mut self) {
        self.zones.clear();
        self.viewport_cache.clear();
    }

    /// Number of zones added (C++ `GetCount`).
    #[must_use]
    pub const fn count(&self) -> usize {
        self.zones.len()
    }

    /// Zone by insertion index (C++ `GetZone`).
    #[must_use]
    pub fn zone(&self, index: usize) -> Option<&Zone> {
        self.zones.get(index)
    }

    /// Rebuilds the paint cache with the zones overlapping the
    /// inclusive viewport `[viewport.0, viewport.1]`, then sorts it by
    /// `low` **descending**, ties by `high` **ascending** (C++
    /// `SetCache`, `ZonesList.cpp:53-75`; spec §6.2).
    pub fn set_viewport_cache(&mut self, viewport: (u64, u64)) {
        let (view_low, view_high) = viewport;
        self.viewport_cache.clear();
        for zone in &self.zones {
            if (zone.low >= view_low && zone.low <= view_high)
                || (view_low >= zone.low && view_low <= zone.high)
            {
                self.viewport_cache.push(zone.clone());
            }
        }
        self.viewport_cache.sort_by(|a, b| {
            if a.low == b.low {
                a.high.cmp(&b.high)
            } else {
                b.low.cmp(&a.low)
            }
        });
    }

    /// First zone in the **viewport cache** containing `position`
    /// (post-sort order; first hit wins). Requires a prior
    /// [`Self::set_viewport_cache`] call — zones outside the cached
    /// viewport are never found (C++ `OffsetToZone`,
    /// `ZonesList.cpp:39-51`; spec §6.3).
    #[must_use]
    pub fn offset_to_zone(&self, position: u64) -> Option<&Zone> {
        self.viewport_cache
            .iter()
            .find(|zone| zone.low <= position && position <= zone.high)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(id: u8) -> CharAttribute {
        // Distinct attributes so tests can tell zones apart.
        use appcui::graphics::Color;
        let fore = if id == 1 { Color::Red } else { Color::Green };
        CharAttribute::with_color(fore, Color::Black)
    }

    fn list_with(zones: &[(u64, u64, &str)]) -> ZonesList {
        let mut list = ZonesList::new();
        for &(low, high, name) in zones {
            list.add(low, high, attr(0), name);
        }
        list
    }

    #[test]
    fn add_and_lookup_basics() {
        let mut list = list_with(&[(0, 9, "a"), (20, 29, "b")]);
        assert_eq!(list.count(), 2);
        assert_eq!(list.zone(0).map(|z| z.name.as_str()), Some("a"));
        assert_eq!(list.zone(2).map(|z| z.name.as_str()), None);
        list.clear();
        assert_eq!(list.count(), 0);
    }

    #[test]
    fn viewport_overlap_filter() {
        // Viewport [10, 20]: keep zones overlapping it, drop the rest.
        let mut list = list_with(&[
            (0, 5, "before"),       // entirely before → dropped
            (5, 15, "cross-low"),   // crosses viewport start → kept
            (12, 18, "inside"),     // inside → kept
            (15, 25, "cross-high"), // crosses viewport end → kept
            (5, 25, "envelops"),    // envelops viewport → kept
            (21, 30, "after"),      // entirely after → dropped
        ]);
        list.set_viewport_cache((10, 20));
        // "before" is not cached.
        assert!(list.offset_to_zone(3).is_none());
        // Position 22 is inside "cross-high" [15,25] and "envelops"
        // [5,25]; sort order (low desc) puts cross-high first.
        assert!(list
            .offset_to_zone(22)
            .is_some_and(|z| z.name == "cross-high"));
        // Position 8 is only inside "envelops" [5,25] among cached
        // zones ("cross-low" [5,15] also matches; low tie 5, high asc
        // puts cross-low first).
        assert!(list
            .offset_to_zone(8)
            .is_some_and(|z| z.name == "cross-low"));
        assert!(list.offset_to_zone(13).is_some());
        // "after" is not in the cache even where it overlaps nothing.
        assert!(list.offset_to_zone(28).is_none());
    }

    #[test]
    fn cache_sort_low_desc_high_asc() {
        let mut list = list_with(&[
            (10, 40, "wide"),
            (30, 35, "mid"),
            (30, 32, "midshort"),
            (20, 25, "low20"),
        ]);
        list.set_viewport_cache((0, 100));
        // Expected order: low desc → 30,30,20,10; tie at 30 → high asc
        // → (30,32) before (30,35).
        let cached: Vec<(u64, u64)> = list
            .viewport_cache
            .iter()
            .map(|z| (z.low, z.high))
            .collect();
        assert_eq!(cached, vec![(30, 32), (30, 35), (20, 25), (10, 40)]);
    }

    #[test]
    fn offset_to_zone_first_hit_wins() {
        // Overlapping zones: post-sort order decides the winner.
        let mut list = list_with(&[(0, 100, "outer"), (40, 60, "inner")]);
        list.set_viewport_cache((0, 100));
        // Sort: low desc → inner (40) before outer (0). Position 50 is
        // in both; the first cache entry (inner) wins.
        assert_eq!(
            list.offset_to_zone(50).map(|z| z.name.as_str()),
            Some("inner")
        );
        assert_eq!(
            list.offset_to_zone(10).map(|z| z.name.as_str()),
            Some("outer")
        );
        assert!(list.offset_to_zone(101).is_none());
    }

    #[test]
    fn add_does_not_rebuild_cache() {
        let mut list = list_with(&[(0, 10, "a")]);
        list.set_viewport_cache((0, 100));
        assert!(list.offset_to_zone(5).is_some());
        // New zone appended after SetCache is invisible to lookups
        // until the next set_viewport_cache (C++ parity).
        list.add(20, 30, attr(1), "late");
        assert!(list.offset_to_zone(25).is_none());
        list.set_viewport_cache((0, 100));
        assert!(list.offset_to_zone(25).is_some());
    }

    #[test]
    fn add_sized_semantics() {
        let mut list = ZonesList::new();
        list.add_sized(10, 5, attr(0), "z"); // [10, 14]
        list.add_sized(10, 0, attr(0), "noop"); // size 0 → no-op
        list.add_sized(u64::MAX, 5, attr(0), "overflow"); // overflow → no-op
        assert_eq!(list.count(), 1);
        let zone = list.zone(0).expect("zone");
        assert_eq!((zone.low, zone.high), (10, 14));
    }
}
