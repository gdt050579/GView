//! `BufferViewer` color resolution.
//!
//! C++ anchors: `Instance::OffsetToColor` (`Instance.cpp:530-614`),
//! `UpdateStringInfo` (`Instance.cpp:412-503`), `DefaultAsciiMask`
//! (`Instance.cpp:19-32`); spec `02_VIEWER_BUFFER` §4.3–4.5.
//! Priority (spec §4.3): 1 selection similarity → 2 object zones →
//! 3 buffer-color callback → 4 position-to-color callback →
//! 5 string highlight → 6 plugin zones; step 7 (selection paint
//! override) is applied by the paint stage **after** `OffsetToColor`
//! via [`apply_selection_override`].

use appcui::graphics::CharAttribute;
use gview_core::cache::DataCache;
use gview_core::constants::INVALID_OFFSET;
use gview_core::selection::Selection;
use gview_core::zones::ZonesList;

use crate::view_control::ViewData;

/// Default printable mask (C++ `DefaultAsciiMask`,
/// `Instance.cpp:19-32`): TAB (9), `0x20..=0x5F`, `0x61..=0x7E`.
///
/// **Spec discrepancy (C++ wins):** spec §4.5 claims 0x7F is allowed
/// and the whole `0x20..0x7E` range is included; the C++ table
/// excludes backtick (0x60) and 0x7F.
#[must_use]
// Loop index bounded by 0x20..=0x7E — cannot overflow.
#[allow(clippy::arithmetic_side_effects)]
pub const fn default_ascii_mask() -> [bool; 256] {
    let mut mask = [false; 256];
    mask[9] = true; // TAB
    let mut i = 0x20_usize;
    while i <= 0x7E {
        mask[i] = i != 0x60; // backtick excluded in C++
        i += 1;
    }
    mask
}

/// Theme colors consumed by the resolver (subset of C++ `Cfg` +
/// `config.Colors`).
#[derive(Clone, Copy, Debug)]
pub struct ColorConfig {
    /// `Cfg.Selection.SimilarText`.
    pub similar_text: CharAttribute,
    /// `Cfg.Text.Inactive`.
    pub inactive: CharAttribute,
    /// `config.Colors.Ascii` (Red on `DarkBlue` in C++).
    pub ascii: CharAttribute,
    /// `config.Colors.Unicode` (Yellow on `DarkBlue` in C++).
    pub unicode: CharAttribute,
    /// `Cfg.Selection.Editor` — the paint-stage override.
    pub selection_editor: CharAttribute,
}

/// Kind of string run under the cursor (C++ `StringType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringType {
    /// No string at the cached range.
    None,
    /// ASCII run.
    Ascii,
    /// UTF-16 (Latin subset) run.
    Unicode,
}

/// Cached string-run state (C++ `StringInfo`).
pub struct StringInfo {
    /// Run start offset (inclusive).
    pub start: u64,
    /// Run end offset (exclusive).
    pub end: u64,
    /// Unicode only: `start + code-unit count`.
    pub middle: u64,
    /// Kind of the cached run.
    pub string_type: StringType,
    /// Highlight ASCII strings.
    pub show_ascii: bool,
    /// Highlight UTF-16 strings.
    pub show_unicode: bool,
    /// Minimum run length (C++ default 4).
    pub min_count: usize,
    /// Which byte values count as string characters.
    pub ascii_mask: [bool; 256],
}

impl Default for StringInfo {
    fn default() -> Self {
        Self {
            start: INVALID_OFFSET,
            end: INVALID_OFFSET,
            middle: INVALID_OFFSET,
            string_type: StringType::None,
            show_ascii: true,
            show_unicode: true,
            min_count: 4,
            ascii_mask: default_ascii_mask(),
        }
    }
}

impl StringInfo {
    fn masked(&self, byte: u8) -> bool {
        self.ascii_mask.get(byte as usize).copied().unwrap_or(false)
    }

    fn u16_at(bytes: &[u8], index: usize) -> Option<u16> {
        let lo = *bytes.get(index)?;
        let hi = *bytes.get(index.checked_add(1)?)?;
        Some(u16::from_le_bytes([lo, hi]))
    }

    fn masked_u16(&self, unit: u16) -> bool {
        unit < 256 && self.masked(unit as u8)
    }

    /// Clears the cached run (C++ `ResetStringInfo`).
    pub const fn reset(&mut self) {
        self.start = INVALID_OFFSET;
        self.end = INVALID_OFFSET;
        self.middle = INVALID_OFFSET;
        self.string_type = StringType::None;
    }

    /// Re-scans a 1024-byte window at `offset`
    /// (C++ `UpdateStringInfo`, `Instance.cpp:412-503` — ported
    /// index-for-pointer).
    #[allow(clippy::arithmetic_side_effects)] // indices bounded by len <= 1024
    pub fn update(&mut self, cache: &mut DataCache, offset: u64) {
        let Ok(buf) = cache.get(offset, 1024, false) else {
            self.reset();
            return;
        };
        let bytes: &[u8] = buf;
        let len = bytes.len();

        // ASCII run at the window start.
        if self.show_ascii && bytes.first().is_some_and(|&b| self.masked(b)) {
            let mut i = 0_usize;
            while i < len && bytes.get(i).is_some_and(|&b| self.masked(b)) {
                i += 1;
            }
            if i >= self.min_count {
                self.start = offset;
                self.end = offset.saturating_add(i as u64);
                self.string_type = StringType::Ascii;
                return;
            }
        }

        // UTF-16 (Latin subset) run at the window start.
        if self.show_unicode {
            let units = len / 2;
            let mut n = 0_usize;
            while n < units && Self::u16_at(bytes, n * 2).is_some_and(|u| self.masked_u16(u)) {
                n += 1;
            }
            if n >= self.min_count {
                self.start = offset;
                self.end = offset.saturating_add((n * 2) as u64);
                self.middle = offset.saturating_add(n as u64);
                self.string_type = StringType::Unicode;
                return;
            }
        }

        // Non-string gap: find where the next possible string starts.
        self.start = offset;
        self.middle = INVALID_OFFSET;
        self.string_type = StringType::None;

        let mut s = 0_usize;
        while s < len {
            while s < len && !bytes.get(s).is_some_and(|&b| self.masked(b)) {
                s += 1;
            }
            if s == len {
                break;
            }
            // Possible ASCII string of at least min_count?
            let mut s_s = s;
            let s_e = s + self.min_count;
            if s_e <= len {
                while s_s < s_e && bytes.get(s_s).is_some_and(|&b| self.masked(b)) {
                    s_s += 1;
                }
                if s_s == s_e {
                    self.end = offset.saturating_add(s as u64);
                    return;
                }
            }
            // Possible UTF-16 string? (C++ bound: end byte + 1 <= e)
            if s + self.min_count * 2 < len {
                let mut k = 0_usize;
                while k < self.min_count
                    && Self::u16_at(bytes, s + k * 2).is_some_and(|u| self.masked_u16(u))
                {
                    k += 1;
                }
                if k == self.min_count {
                    self.end = offset.saturating_add(s as u64);
                    return;
                }
            }
            // Advance past the scanned prefix (C++ `s = s_s` / `s++`).
            s = if s_s > s { s_s } else { s + 1 };
        }
        // Whole window is non-string.
        self.end = offset.saturating_add(len as u64);
    }
}

/// Active-selection similarity state (C++ `CurrentSelection`).
pub struct CurrentSelection {
    /// Match start (inclusive).
    pub start: u64,
    /// Match end (exclusive).
    pub end: u64,
    /// Pattern length (C++ caps at `< 254`); 0 disables the scan.
    pub size: usize,
    /// Highlight-similar toggle.
    pub highlight: bool,
    /// The selected bytes to match.
    pub buffer: [u8; 254],
}

impl Default for CurrentSelection {
    fn default() -> Self {
        Self {
            start: INVALID_OFFSET,
            end: INVALID_OFFSET,
            size: 0,
            highlight: true,
            buffer: [0; 254],
        }
    }
}

/// Cached callback color range (C++ `BufferColor`).
#[derive(Clone, Copy, Debug)]
pub struct BufferColor {
    /// Range start (inclusive).
    pub start: u64,
    /// Range end (inclusive).
    pub end: u64,
    /// Color for the range.
    pub color: CharAttribute,
}

impl Default for BufferColor {
    fn default() -> Self {
        Self {
            start: INVALID_OFFSET,
            end: INVALID_OFFSET,
            color: CharAttribute::default(),
        }
    }
}

/// C++ `BufferColorInterface::GetColorForByteAt`.
pub trait BufferColorCallback {
    /// Color for the byte at `offset`, or `None`.
    fn color_for_byte_at(&mut self, offset: u64, view: &ViewData) -> Option<CharAttribute>;
}

/// C++ `PositionToColorInterface::GetColorForBuffer`.
pub trait PositionToColorCallback {
    /// Color range starting at `offset` given up to 16 bytes of
    /// context, or `None`.
    fn color_for_buffer(&mut self, offset: u64, buf: &[u8]) -> Option<BufferColor>;
}

/// Mutable per-viewer color state.
// The four bools mirror four independent C++ instance flags; folding
// them into enums would obscure the parity mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Default)]
pub struct ColorState {
    /// Selection-similarity scan state.
    pub current_selection: CurrentSelection,
    /// String-run cache.
    pub string_info: StringInfo,
    /// Callback color cache.
    pub buf_color: BufferColor,
    /// C++ `showObjectsHighlighting`.
    pub show_objects_highlighting: bool,
    /// C++ `showCodeExecution`.
    pub show_code_execution: bool,
    /// C++ `showSyncCompare`.
    pub show_sync_compare: bool,
    /// C++ `showTypeObjects`.
    pub show_type_objects: bool,
}

/// Viewer geometry inputs for the callback path.
#[derive(Clone, Copy, Debug)]
pub struct ViewGeometry {
    /// First visible offset (C++ `cursor.GetStartView()`).
    pub start_view: u64,
    /// `charactersPerLine * visibleRows`.
    pub view_size: u64,
    /// Cursor offset.
    pub cursor_pos: u64,
}

/// Resolves the color of the byte at `offset`
/// (C++ `OffsetToColor`, `Instance.cpp:530-614`).
#[allow(clippy::too_many_arguments)]
pub fn offset_to_color(
    state: &mut ColorState,
    offset: u64,
    cache: &mut DataCache,
    zones: &ZonesList,
    object_zones: &ZonesList,
    geometry: ViewGeometry,
    mut buffer_color_cb: Option<&mut dyn BufferColorCallback>,
    mut position_color_cb: Option<&mut dyn PositionToColorCallback>,
    config: &ColorConfig,
) -> CharAttribute {
    // 1. Selection similarity (Instance.cpp:533-547).
    {
        let cs = &mut state.current_selection;
        if cs.size > 0 && cs.highlight {
            if offset >= cs.start && offset < cs.end {
                return config.similar_text;
            }
            let size = cs.size;
            if let Ok(bytes) = cache.get(offset, size as u32, true) {
                if bytes.first() == cs.buffer.first() && bytes.get(..size) == cs.buffer.get(..size)
                {
                    cs.start = offset;
                    cs.end = offset.saturating_add(size as u64);
                    return config.similar_text;
                }
            }
        }
    }

    // 2. Object highlighting zones (Instance.cpp:551-556) — when on,
    // this path never falls through.
    if state.show_objects_highlighting {
        return object_zones
            .offset_to_zone(offset)
            .map_or(config.inactive, |z| z.color);
    }

    // 3. Buffer color callback (Instance.cpp:558-579).
    if state.show_code_execution || state.show_sync_compare {
        if let Some(cb) = buffer_color_cb.as_mut() {
            if offset >= state.buf_color.start && offset <= state.buf_color.end {
                return state.buf_color.color;
            }
            if geometry.start_view <= offset {
                if let Ok(bytes) = cache.get(offset, 1, true) {
                    let view = ViewData {
                        view_start_offset: geometry.start_view,
                        view_size: geometry.view_size,
                        cursor_start_offset: geometry.cursor_pos,
                        byte: bytes.first().copied().unwrap_or(0),
                    };
                    if let Some(color) = cb.color_for_byte_at(offset, &view) {
                        state.buf_color.start = offset;
                        state.buf_color.end = offset;
                        state.buf_color.color = color;
                        return color;
                    }
                }
            }
        }
    }

    // 4. Position-to-color callback (Instance.cpp:581-588).
    if state.show_type_objects {
        if let Some(cb) = position_color_cb.as_mut() {
            if offset >= state.buf_color.start && offset <= state.buf_color.end {
                return state.buf_color.color;
            }
            let context: &[u8] = cache.get(offset, 16, false).unwrap_or(&[]);
            // The callback receives up to 16 bytes (possibly empty at
            // EOF, like the C++ invalid BufferView).
            let context = context.to_owned(); // release the cache borrow
            if let Some(buffer_color) = cb.color_for_buffer(offset, &context) {
                state.buf_color = buffer_color;
                return buffer_color.color;
            }
        }
    }

    // 5. String highlight (Instance.cpp:592-611).
    if state.string_info.show_ascii || state.string_info.show_unicode {
        if offset >= state.string_info.start && offset < state.string_info.end {
            match state.string_info.string_type {
                StringType::Ascii => return config.ascii,
                StringType::Unicode => return config.unicode,
                StringType::None => {}
            }
        } else {
            state.string_info.update(cache, offset);
            if offset >= state.string_info.start && offset < state.string_info.end {
                match state.string_info.string_type {
                    StringType::Ascii => return config.ascii,
                    StringType::Unicode => return config.unicode,
                    StringType::None => {}
                }
            }
        }
    }

    // 6. Plugin zones (Instance.cpp:523-528, 614).
    zones
        .offset_to_zone(offset)
        .map_or(config.inactive, |z| z.color)
}

/// Step 7 — paint-stage override applied after [`offset_to_color`]
/// (C++ `WriteLineTextToChars`/`WriteLineNumbersToChars`,
/// `Instance.cpp:827,869`): a selected byte paints as
/// `Cfg.Selection.Editor`.
#[must_use]
pub fn apply_selection_override(
    color: CharAttribute,
    selection: &Selection,
    offset: u64,
    config: &ColorConfig,
) -> CharAttribute {
    if selection.contains(offset) {
        config.selection_editor
    } else {
        color
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appcui::graphics::Color;
    use gview_core::source::MemorySource;

    fn attr(fore: Color) -> CharAttribute {
        CharAttribute::with_color(fore, Color::Black)
    }

    fn config() -> ColorConfig {
        ColorConfig {
            similar_text: attr(Color::Yellow),
            inactive: attr(Color::Gray),
            ascii: attr(Color::Red),
            unicode: attr(Color::Olive),
            selection_editor: attr(Color::White),
        }
    }

    fn cache_over(data: &[u8]) -> DataCache {
        DataCache::new(Box::new(MemorySource::from_slice(data)), 0)
    }

    struct FixedByteColor(CharAttribute);
    impl BufferColorCallback for FixedByteColor {
        fn color_for_byte_at(&mut self, _o: u64, _v: &ViewData) -> Option<CharAttribute> {
            Some(self.0)
        }
    }

    struct FixedRangeColor(BufferColor);
    impl PositionToColorCallback for FixedRangeColor {
        fn color_for_buffer(&mut self, _o: u64, _b: &[u8]) -> Option<BufferColor> {
            Some(self.0)
        }
    }

    const GEOMETRY: ViewGeometry = ViewGeometry {
        start_view: 0,
        view_size: 160,
        cursor_pos: 0,
    };

    #[test]
    fn default_mask_matches_cpp_table() {
        let mask = default_ascii_mask();
        assert!(mask[9]); // TAB
        assert!(mask[0x20] && mask[b'A' as usize] && mask[0x5F] && mask[0x7E]);
        // C++ excludes backtick and DEL (spec §4.5 wrongly says DEL
        // is allowed; the C++ table wins).
        assert!(!mask[0x60]);
        assert!(!mask[0x7F]);
        assert!(!mask[0x00] && !mask[0x1F] && !mask[0xFF]);
        assert_eq!(mask.iter().filter(|&&m| m).count(), 1 + 95 - 1);
    }

    #[test]
    fn priority_1_similarity_beats_everything() {
        let mut cache = cache_over(b"abcXXXabcXXX");
        let mut state = ColorState {
            show_objects_highlighting: true, // would otherwise win
            ..Default::default()
        };
        state.current_selection.size = 3;
        state.current_selection.buffer[..3].copy_from_slice(b"abc");
        state.current_selection.start = 0;
        state.current_selection.end = 3;
        let zones = ZonesList::new();
        let cfg = config();
        // Inside the current match.
        let c = offset_to_color(
            &mut state, 1, &mut cache, &zones, &zones, GEOMETRY, None, None, &cfg,
        );
        assert_eq!(c, cfg.similar_text);
        // Similar bytes elsewhere: memcmp match relocates the range.
        let c = offset_to_color(
            &mut state, 6, &mut cache, &zones, &zones, GEOMETRY, None, None, &cfg,
        );
        assert_eq!(c, cfg.similar_text);
        assert_eq!(state.current_selection.start, 6);
        assert_eq!(state.current_selection.end, 9);
    }

    #[test]
    fn priority_2_object_zones_never_fall_through() {
        let mut cache = cache_over(b"ABCDEFGH");
        let mut state = ColorState {
            show_objects_highlighting: true,
            ..Default::default()
        };
        let zone_color = attr(Color::Green);
        let mut object_zones = ZonesList::new();
        object_zones.add(0, 3, zone_color, "hdr");
        object_zones.set_viewport_cache((0, 100));
        let mut plugin_zones = ZonesList::new();
        plugin_zones.add(0, 100, attr(Color::Pink), "all");
        plugin_zones.set_viewport_cache((0, 100));
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            1,
            &mut cache,
            &plugin_zones,
            &object_zones,
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c.foreground, Color::Green);
        // Miss inside object mode → Inactive, plugin zones ignored.
        let c = offset_to_color(
            &mut state,
            5,
            &mut cache,
            &plugin_zones,
            &object_zones,
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c, cfg.inactive);
    }

    #[test]
    fn priority_3_buffer_color_callback() {
        let mut cache = cache_over(&[0x90; 32]);
        let mut state = ColorState {
            show_sync_compare: true,
            ..Default::default()
        };
        let cb_color = attr(Color::Aqua);
        let mut cb = FixedByteColor(cb_color);
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            4,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            Some(&mut cb),
            None,
            &cfg,
        );
        assert_eq!(c, cb_color);
        // The single-byte range is cached.
        assert_eq!(state.buf_color.start, 4);
        assert_eq!(state.buf_color.end, 4);
    }

    #[test]
    fn priority_4_position_to_color_and_range_cache() {
        let mut cache = cache_over(&[0x00; 64]);
        let mut state = ColorState {
            show_type_objects: true,
            ..Default::default()
        };
        // Non-string bytes so step 5 stays quiet.
        let range_color = attr(Color::Teal);
        let mut cb = FixedRangeColor(BufferColor {
            start: 8,
            end: 15,
            color: range_color,
        });
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            8,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            None,
            Some(&mut cb),
            &cfg,
        );
        assert_eq!(c, range_color);
        // Subsequent offsets inside the returned range use the cache.
        let c = offset_to_color(
            &mut state,
            12,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            None,
            Some(&mut cb),
            &cfg,
        );
        assert_eq!(c, range_color);
    }

    #[test]
    fn priority_5_string_highlight() {
        // "HELLO" at 4 (>= min_count 4), non-string bytes around.
        let mut data = vec![0_u8; 4];
        data.extend_from_slice(b"HELLO");
        data.extend_from_slice(&[0_u8; 8]);
        let mut cache = cache_over(&data);
        let mut state = ColorState::default();
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            5,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c, cfg.ascii);
        // Non-string byte → falls to zones (none) → inactive.
        let c = offset_to_color(
            &mut state,
            0,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c, cfg.inactive);
    }

    #[test]
    fn unicode_string_detected() {
        // "WIDE" as UTF-16 LE at offset 0 (4 units = min_count).
        let data: Vec<u8> = b"WIDE".iter().flat_map(|&b| [b, 0]).collect();
        let mut cache = cache_over(&data);
        let mut state = ColorState::default();
        state.string_info.show_ascii = false;
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            0,
            &mut cache,
            &ZonesList::new(),
            &ZonesList::new(),
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c, cfg.unicode);
        assert_eq!(state.string_info.string_type, StringType::Unicode);
        assert_eq!(state.string_info.middle, 4);
        assert_eq!(state.string_info.end, 8);
    }

    #[test]
    fn priority_6_zones_and_inactive_fallback() {
        let mut cache = cache_over(&[0_u8; 32]);
        let mut state = ColorState::default();
        let zone_color = attr(Color::Pink);
        let mut zones = ZonesList::new();
        zones.add(0, 15, zone_color, "z");
        zones.set_viewport_cache((0, 100));
        let cfg = config();
        let c = offset_to_color(
            &mut state,
            3,
            &mut cache,
            &zones,
            &ZonesList::new(),
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c.foreground, Color::Pink);
        let c = offset_to_color(
            &mut state,
            20,
            &mut cache,
            &zones,
            &ZonesList::new(),
            GEOMETRY,
            None,
            None,
            &cfg,
        );
        assert_eq!(c, cfg.inactive);
    }

    #[test]
    fn priority_7_selection_override_wins_after_resolution() {
        let cfg = config();
        let mut selection = Selection::new();
        assert!(selection.set_selection(0, 10, 20));
        let base = attr(Color::Red);
        assert_eq!(
            apply_selection_override(base, &selection, 15, &cfg),
            cfg.selection_editor
        );
        assert_eq!(apply_selection_override(base, &selection, 5, &cfg), base);
    }

    #[test]
    fn string_gap_scan_stops_before_next_string() {
        // 6 junk bytes, then a 5-char string: the None-range must end
        // exactly where the possible string begins.
        let mut data = vec![0_u8; 6];
        data.extend_from_slice(b"WORLD");
        let mut cache = cache_over(&data);
        let mut info = StringInfo::default();
        info.update(&mut cache, 0);
        assert_eq!(info.string_type, StringType::None);
        assert_eq!(info.start, 0);
        assert_eq!(info.end, 6);
    }

    #[test]
    fn string_shorter_than_min_count_not_highlighted() {
        let mut data = b"abc".to_vec(); // 3 < min_count 4
        data.extend_from_slice(&[0_u8; 8]);
        let mut cache = cache_over(&data);
        let mut info = StringInfo::default();
        info.update(&mut cache, 0);
        assert_eq!(info.string_type, StringType::None);
    }
}
