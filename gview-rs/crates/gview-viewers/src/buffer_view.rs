//! The hex / binary viewer control.
//!
//! Spec `00_APP §6.2` (control pattern) and `§6.3` (hot-path rules);
//! `02_VIEWER_BUFFER` §2 (state & layout), §4 (rendering loop and
//! colour) and §6 (key matrix); `GUIDE §5.5`. C++ anchor:
//! `GViewCore/src/View/BufferViewer/Instance.cpp` — `Paint`
//! (L660-760), `OnKeyEvent`, `OnMouseEvent`, `OnUpdateCommandBar` and
//! `PaintCursorInformation` (L1734+).
//!
//! Every algorithm already lives in `gview-view`; this control only
//! *owns* that state and drives it from the `AppCUI` hooks:
//!
//! | Hook | Delegates to |
//! |------|--------------|
//! | `OnResize` | [`BufferLayout::update_view_sizes`], then re-clamps the cursor through [`move_to`] |
//! | `OnPaint` | the header row, then [`paint_rows`] into a [`SurfaceRowSink`] |
//! | `OnKeyPressed` | [`navigation_for_key`] → [`apply_navigation`]; actions the state machine refuses become shell events |
//! | `OnMouseEvent` | wheel → [`move_scroll_to`]; click inside a band → [`move_to`] |
//!
//! Actions the viewer cannot service itself (`Ctrl+G`, `Ctrl+F`,
//! `Ctrl+C`, `Escape`) are raised as the control's own events so the
//! `FileWindow` can open its dialogs — that is how `gview-viewers`
//! stays free of a `gview-app` dependency (`00_APP §6.3`).

use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;

use gview_core::cache::DataCache;
use gview_core::constants::INVALID_OFFSET;
use gview_core::selection::Selection;
use gview_core::zones::ZonesList;
use gview_plugin::type_plugin::BufferViewerRequest;
use gview_view::buffer_viewer::color::{ColorConfig, ColorState, PositionToColorCallback};
use gview_view::buffer_viewer::input::{apply_navigation, navigation_for_key, NavAction, NavContext};
use gview_view::buffer_viewer::layout::{
    move_scroll_to, move_to, BufferCursor, BufferLayout, CharacterFormatMode,
};
use gview_view::buffer_viewer::paint::paint_rows;
use gview_view::traits::{SharedObject, SmartViewer, ViewerSettings};
use gview_view::view_control::{clamp_goto, ViewControl, ViewData};

use crate::cursor_info::{CursorSnapshot, SharedCursorInfo};
use crate::surface_sink::{ByteColors, RowColors, SurfaceRowSink, HEX_DIGITS};

/// C++ `hex_header` (`Instance.cpp:11`) — the column ruler painted on
/// row 0, covering the widest supported column count (32).
pub const HEX_HEADER: &str =
    "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F ";
/// C++ `oct_header` (`Instance.cpp:12-13`).
pub const OCT_HEADER: &str = "000 001 002 003 004 005 006 007 010 011 012 013 014 015 016 017 020 021 022 023 024 025 026 027 030 031 032 033 034 035 036 037 ";
/// C++ `signed_dec_header` (`Instance.cpp:14-15`).
pub const SIGNED_DEC_HEADER: &str = "  +0   +1   +2   +3   +4   +5   +6   +7   +8   +9  +10  +11  +12  +13  +14  +15  +16  +17  +18  +19  +20  +21  +22  +23  +24  +25  +26  +27  +28  +29  +30  +31  ";
/// C++ `unsigned_dec_header` (`Instance.cpp:16-17`).
pub const UNSIGNED_DEC_HEADER: &str = " +0  +1  +2  +3  +4  +5  +6  +7  +8  +9 +10 +11 +12 +13 +14 +15 +16 +17 +18 +19 +20 +21 +22 +23 +24 +25 +26 +27 +28 +29 +30 +31 ";
/// C++ `WriteHeaders` address caption when the plugin declared no
/// translation methods (`Instance.cpp:704`).
pub const ADDRESS_HEADER: &str = "Address";
/// C++ `WriteHeaders` text-band caption (`Instance.cpp:733`).
pub const TEXT_HEADER: &str = "Text";

/// Widest `Pos:`/`Sel:` bar this control formats without allocating.
const CURSOR_BAR_CAPACITY: usize = 96;

/// Runs the Find engine for a [`BufferView`].
///
/// C++ `Instance::ShowFindDialog` owns a `FindDialog` and the search
/// engine; the Rust engine lives in `gview_app::buffer_find`, which
/// this crate must not depend on (`00_APP §6.3`). The window installs
/// a provider at mount time instead.
pub trait FindProvider: Send {
    /// Next match at or after `from`, as `(offset, length)`.
    fn find_next(&mut self, cache: &mut DataCache, from: u64) -> Option<(u64, u64)>;
}

/// Everything the `FileWindow` hands a [`BufferView`] at mount
/// (`00_APP §5.3.2`): the plugin's `BufferViewerRequest` plus the three
/// host-side services.
pub struct BufferViewSettings {
    /// The plugin's `BufferViewer::Settings`, moved in whole (the
    /// `ZonesList` is never cloned).
    pub request: BufferViewerRequest,
    /// `SetPositionToColorCallback` result (`00_APP §5.3.3`).
    pub colorizer: Option<Box<dyn PositionToColorCallback + Send>>,
    /// The window's bottom-bar slot (`00_APP §5.3.5`).
    pub cursor_info: SharedCursorInfo,
    /// The host's Find engine.
    pub find: Option<Box<dyn FindProvider>>,
    /// `CreateViewer<T>(name)` override.
    pub custom_name: Option<String>,
}

impl Default for BufferViewSettings {
    fn default() -> Self {
        Self {
            request: BufferViewerRequest::default(),
            colorizer: None,
            cursor_info: SharedCursorInfo::new(),
            find: None,
            custom_name: None,
        }
    }
}

impl core::fmt::Debug for BufferViewSettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BufferViewSettings")
            .field("zones", &self.request.zones.count())
            .field("has_colorizer", &self.colorizer.is_some())
            .field("has_find", &self.find.is_some())
            .finish_non_exhaustive()
    }
}

impl ViewerSettings for BufferViewSettings {
    fn custom_name(&self) -> Option<&str> {
        self.custom_name.as_deref()
    }

    fn set_custom_name(&mut self, name: &str) {
        self.custom_name = Some(name.to_owned());
    }
}

/// The hex / binary viewer (C++ `BufferViewer::Instance`).
///
/// State that `on_paint` must refresh (the zone viewport cache, the
/// colour cache, the plugin colourer) sits behind an uncontended
/// `Mutex` because `OnPaint::on_paint` takes `&self`; a poisoned lock
/// degrades through `PoisonError::into_inner` instead of panicking
/// (`00_APP §0.3 D4`).
#[CustomControl(overwrite = OnPaint+OnKeyPressed+OnResize+OnMouseEvent, emit = ShowGoTo+ShowFind+ShowCopy+FocusView)]
pub struct BufferView {
    object: SharedObject,
    layout: BufferLayout,
    cursor: BufferCursor,
    selection: Selection,
    zones: Mutex<ZonesList>,
    /// Throwaway list handed to [`paint_rows`], which always writes a
    /// viewport cache into the list it is given. The *real* cache is
    /// refreshed by the key / resize handlers (and once more at the
    /// top of `on_paint`), which is where `00_APP §6.2` puts it; this
    /// list stays empty and never allocates.
    paint_scratch: Mutex<ZonesList>,
    color_state: Mutex<ColorState>,
    colorizer: Mutex<Option<Box<dyn PositionToColorCallback + Send>>>,
    color_config: ColorConfig,
    /// `SetBookmark(slot, offset)`; `INVALID_OFFSET` = unset.
    bookmarks: [u64; 10],
    /// F7 target; `INVALID_OFFSET` = unset.
    entry_point: u64,
    /// Address-column captions after `FileOffset` (C++
    /// `settings->translationMethods`).
    translation_methods: Vec<String>,
    /// C++ `currentAdrressMode`.
    address_mode: usize,
    name: String,
    cursor_info: SharedCursorInfo,
    find: Option<Box<dyn FindProvider>>,
    /// Scratch for `paint_cursor_information`, sized once at
    /// construction so the bottom bar never allocates.
    cursor_bar: [u8; CURSOR_BAR_CAPACITY],
}

impl BufferView {
    /// The inclusive offset interval `paint_rows` caches zones for
    /// (C++ `Paint`: `SetCache({startView, startView +
    /// charactersPerLine * (visibleRows - 1)})`).
    fn viewport(&self) -> (u64, u64) {
        let cpl = u64::from(self.layout.characters_per_line);
        let rows = u64::from(self.layout.visible_rows.saturating_sub(1));
        (
            self.cursor.start_view,
            self.cursor.start_view.saturating_add(cpl.saturating_mul(rows)),
        )
    }

    /// The object's size, read through the shared lock.
    fn file_size(&self) -> u64 {
        let guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        guard.data().size()
    }

    /// The current cursor and selection, for the bottom bar.
    fn snapshot(&self) -> CursorSnapshot {
        let mut snapshot = CursorSnapshot::with_name(&self.name);
        snapshot.offset = self.cursor.current_pos;
        snapshot.base = 16;
        snapshot.size = self.file_size();
        if let Some((start, end)) = self.selection.get_selection(0) {
            snapshot.has_selection = true;
            snapshot.selection_start = start;
            snapshot.selection_end = end;
        }
        snapshot
    }

    /// Publishes the cursor to the window's bottom bar.
    fn publish(&self) {
        self.cursor_info.write(self.snapshot());
    }

    /// The column ruler for the current numeric mode
    /// (C++ `WriteHeaders`, `Instance.cpp:711-729`).
    #[must_use]
    pub const fn numbers_header(&self) -> &'static str {
        match self.layout.char_format_mode {
            CharacterFormatMode::Hex => HEX_HEADER,
            CharacterFormatMode::Octal => OCT_HEADER,
            CharacterFormatMode::SignedDecimal => SIGNED_DEC_HEADER,
            CharacterFormatMode::UnsignedDecimal => UNSIGNED_DEC_HEADER,
        }
    }

    /// The address-column caption: the plugin's current translation
    /// method, else `"Address"` (C++ `Instance.cpp:700-706`).
    #[must_use]
    pub fn address_header(&self) -> &str {
        self.translation_methods
            .get(self.address_mode)
            .map_or(ADDRESS_HEADER, String::as_str)
    }

    /// Read-only view of the layout (tests and the mount code).
    #[must_use]
    pub const fn layout(&self) -> &BufferLayout {
        &self.layout
    }

    /// Read-only view of the cursor.
    #[must_use]
    pub const fn cursor(&self) -> BufferCursor {
        self.cursor
    }

    /// Read-only view of the selection.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// C++ `WriteHeaders` (`Instance.cpp:691-734`): the address, the
    /// numeric ruler and the `Text` caption on row 0.
    fn paint_header(&self, surface: &mut Surface, attr: CharAttribute) {
        let width = surface.size().width;
        surface.fill_horizontal_line(0, 0, width.cast_signed(), Character::with_attributes(' ', attr));
        if self.layout.line_address_size > 0 {
            surface.write_string(self.layout.x_address.cast_signed(), 0, self.address_header(), attr, false);
        }
        if self.layout.nr_cols > 0 {
            // The ruler is a prefix of the 32-column constant: one
            // header cell per data column, same cell width as a row.
            let cell = self.layout.char_format_mode.size().saturating_add(1) as usize;
            let len = cell.saturating_mul(self.layout.nr_cols as usize);
            let ruler = self.numbers_header();
            let ruler = ruler.get(..len.min(ruler.len())).unwrap_or(ruler);
            surface.write_string(self.layout.x_numbers.cast_signed(), 0, ruler, attr, false);
        }
        surface.write_string(self.layout.x_text.cast_signed(), 0, TEXT_HEADER, attr, false);
    }

    /// Byte offset under a click at `(x, y)` in control coordinates,
    /// or `None` outside the numeric and text bands
    /// (C++ `OnMouseEvent` `MouseEventType::Pressed`).
    #[must_use]
    pub fn offset_at(&self, x: i32, y: i32) -> Option<u64> {
        if y < 1 || x < 0 {
            return None;
        }
        let row = u32::try_from(y.saturating_sub(1)).ok()?;
        if row >= self.layout.visible_rows {
            return None;
        }
        let x = u32::try_from(x).ok()?;
        let column = if self.layout.nr_cols == 0 {
            x.checked_sub(self.layout.x_text)?
        } else if x >= self.layout.x_text {
            x.saturating_sub(self.layout.x_text)
        } else if x >= self.layout.x_numbers {
            let cell = self.layout.char_format_mode.size().saturating_add(1);
            x.saturating_sub(self.layout.x_numbers).checked_div(cell)?
        } else {
            return None;
        };
        if self.layout.nr_cols > 0 && column >= self.layout.nr_cols {
            return None;
        }
        let offset = self
            .layout
            .line_offset(row, self.cursor.start_view)
            .saturating_add(u64::from(column));
        (offset < self.file_size()).then_some(offset)
    }

    /// Runs one [`NavAction`] against the viewer state, returning
    /// `true` when the state machine consumed it (C++ `OnKeyEvent`).
    fn navigate(&mut self, action: NavAction) -> bool {
        // `ZonesList::offset_to_zone` answers from the viewport cache
        // alone, so `Ctrl+PageUp/PageDown` needs it fresh *before* the
        // action runs — `00_APP §6.2` puts this refresh in the key and
        // resize handlers rather than in paint.
        let viewport = self.viewport();
        // One block so every lock is released here rather than at the
        // end of the enclosing scope.
        let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        let mut zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
        zones.set_viewport_cache(viewport);
        let handled = {
            let zones: &ZonesList = &zones;
            let mut ctx = NavContext {
                cursor: &mut self.cursor,
                selection: &mut self.selection,
                layout: &self.layout,
                cache: guard.data_mut(),
                zones,
                bookmarks: &self.bookmarks,
                entry_point: self.entry_point,
            };
            apply_navigation(action, &mut ctx)
        };
        drop(zones);
        drop(guard);
        handled
    }

    /// Applies the display-mode actions the state machine defers to
    /// the shell but that belong to this control (C++
    /// `Instance::OnKeyEvent` display branch, `Instance.cpp:242-356`).
    fn apply_display_action(&mut self, action: NavAction, size: Size) -> bool {
        match action {
            NavAction::ChangeColumnsCount => {
                self.layout.nr_cols =
                    gview_view::buffer_viewer::input::next_columns_count(self.layout.nr_cols);
                self.resize_layout(size);
                true
            }
            NavAction::ChangeValueFormatOrCp => {
                self.layout.char_format_mode = match self.layout.char_format_mode {
                    CharacterFormatMode::Hex => CharacterFormatMode::Octal,
                    CharacterFormatMode::Octal => CharacterFormatMode::SignedDecimal,
                    CharacterFormatMode::SignedDecimal => CharacterFormatMode::UnsignedDecimal,
                    CharacterFormatMode::UnsignedDecimal => CharacterFormatMode::Hex,
                };
                self.resize_layout(size);
                true
            }
            NavAction::ChangeAddressMode => {
                // C++ `currentAdrressMode = (currentAdrressMode + 1) %
                // translationMethodsCount`; with none declared the
                // column keeps showing the file offset.
                let count = self.translation_methods.len();
                self.address_mode = self
                    .address_mode
                    .saturating_add(1)
                    .checked_rem(count.max(1))
                    .unwrap_or(0);
                true
            }
            NavAction::ChangeSelectionType => {
                self.selection.invert_multi_selection_mode();
                true
            }
            _ => false,
        }
    }

    /// Recomputes the layout for `size` and re-clamps the cursor
    /// (C++ `OnAfterResize` → `UpdateViewSizes` + `MoveTo`).
    fn resize_layout(&mut self, size: Size) {
        self.layout.update_view_sizes(size.width, size.height);
        let file_size = self.file_size();
        let visible = self.layout.visible_bytes();
        let pos = self.cursor.current_pos;
        move_to(&mut self.cursor, &mut self.selection, pos, false, file_size, visible);
        let viewport = self.viewport();
        self.zones
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .set_viewport_cache(viewport);
    }
}

impl SmartViewer for BufferView {
    type Settings = BufferViewSettings;

    fn from_settings(object: SharedObject, settings: Self::Settings) -> Self {
        let BufferViewSettings {
            request,
            colorizer,
            cursor_info,
            find,
            custom_name,
        } = settings;
        let mut bookmarks = [INVALID_OFFSET; 10];
        for (slot, offset) in &request.bookmarks {
            if let Some(cell) = bookmarks.get_mut(*slot as usize) {
                *cell = *offset;
            }
        }
        // C++ `showTypeObjects` is on exactly when the plugin asked for
        // opcode colouring (`SetPositionToColorCallback`).
        let color_state = ColorState {
            show_type_objects: request.position_to_color && colorizer.is_some(),
            ..ColorState::default()
        };
        let view = Self {
            base: ControlBase::with_focus_overlay(layout!("d:f")),
            object,
            layout: BufferLayout::default(),
            cursor: BufferCursor::default(),
            selection: Selection::new(),
            zones: Mutex::new(request.zones),
            paint_scratch: Mutex::new(ZonesList::new()),
            color_state: Mutex::new(color_state),
            colorizer: Mutex::new(colorizer),
            color_config: default_color_config(),
            bookmarks,
            entry_point: request.entry_point.unwrap_or(INVALID_OFFSET),
            translation_methods: request.translation_methods,
            address_mode: 0,
            name: custom_name.unwrap_or_else(|| String::from("Buffer")),
            cursor_info,
            find,
            cursor_bar: [b' '; CURSOR_BAR_CAPACITY],
        };
        view.publish();
        view
    }
}

/// C++ `Cfg.*` defaults for the colour steps this control resolves
/// (`BufferViewer/Instance.cpp` `Cfg.Selection.SimilarText`,
/// `Cfg.Text.Inactive`, `config.Colors.Ascii/Unicode`,
/// `Cfg.Selection.Editor`).
fn default_color_config() -> ColorConfig {
    ColorConfig {
        similar_text: CharAttribute::with_color(Color::Black, Color::Yellow),
        inactive: CharAttribute::with_color(Color::Gray, Color::Black),
        ascii: CharAttribute::with_color(Color::Red, Color::DarkBlue),
        unicode: CharAttribute::with_color(Color::Yellow, Color::DarkBlue),
        selection_editor: CharAttribute::with_color(Color::Black, Color::White),
    }
}

impl ViewControl for BufferView {
    fn name(&self) -> &str {
        &self.name
    }

    fn go_to(&mut self, offset: u64) -> bool {
        let file_size = self.file_size();
        if file_size == 0 {
            return false;
        }
        let target = clamp_goto(offset, file_size);
        let visible = self.layout.visible_bytes();
        move_to(&mut self.cursor, &mut self.selection, target, false, file_size, visible);
        self.publish();
        true
    }

    fn select(&mut self, offset: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let file_size = self.file_size();
        if file_size == 0 {
            return false;
        }
        let start = clamp_goto(offset, file_size);
        let end = clamp_goto(offset.saturating_add(size).saturating_sub(1), file_size);
        let selected = self.selection.set_selection(0, start, end);
        if selected {
            self.publish();
        }
        selected
    }

    /// The dialog belongs to the `FileWindow`; the control raises the
    /// event and the window opens it (`00_APP §5.6`).
    fn show_goto_dialog(&mut self) -> bool {
        self.raise_event(bufferview::Events::ShowGoTo);
        true
    }

    fn show_find_dialog(&mut self) -> bool {
        self.raise_event(bufferview::Events::ShowFind);
        true
    }

    fn show_copy_dialog(&mut self) -> bool {
        self.raise_event(bufferview::Events::ShowCopy);
        true
    }

    /// C++ `PaintCursorInformation` (`Instance.cpp:1734+`) for the
    /// one-line bar: the selection field, then `Pos:` with the cursor
    /// offset in the cursor's base.
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let snapshot = self.snapshot();
        let len = format_cursor_bar(&mut self.cursor_bar, snapshot);
        let text = self.cursor_bar.get(..len).unwrap_or(&[]);
        surface.write_ascii(0, 0, text, CharAttribute::default(), false);
    }

    fn view_data(&self, data: &mut ViewData, offset: u64) -> bool {
        let byte = {
            let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            let byte = guard.data_mut().get(offset, 1, true).ok().and_then(|b| b.first().copied());
            byte
        };
        let Some(byte) = byte else {
            return false;
        };
        data.view_start_offset = self.cursor.start_view;
        data.view_size = self.layout.visible_bytes();
        data.cursor_start_offset = self.cursor.current_pos;
        data.byte = byte;
        true
    }

    fn advance_start_view(&mut self, delta: i64) -> bool {
        let file_size = self.file_size();
        if file_size == 0 {
            return false;
        }
        let target = if delta >= 0 {
            self.cursor.start_view.saturating_add(delta.unsigned_abs())
        } else {
            self.cursor.start_view.saturating_sub(delta.unsigned_abs())
        };
        let visible = self.layout.visible_bytes();
        move_scroll_to(&mut self.cursor, &mut self.selection, target, file_size, visible);
        self.publish();
        true
    }
}

/// A bounded, allocation-free ASCII writer over the control's inline
/// `cursor_bar` scratch: everything past the buffer is dropped rather
/// than panicking.
struct BarWriter<'a> {
    out: &'a mut [u8; CURSOR_BAR_CAPACITY],
    len: usize,
}

impl BarWriter<'_> {
    /// Appends one byte, if there is room.
    fn push(&mut self, byte: u8) {
        if let Some(slot) = self.out.get_mut(self.len) {
            *slot = byte;
            self.len = self.len.saturating_add(1);
        }
    }

    /// Appends an ASCII literal.
    fn push_str(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.push(*byte);
        }
    }

    /// Appends `value` in `base` (16 or 10), most significant digit
    /// first, upper-case (C++ `NumericFormatter::ToBase`).
    fn push_base(&mut self, value: u64, base: u64) {
        // 64 bits never need more than 20 digits in base 10.
        let mut digits = [b'0'; 20];
        let mut count = 0_usize;
        let mut rest = value;
        loop {
            let digit = rest
                .checked_rem(base)
                .and_then(|index| HEX_DIGITS.get(index as usize).copied())
                .unwrap_or(b'0');
            if let Some(slot) = digits.get_mut(count) {
                *slot = digit;
            }
            count = count.saturating_add(1);
            rest = rest.checked_div(base).unwrap_or(0);
            if rest == 0 || count >= digits.len() {
                break;
            }
        }
        for index in (0..count).rev() {
            self.push(digits.get(index).copied().unwrap_or(b'0'));
        }
    }
}

/// Formats the one-line cursor bar into `out` without allocating,
/// returning the written length.
///
/// Field order mirrors the C++ one-line `PaintCursorInformation`
/// (`Instance.cpp:1750-1765`): `PrintSelectionInfo(0)` — which prints
/// `"%X,%X"` of the selection start and length, or `"NO Selection"` —
/// then `PrintCursorPosInfo`, which prints `"Pos:"` followed by the
/// offset in the cursor's base and the `%3u%%` progress field
/// (`"----"` for an empty object).
fn format_cursor_bar(out: &mut [u8; CURSOR_BAR_CAPACITY], snapshot: CursorSnapshot) -> usize {
    let mut bar = BarWriter { out, len: 0 };
    if snapshot.has_selection {
        bar.push_str(b"Sel:");
        bar.push_base(snapshot.selection_start, 16);
        bar.push(b',');
        bar.push_base(snapshot.selection_len(), 16);
    } else {
        bar.push_str(b"NO Selection");
    }
    bar.push_str(b"  Pos:");
    bar.push_base(snapshot.offset, u64::from(snapshot.base.max(2)));
    if let Some(percent) = snapshot.percent() {
        bar.push_str(b"  ");
        bar.push_base(percent, 10);
        bar.push(b'%');
    } else {
        bar.push_str(b"  ----");
    }
    bar.len
}

impl OnResize for BufferView {
    fn on_resize(&mut self, _old: Size, new: Size) {
        self.resize_layout(new);
        self.publish();
    }
}

impl OnPaint for BufferView {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.editor.normal));
        self.paint_header(surface, theme.header.text.normal);

        let colors = RowColors {
            address: theme.text.inactive,
            numbers: theme.editor.normal,
            text: theme.editor.normal,
        };
        let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        let mut zones_guard = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
        // The C++ `Paint` calls `SetCache` before the row loop; do the
        // same so the very first frame — before any key or resize —
        // already colours by zone.
        zones_guard.set_viewport_cache(self.viewport());
        let zones: &ZonesList = &zones_guard;
        let mut colorizer = self.colorizer.lock().unwrap_or_else(PoisonError::into_inner);
        let show_type_objects = self
            .color_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .show_type_objects;
        let byte_colors = ByteColors {
            zones,
            selection: &self.selection,
            colorizer: colorizer.as_deref_mut().map(|cb| cb as &mut dyn PositionToColorCallback),
            config: self.color_config,
            show_type_objects,
        };
        let mut sink = SurfaceRowSink::new(surface, self.layout, colors).with_byte_colors(byte_colors);
        // `paint_rows` writes a viewport cache into whatever list it is
        // given; the real list was refreshed just above, so it gets the
        // control's empty scratch instead of a second mutable borrow.
        let mut scratch = self.paint_scratch.lock().unwrap_or_else(PoisonError::into_inner);
        paint_rows(
            &self.layout,
            self.cursor,
            guard.data_mut(),
            &mut scratch,
            &mut sink,
        );
        drop(scratch);
        drop(colorizer);
        drop(zones_guard);
        drop(guard);
    }
}

/// The window-level shortcut a key maps to, if any (C++
/// `FileWindow::OnKeyEvent`, `FileWindow.cpp:184-221`): Escape
/// refocuses the view tab, `Ctrl+G` / `Ctrl+F` / `Ctrl+C` /
/// `Ctrl+Insert` open the window's dialogs.
fn shell_event_for_key(key: Key) -> Option<bufferview::Events> {
    let plain = |code: KeyCode| Key::new(code, KeyModifier::None);
    let ctrl = |code: KeyCode| Key::new(code, KeyModifier::Ctrl);
    if key == plain(KeyCode::Escape) {
        return Some(bufferview::Events::FocusView);
    }
    if key == ctrl(KeyCode::G) {
        return Some(bufferview::Events::ShowGoTo);
    }
    if key == ctrl(KeyCode::F) {
        return Some(bufferview::Events::ShowFind);
    }
    if key == ctrl(KeyCode::C) || key == ctrl(KeyCode::Insert) {
        return Some(bufferview::Events::ShowCopy);
    }
    None
}

impl OnKeyPressed for BufferView {
    fn on_key_pressed(&mut self, key: Key, _character: char) -> EventProcessStatus {
        // Shell-owned shortcuts first: the window opens the dialogs
        // (`FileWindow.cpp:184-221`). `KeyModifier` is a bit-flag type
        // and cannot appear in a pattern, so these compare by value.
        if let Some(event) = shell_event_for_key(key) {
            self.raise_event(event);
            return EventProcessStatus::Processed;
        }
        let Some(action) = navigation_for_key(key) else {
            return EventProcessStatus::Ignored;
        };
        let size = self.client_size();
        let handled = if self.navigate(action) || self.apply_display_action(action, size) {
            true
        } else {
            // Actions the state machine defers and this control cannot
            // service (find, dissasm dialog, open selection) become
            // window events.
            match action {
                NavAction::FindNext | NavAction::FindPrevious => {
                    self.raise_event(bufferview::Events::ShowFind);
                    true
                }
                _ => false,
            }
        };
        if handled {
            self.publish();
            self.request_update();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

impl OnMouseEvent for BufferView {
    fn on_mouse_event(&mut self, event: &MouseEvent) -> EventProcessStatus {
        let handled = match event {
            MouseEvent::Wheel(MouseWheelDirection::Down) => {
                self.navigate(NavAction::Scroll { delta: i64::MAX })
            }
            MouseEvent::Wheel(MouseWheelDirection::Up) => {
                self.navigate(NavAction::Scroll { delta: i64::MIN })
            }
            MouseEvent::Pressed(data) | MouseEvent::Drag(data) => {
                match self.offset_at(data.x, data.y) {
                    Some(offset) => {
                        let file_size = self.file_size();
                        let visible = self.layout.visible_bytes();
                        let select = matches!(event, MouseEvent::Drag(_));
                        move_to(
                            &mut self.cursor,
                            &mut self.selection,
                            offset,
                            select,
                            file_size,
                            visible,
                        );
                        true
                    }
                    None => false,
                }
            }
            _ => false,
        };
        if handled {
            self.publish();
            self.request_update();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_cursor_bar, BufferView, BufferViewSettings, FindProvider, CURSOR_BAR_CAPACITY,
        HEX_HEADER,
    };
    use crate::cursor_info::SharedCursorInfo;
    use appcui::prelude::*;
    use gview_core::cache::DataCache;
    use gview_core::object::Object;
    use gview_core::source::MemorySource;
    use gview_plugin::type_plugin::BufferViewerRequest;
    use gview_view::buffer_viewer::color::{BufferColor, PositionToColorCallback};
    use gview_view::buffer_viewer::layout::CharacterFormatMode;
    use gview_view::traits::{SharedObject, SmartViewer};
    use gview_view::view_control::ViewControl;
    use std::sync::{Arc, Mutex as StdMutex};

    /// `EventProcessStatus` is not `Debug`, so tests assert through a
    /// predicate.
    fn processed(status: EventProcessStatus) -> bool {
        status == EventProcessStatus::Processed
    }

    /// The 64-byte fixture: an `MZ` header followed by a ramp.
    fn fixture() -> Vec<u8> {
        let mut data = vec![0x4D, 0x5A, 0x90, 0x00];
        data.extend(4..64_u8);
        data
    }

    fn object_of(bytes: &[u8], name: &str) -> SharedObject {
        Arc::new(StdMutex::new(Object::from_buffer(bytes, name, 0)))
    }

    fn view_with(request: BufferViewerRequest, info: SharedCursorInfo, size: Size) -> BufferView {
        let object = object_of(&fixture(), "sample.bin");
        let mut view = BufferView::from_settings(
            object,
            BufferViewSettings {
                request,
                cursor_info: info,
                ..BufferViewSettings::default()
            },
        );
        // `OnResize` is what the framework calls once the control is
        // laid out; drive it directly in the unit tests.
        OnResize::on_resize(&mut view, Size::new(0, 0), size);
        view
    }

    fn view(size: Size) -> BufferView {
        view_with(BufferViewerRequest::default(), SharedCursorInfo::new(), size)
    }

    fn read(surface: &Surface, x: u32, y: u32, len: usize) -> String {
        (0..len)
            .filter_map(|i| {
                surface
                    .char(x.saturating_add(i as u32).cast_signed(), y.cast_signed())
                    .map(|c| c.code)
            })
            .collect()
    }

    #[test]
    fn paints_the_header_and_the_first_row() {
        let view = view(Size::new(120, 12));
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(120, 12);
        OnPaint::on_paint(&view, &mut surface, &theme);

        let layout = view.layout();
        assert_eq!(layout.nr_cols, 16);
        // Header: the address caption and the hex ruler prefix.
        assert_eq!(read(&surface, layout.x_address, 0, 7), "Address");
        assert_eq!(
            read(&surface, layout.x_numbers, 0, 12),
            HEX_HEADER.get(..12).expect("ruler")
        );
        assert_eq!(read(&surface, layout.x_text, 0, 4), "Text");
        // Row 0 of the data area is screen row 1.
        assert_eq!(read(&surface, layout.x_numbers, 1, 6), "4D 5A ");
        assert_eq!(read(&surface, layout.x_text, 1, 2), "MZ");
        assert_eq!(read(&surface, layout.x_address, 1, 8), "00000000");
    }

    #[test]
    fn down_moves_the_cursor_by_one_row() {
        let mut view = view(Size::new(120, 12));
        let cpl = u64::from(view.layout().characters_per_line);
        assert_eq!(cpl, 16);
        assert_eq!(view.cursor().current_pos, 0);
        let status = OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert!(processed(status));
        assert_eq!(view.cursor().current_pos, cpl);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(view.cursor().current_pos, cpl * 2);
        // Up comes back.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Up, KeyModifier::None), '\0');
        assert_eq!(view.cursor().current_pos, cpl);
    }

    #[test]
    fn ctrl_page_down_jumps_to_the_end_of_the_current_zone() {
        let mut request = BufferViewerRequest::default();
        request.zones.add_sized(
            0,
            16,
            CharAttribute::with_color(Color::Olive, Color::Black),
            "DOS Header",
        );
        request.zones.add_sized(
            16,
            48,
            CharAttribute::with_color(Color::Magenta, Color::Black),
            "Body",
        );
        let mut view = view_with(request, SharedCursorInfo::new(), Size::new(120, 12));
        assert_eq!(view.cursor().current_pos, 0);
        let status = OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageDown, KeyModifier::Ctrl), '\0');
        assert!(processed(status));
        // Zone 0 covers [0, 15]: the jump lands on its high bound.
        assert_eq!(view.cursor().current_pos, 15);
        // Ctrl+PageUp goes back to the zone start.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageUp, KeyModifier::Ctrl), '\0');
        assert_eq!(view.cursor().current_pos, 0);
    }

    #[test]
    fn shift_right_extends_the_selection() {
        let mut view = view(Size::new(120, 12));
        assert!(view.selection().get_selection(0).is_none());
        for _ in 0..3 {
            let status = OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Right, KeyModifier::Shift), '\0');
            assert!(processed(status));
        }
        assert_eq!(view.cursor().current_pos, 3);
        assert_eq!(view.selection().get_selection(0), Some((0, 3)));
    }

    /// Quirk #9: `UpdateViewSizes` (`Instance.cpp:617-653`) recomputes
    /// the derived geometry but never re-fits `nrCols` to the width —
    /// only F6 changes the column count. A narrow terminal keeps its
    /// 16 columns and clips, exactly as the C++ does.
    #[test]
    fn a_narrow_resize_keeps_the_column_count_and_reclamps_the_cursor() {
        let mut view = view(Size::new(120, 12));
        assert_eq!(view.layout().characters_per_line, 16);
        let wide_rows = view.layout().visible_rows;

        OnResize::on_resize(&mut view, Size::new(120, 12), Size::new(40, 6));
        assert_eq!(view.layout().nr_cols, 16, "C++ never re-fits nr_cols");
        assert_eq!(view.layout().characters_per_line, 16);
        // The derived geometry *is* recomputed: fewer rows, and the
        // text band now sits past the 40-cell width (the C++ clips it).
        assert_eq!(view.layout().visible_rows, 5);
        assert!(view.layout().visible_rows < wide_rows);
        assert!(view.layout().x_text > 40, "clipped, not re-fitted");
        // The cursor stays inside the file.
        assert!(view.cursor().current_pos < 64);

        // F6 is the only path to 8 columns: 16 → 32 → 0 → 8.
        for expected in [32, 0, 8] {
            OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::F6, KeyModifier::None), '\0');
            assert_eq!(view.layout().nr_cols, expected);
        }
        assert_eq!(view.layout().characters_per_line, 8);
    }

    #[test]
    fn cursor_information_shows_pos_and_the_hex_offset() {
        let mut view = view(Size::new(120, 12));
        assert!(view.go_to(0x2A));
        let mut surface = Surface::new(80, 1);
        view.paint_cursor_information(&mut surface, 80, 1);
        let line = read(&surface, 0, 0, 40);
        assert!(line.starts_with("NO Selection  Pos:2A"), "{line:?}");
        // A zero-sized bar is a no-op.
        let mut empty = Surface::new(1, 1);
        view.paint_cursor_information(&mut empty, 0, 0);
    }

    #[test]
    fn cursor_bar_formats_selection_position_and_percent() {
        let mut view = view(Size::new(120, 12));
        assert!(view.select(4, 8));
        let mut out = [b' '; CURSOR_BAR_CAPACITY];
        let len = format_cursor_bar(&mut out, view.snapshot());
        let text = core::str::from_utf8(&out[..len]).expect("ascii");
        // Selection 4..=11 is 8 bytes; the cursor is still at 0 of 64.
        assert_eq!(text, "Sel:4,8  Pos:0  1%");
    }

    #[test]
    fn go_to_and_select_clamp_to_the_file() {
        let mut view = view(Size::new(120, 12));
        assert!(view.go_to(u64::MAX));
        assert_eq!(view.cursor().current_pos, 63, "clamped to the last byte");
        assert!(view.select(60, 100));
        assert_eq!(view.selection().get_selection(0), Some((60, 63)));
        assert!(!view.select(0, 0), "an empty selection is refused");

        // An empty object never panics and refuses both.
        let mut empty = BufferView::from_settings(
            object_of(b"", "empty.bin"),
            BufferViewSettings::default(),
        );
        OnResize::on_resize(&mut empty, Size::new(0, 0), Size::new(120, 12));
        assert!(!empty.go_to(0));
        assert!(!empty.select(0, 4));
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(120, 12);
        OnPaint::on_paint(&empty, &mut surface, &theme);
    }

    #[test]
    fn the_bottom_bar_slot_follows_the_cursor() {
        let info = SharedCursorInfo::new();
        let mut view = view_with(BufferViewerRequest::default(), info.clone(), Size::new(120, 12));
        assert_eq!(info.read().name_str(), "Buffer");
        assert_eq!(info.read().size, 64);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(info.read().offset, 16);
    }

    #[test]
    fn display_actions_change_columns_and_format() {
        let mut view = view(Size::new(120, 12));
        assert_eq!(view.layout().nr_cols, 16);
        // F6 cycles 16 → 32.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::F6, KeyModifier::None), '\0');
        assert_eq!(view.layout().nr_cols, 32);
        // F2 cycles the numeric format and the ruler with it.
        assert_eq!(view.numbers_header(), HEX_HEADER);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::F2, KeyModifier::None), '\0');
        assert_eq!(view.layout().char_format_mode, CharacterFormatMode::Octal);
        assert_ne!(view.numbers_header(), HEX_HEADER);
    }

    #[test]
    fn address_header_follows_the_translation_methods() {
        let request = BufferViewerRequest {
            translation_methods: vec![String::from("RVA"), String::from("VA")],
            ..BufferViewerRequest::default()
        };
        let mut view = view_with(request, SharedCursorInfo::new(), Size::new(120, 12));
        assert_eq!(view.address_header(), "RVA");
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::F3, KeyModifier::None), '\0');
        assert_eq!(view.address_header(), "VA");
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::F3, KeyModifier::None), '\0');
        assert_eq!(view.address_header(), "RVA", "wraps");
        // With none declared the caption stays `Address`.
        let plain = view_with(
            BufferViewerRequest::default(),
            SharedCursorInfo::new(),
            Size::new(120, 12),
        );
        assert_eq!(plain.address_header(), "Address");
    }

    #[test]
    fn a_click_inside_a_band_moves_the_cursor() {
        let mut view = view(Size::new(120, 12));
        let layout = *view.layout();
        // Text band, row 1 (screen row 2), column 3 → offset 16 + 3.
        let x = layout.x_text.saturating_add(3).cast_signed();
        let event = MouseEvent::Pressed(MouseEventData {
            x,
            y: 2,
            button: MouseButton::Left,
            modifier: KeyModifier::None,
        });
        assert!(processed(OnMouseEvent::on_mouse_event(&mut view, &event)));
        assert_eq!(view.cursor().current_pos, 19);

        // The header row and anything left of the bands are ignored.
        assert!(view.offset_at(x, 0).is_none());
        assert!(view.offset_at(0, 2).is_none() || layout.x_address == 0);
        // Past EOF: the 64-byte fixture has 4 rows of 16.
        assert!(view.offset_at(x, 9).is_none());
    }

    #[test]
    fn the_mouse_wheel_scrolls_the_viewport() {
        let mut view = view(Size::new(120, 6));
        let start = view.cursor().start_view;
        let event = MouseEvent::Wheel(MouseWheelDirection::Down);
        assert!(processed(OnMouseEvent::on_mouse_event(&mut view, &event)));
        assert!(view.cursor().start_view > start, "scrolled down");
        let scrolled = view.cursor().start_view;
        OnMouseEvent::on_mouse_event(&mut view, &MouseEvent::Wheel(MouseWheelDirection::Up));
        assert!(view.cursor().start_view < scrolled, "scrolled back up");
    }

    #[test]
    fn unhandled_keys_are_ignored() {
        let mut view = view(Size::new(120, 12));
        assert!(!processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::F12, KeyModifier::Alt),
            ' '
        )));
    }

    /// The plugin's colourer is fed the row's own bytes, so an opcode
    /// byte inside a code zone paints in the plugin's colour.
    #[test]
    fn the_plugin_colorizer_colours_its_bytes() {
        struct MzMarker;
        impl PositionToColorCallback for MzMarker {
            fn color_for_buffer(&mut self, offset: u64, buf: &[u8]) -> Option<BufferColor> {
                (buf.starts_with(b"MZ")).then_some(BufferColor {
                    start: offset,
                    end: offset.saturating_add(1),
                    color: CharAttribute::with_color(Color::Yellow, Color::DarkRed),
                })
            }
        }
        let request = BufferViewerRequest {
            position_to_color: true,
            ..BufferViewerRequest::default()
        };
        let object = object_of(&fixture(), "sample.bin");
        let mut view = BufferView::from_settings(
            object,
            BufferViewSettings {
                request,
                colorizer: Some(Box::new(MzMarker)),
                ..BufferViewSettings::default()
            },
        );
        OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(120, 12));
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(120, 12);
        OnPaint::on_paint(&view, &mut surface, &theme);
        let layout = view.layout();
        let marked = surface
            .char(layout.x_numbers.cast_signed(), 1)
            .expect("first hex cell");
        assert_eq!(marked.foreground, Color::Yellow);
        assert_eq!(marked.background, Color::DarkRed);
        // The next byte is not an `MZ` start, so it keeps the fallback.
        let plain = surface
            .char(layout.x_numbers.saturating_add(3).cast_signed(), 1)
            .expect("second hex cell");
        assert_ne!(plain.background, Color::DarkRed);
    }

    #[test]
    fn a_find_provider_is_carried_by_the_settings() {
        struct AlwaysAtTen;
        impl FindProvider for AlwaysAtTen {
            fn find_next(&mut self, _cache: &mut DataCache, _from: u64) -> Option<(u64, u64)> {
                Some((10, 2))
            }
        }
        let settings = BufferViewSettings {
            find: Some(Box::new(AlwaysAtTen)),
            ..BufferViewSettings::default()
        };
        assert!(format!("{settings:?}").contains("has_find: true"));
        let mut view = BufferView::from_settings(object_of(&fixture(), "f.bin"), settings);
        let mut cache = DataCache::new(Box::new(MemorySource::new(fixture())), 0);
        let found = view
            .find
            .as_mut()
            .and_then(|provider| provider.find_next(&mut cache, 0));
        assert_eq!(found, Some((10, 2)));
    }

    #[test]
    fn debug_app_paints_the_fixture() {
        let script = "
            Paint.Enable(false)
            Paint('buffer view with the MZ fixture')
            CheckHash(0xA45EBE85D85CD1B0)
        ";
        let mut app = App::debug(100, 14, script).build().expect("debug app");
        let mut window = Window::new("Test", layout!("a:c,w:96,h:12"), window::Flags::None);
        window.add(view(Size::new(96, 10)));
        app.add_window(window);
        app.run();
    }
}
