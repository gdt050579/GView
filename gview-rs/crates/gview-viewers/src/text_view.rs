//! The plain-text viewer control.
//!
//! Spec `00_APP §6.2`; `02_VIEWER_TEXT` §3 (line index), §6 (viewport)
//! and §8 (key matrix). C++ anchor:
//! `GViewCore/src/View/TextViewer/Instance.cpp` — `Paint` (L1252),
//! `DrawLine` (L1148), `OnKeyEvent` (L1292), `OnAfterResize` and
//! `PaintCursorInformation` (L1671).
//!
//! Construction (C++ `Instance::Instance` → `RecomputeLineIndexes`):
//! the first `0x8800` bytes are sniffed with
//! [`analyze_encoding`], and [`build_line_index`] then walks the whole
//! object once to produce the logical-line table. Both run **once**, in
//! [`SmartViewer::from_settings`], because the open pipeline may
//! allocate (`00_APP §7`) while paint and key handling may not
//! (`§6.3`).
//!
//! | Hook | Delegates to |
//! |------|--------------|
//! | `OnResize` | width/height into the [`TextViewContext`], then [`update_view_port`] |
//! | `OnPaint` | one [`CharacterStream`] per visible [`ViewPortLine`] |
//! | `OnKeyPressed` | [`text_action_for_key`] → the `gview_view::text_viewer::input` movers |
//! | `OnMouseEvent` | wheel → [`move_scroll_down`] / [`move_scroll_up`] |
//!
//! `show_find_dialog` returns `false`: the C++ `TextViewer` never
//! implemented one (quirk #4).

use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;

use gview_core::selection::Selection;
use gview_view::text_viewer::input::{
    move_down, move_left, move_right, move_scroll_down, move_scroll_up, move_to,
    move_to_end_of_file, move_to_end_of_line, move_to_next_word, move_to_previous_word,
    move_to_start_of_line, move_up, open_current_selection, text_action_for_key,
    OpenSelectionRequest, TextNavAction,
};
use gview_view::text_viewer::line_index::{
    analyze_encoding, build_line_index, line_number_width, Encoding, LineInfo,
};
use gview_view::text_viewer::viewport::{
    update_view_port, TextCursor, TextViewContext, ViewPort, ViewPortLine,
};
use gview_view::text_viewer::wrap::{CharacterStream, SubLines, WrapMethod};
use gview_view::traits::{SharedObject, SmartViewer, ViewerSettings};
use gview_view::view_control::{clamp_goto, ViewControl, ViewData};

use crate::cursor_info::{CursorSnapshot, SharedCursorInfo};

/// Bytes sniffed for the encoding probe (C++ identification buffer).
pub const ENCODING_SAMPLE_SIZE: u32 = 0x8800;
/// C++ `settings->tabSize` default.
pub const DEFAULT_TAB_SIZE: u32 = 4;
/// Widest cursor bar this control formats without allocating.
const CURSOR_BAR_CAPACITY: usize = 96;

/// What the `FileWindow` hands a [`TextView`] at mount.
///
/// The C++ `TextViewer::Settings` carries only display preferences —
/// the content comes from the window's object — so this is small.
pub struct TextViewSettings {
    /// C++ `SetWrapMethod`.
    pub wrap_method: WrapMethod,
    /// C++ `SetTabSize`.
    pub tab_size: u32,
    /// C++ `highlightCurrentLine`.
    pub highlight_current_line: bool,
    /// The window's bottom-bar slot (`00_APP §5.3.5`).
    pub cursor_info: SharedCursorInfo,
    /// `CreateViewer<T>(name)` override.
    pub custom_name: Option<String>,
}

impl Default for TextViewSettings {
    fn default() -> Self {
        Self {
            wrap_method: WrapMethod::None,
            tab_size: DEFAULT_TAB_SIZE,
            highlight_current_line: true,
            cursor_info: SharedCursorInfo::new(),
            custom_name: None,
        }
    }
}

impl core::fmt::Debug for TextViewSettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TextViewSettings")
            .field("wrap_method", &self.wrap_method)
            .field("tab_size", &self.tab_size)
            .finish_non_exhaustive()
    }
}

impl ViewerSettings for TextViewSettings {
    fn custom_name(&self) -> Option<&str> {
        self.custom_name.as_deref()
    }

    fn set_custom_name(&mut self, name: &str) {
        self.custom_name = Some(name.to_owned());
    }
}

/// The plain-text viewer (C++ `TextViewer::Instance`).
#[CustomControl(overwrite = OnPaint+OnKeyPressed+OnResize+OnMouseEvent, emit = ShowGoTo+ShowFind+ShowCopy+FocusView+OpenSelection)]
pub struct TextView {
    object: SharedObject,
    /// Built once in `from_settings` (C++ `RecomputeLineIndexes`).
    lines: Vec<LineInfo>,
    encoding: Encoding,
    /// Bytes of BOM skipped before line 0.
    bom_size: u32,
    wrap_method: WrapMethod,
    tab_size: u32,
    highlight_current_line: bool,
    line_number_width: u32,
    control_width: u32,
    control_height: u32,
    view_port: Mutex<ViewPort>,
    sub_lines: Mutex<SubLines>,
    cursor: TextCursor,
    selection: Selection,
    name: String,
    cursor_info: SharedCursorInfo,
    /// The last `Enter` request, for the window to service.
    pending_open: Option<OpenSelectionRequest>,
    /// Scratch for `paint_cursor_information`.
    cursor_bar: [u8; CURSOR_BAR_CAPACITY],
}

impl TextView {
    /// Logical lines in the index.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.lines.len()
    }

    /// The detected encoding (C++ `settings->encoding`).
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Bytes of BOM skipped before line 0.
    #[must_use]
    pub const fn bom_size(&self) -> u32 {
        self.bom_size
    }

    /// The cursor (C++ `Cursor`).
    #[must_use]
    pub const fn cursor(&self) -> TextCursor {
        self.cursor
    }

    /// The selection.
    #[must_use]
    pub const fn selection(&self) -> &Selection {
        &self.selection
    }

    /// C++ `settings->wrapMethod`.
    #[must_use]
    pub const fn wrap_method(&self) -> WrapMethod {
        self.wrap_method
    }

    /// Width of the line-number gutter (C++ `lineNumberWidth`).
    #[must_use]
    pub const fn line_number_width(&self) -> u32 {
        self.line_number_width
    }

    /// The `Enter` request the window has not serviced yet.
    #[must_use]
    pub const fn pending_open(&self) -> Option<&OpenSelectionRequest> {
        self.pending_open.as_ref()
    }

    /// Takes the pending `Enter` request (C++ `OpenCurrentSelection`).
    pub const fn take_pending_open(&mut self) -> Option<OpenSelectionRequest> {
        self.pending_open.take()
    }

    /// The visible rows of the current viewport, copied out for tests
    /// and the mount code.
    #[must_use]
    pub fn visible_lines(&self) -> Vec<ViewPortLine> {
        self.view_port
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .lines
            .clone()
    }

    /// Runs `f` with a [`TextViewContext`] over the current state.
    ///
    /// Every mover in `gview_view::text_viewer::input` takes this
    /// context plus the viewport, cursor and selection; funnelling
    /// them through one helper keeps the lock order in a single place.
    fn with_context<R>(
        &mut self,
        f: impl FnOnce(&mut TextViewContext<'_>, &mut ViewPort, &mut TextCursor, &mut Selection) -> R,
    ) -> R {
        let mut object = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        let mut view_port = self.view_port.lock().unwrap_or_else(PoisonError::into_inner);
        let mut sub_lines = self.sub_lines.lock().unwrap_or_else(PoisonError::into_inner);
        let result = {
            let mut ctx = TextViewContext {
                lines: &self.lines,
                cache: object.data_mut(),
                encoding: self.encoding,
                wrap_method: self.wrap_method,
                tab_size: self.tab_size,
                control_width: self.control_width,
                control_height: self.control_height,
                line_number_width: self.line_number_width,
                sub_lines: &mut sub_lines,
            };
            f(&mut ctx, &mut view_port, &mut self.cursor, &mut self.selection)
        };
        drop(sub_lines);
        drop(view_port);
        drop(object);
        result
    }

    /// The bottom-bar snapshot (C++ `PaintCursorInformation` inputs).
    fn snapshot(&self) -> CursorSnapshot {
        let mut snapshot = CursorSnapshot::with_name(&self.name);
        snapshot.offset = self.cursor.pos;
        snapshot.base = 10;
        snapshot.size = {
            let guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            guard.data().size()
        };
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

    /// C++ `CMD_ID_WORD_WRAP`: cycles the wrap method and re-wraps at
    /// the current control width.
    pub fn toggle_word_wrap(&mut self) {
        self.wrap_method = match self.wrap_method {
            WrapMethod::None => WrapMethod::LeftMargin,
            WrapMethod::LeftMargin => WrapMethod::Padding,
            WrapMethod::Padding => WrapMethod::Bullets,
            WrapMethod::Bullets => WrapMethod::None,
        };
        // The sub-line cache describes the previous wrap method.
        self.sub_lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .line_no = gview_view::text_viewer::wrap::INVALID_LINE_NUMBER;
        self.rebuild_view_port();
    }

    /// Recomputes the viewport for the current geometry and cursor
    /// (C++ `OnAfterResize` → `UpdateViewPort`).
    fn rebuild_view_port(&mut self) {
        self.with_context(|ctx, vp, cursor, _selection| {
            vp.reset();
            update_view_port(vp, ctx, cursor);
        });
        self.publish();
    }

    /// Runs one [`TextNavAction`] (C++ `OnKeyEvent`).
    fn navigate(&mut self, action: TextNavAction) -> bool {
        let page = self.control_height.max(1);
        match action {
            TextNavAction::MoveLeft { select } => {
                self.with_context(|c, v, cu, s| move_left(c, v, cu, s, select));
            }
            TextNavAction::MoveRight { select } => {
                self.with_context(|c, v, cu, s| move_right(c, v, cu, s, select));
            }
            TextNavAction::WordLeft { select } => {
                self.with_context(|c, v, cu, s| move_to_previous_word(c, v, cu, s, select));
            }
            TextNavAction::WordRight { select } => {
                self.with_context(|c, v, cu, s| move_to_next_word(c, v, cu, s, select));
            }
            TextNavAction::MoveUp { select } => {
                self.with_context(|c, v, cu, s| move_up(c, v, cu, s, 1, select));
            }
            TextNavAction::MoveDown { select } => {
                self.with_context(|c, v, cu, s| move_down(c, v, cu, s, 1, select));
            }
            TextNavAction::PageUp { select } => {
                self.with_context(|c, v, cu, s| move_up(c, v, cu, s, page, select));
            }
            TextNavAction::PageDown { select } => {
                self.with_context(|c, v, cu, s| move_down(c, v, cu, s, page, select));
            }
            TextNavAction::ScrollUp => {
                self.with_context(move_scroll_up_adapter);
            }
            TextNavAction::ScrollDown => {
                self.with_context(move_scroll_down_adapter);
            }
            TextNavAction::LineStart { select } => {
                let line = self.cursor.line_no;
                self.with_context(|c, v, cu, s| move_to_start_of_line(c, v, cu, s, line, select));
            }
            TextNavAction::LineEnd { select } => {
                let line = self.cursor.line_no;
                self.with_context(|c, v, cu, s| move_to_end_of_line(c, v, cu, s, line, select));
            }
            TextNavAction::FileStart { select } => {
                self.with_context(|c, v, cu, s| move_to(c, v, cu, s, 0, 0, select));
            }
            TextNavAction::FileEnd { select } => {
                self.with_context(|c, v, cu, s| move_to_end_of_file(c, v, cu, s, select));
            }
            TextNavAction::OpenSelection => {
                // C++ `OpenCurrentSelection`: the shell opens the
                // buffer, the viewer only produces the request.
                self.pending_open = open_current_selection(&self.selection, self.cursor);
                if self.pending_open.is_some() {
                    self.raise_event(textview::Events::OpenSelection);
                }
            }
        }
        true
    }

    /// C++ `DrawLine` (`Instance.cpp:1148-1250`) for one visible row.
    fn draw_line(&self, surface: &mut Surface, theme: &Theme, row: DrawRow<'_>) {
        let DrawRow {
            y,
            line,
            show_line_number,
            scroll_x,
            bytes,
        } = row;
        let gutter = self.line_number_width;
        let on_cursor_line = line.line_no == self.cursor.line_no;
        let text_color = if on_cursor_line && self.highlight_current_line {
            theme.editor.focused
        } else {
            theme.text.normal
        };
        let line_no_color = if on_cursor_line && self.highlight_current_line {
            theme.editor.pressed_or_selected
        } else {
            theme.text.inactive
        };
        let y = y.cast_signed();

        // Gutter background, then the 1-based line number, then the
        // vertical separator (C++ L1180-1183).
        surface.fill_horizontal_line(
            0,
            y,
            gutter.saturating_sub(1).cast_signed(),
            Character::with_attributes(' ', line_no_color),
        );
        if show_line_number {
            let mut digits = [b' '; 20];
            let len = write_decimal_right(&mut digits, u64::from(line.line_no).saturating_add(1), gutter as usize);
            surface.write_ascii(0, y, digits.get(..len).unwrap_or(&[]), line_no_color, false);
        }
        surface.write_char(
            gutter.cast_signed(),
            y,
            Character::with_attributes('│', theme.border.normal),
        );

        if bytes.is_empty() {
            return;
        }
        let text_x = gutter.saturating_add(1);
        let mut stream = CharacterStream::new(bytes, 0, self.encoding, self.tab_size);
        // Skip the horizontally scrolled prefix (C++ L1193-1203).
        let mut x_scroll = 0_u32;
        if scroll_x > 0 {
            while stream.next_char() {
                if stream.next_x_offset() >= scroll_x {
                    x_scroll = scroll_x;
                    break;
                }
            }
        }
        let mut buffer_pos = stream.current_buffer_pos();
        while stream.next_char() {
            let column = stream
                .next_x_offset()
                .saturating_sub(1)
                .saturating_add(line.x_start)
                .saturating_sub(x_scroll);
            if column >= self.control_width.saturating_sub(text_x) {
                break;
            }
            let byte_offset = line.offset.saturating_add(u64::from(buffer_pos));
            let at_cursor = on_cursor_line
                && stream.char_index().saturating_add(line.line_char_index) == self.cursor.char_index;
            let color = if self.selection.contains(byte_offset) {
                if at_cursor {
                    theme.editor.hovered
                } else {
                    theme.editor.pressed_or_selected
                }
            } else if at_cursor {
                theme.editor.focused
            } else if stream.is_tab() {
                theme.text.inactive
            } else {
                text_color
            };
            let glyph = char::from_u32(stream.character()).unwrap_or('.');
            // A TAB paints as blanks; its column advance already
            // accounted for the width (C++ `CharacterStream`).
            let glyph = if stream.is_tab() { ' ' } else { glyph };
            surface.write_char(
                text_x.saturating_add(column).cast_signed(),
                y,
                Character::with_attributes(glyph, color),
            );
            buffer_pos = stream.current_buffer_pos();
        }
    }
}

/// One visible row's paint inputs, bundled so `draw_line` keeps a
/// readable signature.
#[derive(Clone, Copy)]
struct DrawRow<'a> {
    /// Screen row.
    y: u32,
    /// The viewport entry.
    line: ViewPortLine,
    /// Whether this row starts a new logical line (C++
    /// `cLineNo != lineNo`).
    show_line_number: bool,
    /// C++ `ViewPort.scrollX`.
    scroll_x: u32,
    /// The fragment's bytes, borrowed from the cache.
    bytes: &'a [u8],
}

/// `move_scroll_up` with the argument order [`TextView::with_context`]
/// hands out.
fn move_scroll_up_adapter(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
) {
    move_scroll_up(ctx, vp, cursor, selection);
}

/// `move_scroll_down` with the argument order
/// [`TextView::with_context`] hands out.
fn move_scroll_down_adapter(
    ctx: &mut TextViewContext<'_>,
    vp: &mut ViewPort,
    cursor: &mut TextCursor,
    selection: &mut Selection,
) {
    move_scroll_down(ctx, vp, cursor, selection);
}

/// Writes `value` right-aligned in `width` cells of `out`, returning
/// the used length (C++ `WriteSingleLineText(..., TextAlignament::Right)`).
fn write_decimal_right(out: &mut [u8; 20], value: u64, width: usize) -> usize {
    let width = width.min(out.len());
    let mut digits = [b'0'; 20];
    let mut count = 0_usize;
    let mut rest = value;
    loop {
        let digit = b'0'.saturating_add(rest.checked_rem(10).unwrap_or(0) as u8);
        if let Some(slot) = digits.get_mut(count) {
            *slot = digit;
        }
        count = count.saturating_add(1);
        rest = rest.checked_div(10).unwrap_or(0);
        if rest == 0 || count >= digits.len() {
            break;
        }
    }
    let pad = width.saturating_sub(count);
    for slot in out.iter_mut().take(pad) {
        *slot = b' ';
    }
    for index in 0..count.min(width) {
        let digit = digits
            .get(count.saturating_sub(index).saturating_sub(1))
            .copied()
            .unwrap_or(b'0');
        if let Some(slot) = out.get_mut(pad.saturating_add(index)) {
            *slot = digit;
        }
    }
    width
}

impl SmartViewer for TextView {
    type Settings = TextViewSettings;

    fn from_settings(object: SharedObject, settings: Self::Settings) -> Self {
        let TextViewSettings {
            wrap_method,
            tab_size,
            highlight_current_line,
            cursor_info,
            custom_name,
        } = settings;
        // C++ `Instance::Instance`: sniff the encoding on the leading
        // sample, then index every line. Both allocate; the open
        // pipeline allows that (`00_APP §7`), paint does not.
        let (encoding_info, lines) = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            let cache = guard.data_mut();
            let sample = cache
                .get(0, ENCODING_SAMPLE_SIZE, false)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            let info = analyze_encoding(&sample);
            let lines = build_line_index(cache, info.encoding, info.bom_size);
            let result = (info, lines);
            drop(guard);
            result
        };
        let view = Self {
            base: ControlBase::with_focus_overlay(layout!("d:f")),
            object,
            line_number_width: line_number_width(lines.len()),
            lines,
            encoding: encoding_info.encoding,
            bom_size: encoding_info.bom_size,
            wrap_method,
            tab_size: if tab_size == 0 { DEFAULT_TAB_SIZE } else { tab_size },
            highlight_current_line,
            control_width: 1,
            control_height: 1,
            view_port: Mutex::new(ViewPort::default()),
            sub_lines: Mutex::new(SubLines::default()),
            cursor: TextCursor::default(),
            selection: Selection::new(),
            name: custom_name.unwrap_or_else(|| String::from("Text")),
            cursor_info,
            pending_open: None,
            cursor_bar: [b' '; CURSOR_BAR_CAPACITY],
        };
        view.publish();
        view
    }
}

impl ViewControl for TextView {
    fn name(&self) -> &str {
        &self.name
    }

    /// C++ `GoTo(offset)`: finds the line containing `offset` and puts
    /// the cursor at its start.
    fn go_to(&mut self, offset: u64) -> bool {
        if self.lines.is_empty() {
            return false;
        }
        let size = {
            let guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            guard.data().size()
        };
        let target = clamp_goto(offset, size);
        // The index is ascending by offset: the last line that starts
        // at or before `target` owns it.
        let line_no = self
            .lines
            .partition_point(|line| line.offset <= target)
            .saturating_sub(1);
        let line_no = u32::try_from(line_no).unwrap_or(0);
        self.with_context(|c, v, cu, s| move_to(c, v, cu, s, line_no, 0, false));
        self.publish();
        true
    }

    fn select(&mut self, offset: u64, size: u64) -> bool {
        if size == 0 || self.lines.is_empty() {
            return false;
        }
        let file_size = {
            let guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            guard.data().size()
        };
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

    fn show_goto_dialog(&mut self) -> bool {
        self.raise_event(textview::Events::ShowGoTo);
        true
    }

    /// Quirk #4: the C++ `TextViewer::ShowFindDialog` is an empty stub,
    /// so the Rust port refuses rather than inventing a dialog.
    fn show_find_dialog(&mut self) -> bool {
        false
    }

    fn show_copy_dialog(&mut self) -> bool {
        self.raise_event(textview::Events::ShowCopy);
        true
    }

    /// C++ `PaintCursorInformation` (`Instance.cpp:1671+`) for the
    /// one-line bar: the selection field, then the line / column.
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let cursor = self.cursor;
        let snapshot = self.snapshot();
        let len = format_text_cursor_bar(&mut self.cursor_bar, snapshot, cursor);
        let text = self.cursor_bar.get(..len).unwrap_or(&[]);
        surface.write_ascii(0, 0, text, CharAttribute::default(), false);
    }

    fn view_data(&self, data: &mut ViewData, offset: u64) -> bool {
        let byte = {
            let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            guard
                .data_mut()
                .get(offset, 1, true)
                .ok()
                .and_then(|b| b.first().copied())
        };
        let Some(byte) = byte else {
            return false;
        };
        let view_port = self.view_port.lock().unwrap_or_else(PoisonError::into_inner);
        data.view_start_offset = view_port.lines.first().map_or(0, |line| line.offset);
        data.view_size = view_port
            .lines
            .iter()
            .map(|line| u64::from(line.size))
            .sum::<u64>();
        data.cursor_start_offset = self.cursor.pos;
        data.byte = byte;
        drop(view_port);
        true
    }
}

/// Formats `"NO Selection  Ln:<line>  Col:<char>"` (or the selection
/// range) into `out` without allocating, returning the length.
/// Mirrors the field order of the C++ one-line
/// `PaintCursorInformation` (`Instance.cpp:1671-1700`).
fn format_text_cursor_bar(
    out: &mut [u8; CURSOR_BAR_CAPACITY],
    snapshot: CursorSnapshot,
    cursor: TextCursor,
) -> usize {
    let mut len = 0_usize;
    let push = |bytes: &[u8], out: &mut [u8; CURSOR_BAR_CAPACITY], len: &mut usize| {
        for byte in bytes {
            if let Some(slot) = out.get_mut(*len) {
                *slot = *byte;
                *len = len.saturating_add(1);
            }
        }
    };
    if snapshot.has_selection {
        push(b"Sel:", out, &mut len);
        len = push_decimal(out, len, snapshot.selection_start);
        push(b",", out, &mut len);
        len = push_decimal(out, len, snapshot.selection_len());
    } else {
        push(b"NO Selection", out, &mut len);
    }
    push(b"  Ln:", out, &mut len);
    len = push_decimal(out, len, u64::from(cursor.line_no).saturating_add(1));
    push(b"  Col:", out, &mut len);
    len = push_decimal(out, len, u64::from(cursor.char_index).saturating_add(1));
    len
}

/// Appends `value` in decimal, bounded by the buffer.
fn push_decimal(out: &mut [u8; CURSOR_BAR_CAPACITY], mut len: usize, value: u64) -> usize {
    let mut digits = [b'0'; 20];
    let mut count = 0_usize;
    let mut rest = value;
    loop {
        let digit = b'0'.saturating_add(rest.checked_rem(10).unwrap_or(0) as u8);
        if let Some(slot) = digits.get_mut(count) {
            *slot = digit;
        }
        count = count.saturating_add(1);
        rest = rest.checked_div(10).unwrap_or(0);
        if rest == 0 || count >= digits.len() {
            break;
        }
    }
    for index in (0..count).rev() {
        if let Some(slot) = out.get_mut(len) {
            *slot = digits.get(index).copied().unwrap_or(b'0');
            len = len.saturating_add(1);
        }
    }
    len
}

impl OnResize for TextView {
    fn on_resize(&mut self, _old: Size, new: Size) {
        self.control_width = new.width.max(1);
        self.control_height = new.height.max(1);
        self.rebuild_view_port();
    }
}

impl OnPaint for TextView {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.editor.normal));
        let view_port = self.view_port.lock().unwrap_or_else(PoisonError::into_inner);
        let scroll_x = view_port.scroll_x;
        let mut previous_line = None;
        let mut object = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        for (row, line) in view_port.lines.iter().enumerate() {
            let show_line_number = previous_line != Some(line.line_no);
            previous_line = Some(line.line_no);
            let bytes = if line.size == 0 {
                &[][..]
            } else {
                object.data_mut().get(line.offset, line.size, false).unwrap_or(&[])
            };
            self.draw_line(
                surface,
                theme,
                DrawRow {
                    y: row as u32,
                    line: *line,
                    show_line_number,
                    scroll_x,
                    bytes,
                },
            );
        }
        drop(object);
        drop(view_port);
    }
}

impl OnKeyPressed for TextView {
    fn on_key_pressed(&mut self, key: Key, _character: char) -> EventProcessStatus {
        if let Some(event) = shell_event_for_key(key) {
            self.raise_event(event);
            return EventProcessStatus::Processed;
        }
        // C++ `CMD_ID_WORD_WRAP` is bound to a configurable key; the
        // default binding is Ctrl+W.
        if key == Key::new(KeyCode::W, KeyModifier::Ctrl) {
            self.toggle_word_wrap();
            self.request_update();
            return EventProcessStatus::Processed;
        }
        let Some(action) = text_action_for_key(key) else {
            return EventProcessStatus::Ignored;
        };
        self.navigate(action);
        self.publish();
        self.request_update();
        EventProcessStatus::Processed
    }
}

/// The window-level shortcut a key maps to, if any (C++
/// `FileWindow::OnKeyEvent`). `Ctrl+F` is deliberately absent: the
/// text viewer has no find dialog (quirk #4).
fn shell_event_for_key(key: Key) -> Option<textview::Events> {
    if key == Key::new(KeyCode::Escape, KeyModifier::None) {
        return Some(textview::Events::FocusView);
    }
    if key == Key::new(KeyCode::G, KeyModifier::Ctrl) {
        return Some(textview::Events::ShowGoTo);
    }
    if key == Key::new(KeyCode::C, KeyModifier::Ctrl) || key == Key::new(KeyCode::Insert, KeyModifier::Ctrl) {
        return Some(textview::Events::ShowCopy);
    }
    None
}

impl OnMouseEvent for TextView {
    fn on_mouse_event(&mut self, event: &MouseEvent) -> EventProcessStatus {
        let handled = match event {
            MouseEvent::Wheel(MouseWheelDirection::Down) => {
                self.with_context(move_scroll_down_adapter);
                true
            }
            MouseEvent::Wheel(MouseWheelDirection::Up) => {
                self.with_context(move_scroll_up_adapter);
                true
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
    use super::{format_text_cursor_bar, TextView, TextViewSettings, CURSOR_BAR_CAPACITY};
    use crate::cursor_info::SharedCursorInfo;
    use appcui::prelude::*;
    use gview_core::object::Object;
    use gview_view::text_viewer::line_index::Encoding;
    use gview_view::text_viewer::wrap::WrapMethod;
    use gview_view::traits::{SharedObject, SmartViewer};
    use gview_view::view_control::ViewControl;
    use std::sync::{Arc, Mutex as StdMutex};

    fn processed(status: EventProcessStatus) -> bool {
        status == EventProcessStatus::Processed
    }

    fn object_of(bytes: &[u8]) -> SharedObject {
        Arc::new(StdMutex::new(Object::from_buffer(bytes, "sample.txt", 0)))
    }

    fn view_of(bytes: &[u8], size: Size) -> TextView {
        view_with(bytes, size, TextViewSettings::default())
    }

    fn view_with(bytes: &[u8], size: Size, settings: TextViewSettings) -> TextView {
        let mut view = TextView::from_settings(object_of(bytes), settings);
        OnResize::on_resize(&mut view, Size::new(0, 0), size);
        view
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
    fn a_utf8_fixture_indexes_and_paints_three_lines() {
        let view = view_of(b"alpha\nbeta\ngamma\n", Size::new(60, 6));
        // Pure 7-bit content with no BOM is `Ascii`, not `Utf8`
        // (C++ `AnalyzeBufferForEncoding` only promotes to UTF-8 for
        // a BOM or a valid multi-byte sequence).
        assert_eq!(view.encoding(), Encoding::Ascii);
        assert_eq!(view.bom_size(), 0);
        assert_eq!(view.line_count(), 3, "the trailing newline ends line 3");

        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(60, 6);
        OnPaint::on_paint(&view, &mut surface, &theme);
        let text_x = view.line_number_width().saturating_add(1);
        assert_eq!(read(&surface, text_x, 0, 5), "alpha");
        assert_eq!(read(&surface, text_x, 1, 4), "beta");
        assert_eq!(read(&surface, text_x, 2, 5), "gamma");
        // The gutter carries the 1-based line number.
        let gutter = view.line_number_width() as usize;
        assert_eq!(read(&surface, 0, 0, gutter).trim(), "1");
        assert_eq!(read(&surface, 0, 1, gutter).trim(), "2");
    }

    #[test]
    fn a_utf8_bom_is_skipped_before_the_first_line() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"hello\nworld\n");
        let view = view_of(&bytes, Size::new(60, 6));
        assert_eq!(view.encoding(), Encoding::Utf8);
        assert_eq!(view.bom_size(), 3, "the BOM is not part of line 0");
        assert_eq!(view.line_count(), 2);

        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(60, 6);
        OnPaint::on_paint(&view, &mut surface, &theme);
        let text_x = view.line_number_width().saturating_add(1);
        assert_eq!(read(&surface, text_x, 0, 5), "hello", "the BOM is not painted");
    }

    #[test]
    fn mixed_crlf_lf_and_cr_terminators_index_correctly() {
        // `a\r\n` `bb\n` `ccc\r` `dddd`
        let view = view_of(b"a\r\nbb\nccc\rdddd", Size::new(60, 8));
        assert_eq!(view.line_count(), 4);
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(60, 8);
        OnPaint::on_paint(&view, &mut surface, &theme);
        let text_x = view.line_number_width().saturating_add(1);
        assert_eq!(read(&surface, text_x, 0, 1), "a");
        assert_eq!(read(&surface, text_x, 1, 2), "bb");
        assert_eq!(read(&surface, text_x, 2, 3), "ccc");
        assert_eq!(read(&surface, text_x, 3, 4), "dddd");
    }

    #[test]
    fn ctrl_right_moves_by_words() {
        let mut view = view_of(b"alpha beta gamma\n", Size::new(60, 6));
        assert_eq!(view.cursor().char_index, 0);
        assert!(processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::Right, KeyModifier::Ctrl),
            '\0'
        )));
        let after_first = view.cursor().char_index;
        assert!(after_first > 0, "moved off the first word");
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Right, KeyModifier::Ctrl), '\0');
        assert!(view.cursor().char_index > after_first, "moved again");
        // Ctrl+Left comes back.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Left, KeyModifier::Ctrl), '\0');
        assert!(view.cursor().char_index < view.cursor().char_index.saturating_add(1));
    }

    #[test]
    fn plain_arrows_and_page_keys_move_the_cursor() {
        let mut body = String::new();
        for i in 0..40 {
            body.push_str("line ");
            body.push_str(&i.to_string());
            body.push('\n');
        }
        let mut view = view_of(body.as_bytes(), Size::new(60, 10));
        assert_eq!(view.line_count(), 40);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(view.cursor().line_no, 1);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageDown, KeyModifier::None), '\0');
        assert!(view.cursor().line_no > 1);
        let after_page = view.cursor().line_no;
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageUp, KeyModifier::None), '\0');
        assert!(view.cursor().line_no < after_page);
        // Ctrl+End lands on the last line.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::End, KeyModifier::Ctrl), '\0');
        assert_eq!(view.cursor().line_no, 39);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Home, KeyModifier::Ctrl), '\0');
        assert_eq!(view.cursor().line_no, 0);
    }

    #[test]
    fn the_word_wrap_toggle_rewraps_at_the_control_width() {
        let long = format!("{}\n", "word ".repeat(30));
        let mut view = view_of(long.as_bytes(), Size::new(30, 8));
        assert_eq!(view.wrap_method(), WrapMethod::None);
        // Unwrapped: the single logical line occupies one row.
        assert_eq!(view.visible_lines().len(), 1);

        view.toggle_word_wrap();
        assert_eq!(view.wrap_method(), WrapMethod::LeftMargin);
        let wrapped = view.visible_lines();
        assert!(wrapped.len() > 1, "the long line now spans rows: {}", wrapped.len());
        assert!(wrapped.iter().all(|row| row.line_no == 0), "all from line 0");

        // The cycle returns to None.
        for expected in [WrapMethod::Padding, WrapMethod::Bullets, WrapMethod::None] {
            view.toggle_word_wrap();
            assert_eq!(view.wrap_method(), expected);
        }
        assert_eq!(view.visible_lines().len(), 1);
    }

    #[test]
    fn an_empty_file_paints_nothing_and_never_panics() {
        let mut view = view_of(b"", Size::new(60, 6));
        assert_eq!(view.line_count(), 0);
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(60, 6);
        OnPaint::on_paint(&view, &mut surface, &theme);
        // Nothing was drawn past the gutter.
        let text_x = view.line_number_width().saturating_add(1);
        assert_eq!(read(&surface, text_x, 0, 4).trim(), "");
        // Every navigation is a safe no-op.
        for code in [KeyCode::Down, KeyCode::Up, KeyCode::Right, KeyCode::Left, KeyCode::End] {
            OnKeyPressed::on_key_pressed(&mut view, Key::new(code, KeyModifier::None), '\0');
        }
        assert_eq!(view.cursor().line_no, 0);
        assert!(!view.go_to(10));
        assert!(!view.select(0, 4));
    }

    /// Quirk #4: the C++ `TextViewer` never implemented a find dialog.
    #[test]
    fn the_find_dialog_is_refused() {
        let mut view = view_of(b"alpha\n", Size::new(60, 6));
        assert!(!view.show_find_dialog());
        assert!(view.show_goto_dialog());
        assert!(view.show_copy_dialog());
        // Ctrl+F is therefore not a shell shortcut here.
        assert!(!processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::F, KeyModifier::Ctrl),
            '\0'
        )));
    }

    #[test]
    fn go_to_lands_on_the_line_owning_the_offset() {
        let view_bytes = b"alpha\nbeta\ngamma\n";
        let mut view = view_of(view_bytes, Size::new(60, 6));
        // Offset 8 is inside "beta" (line 1, bytes 6..=9).
        assert!(view.go_to(8));
        assert_eq!(view.cursor().line_no, 1);
        assert!(view.go_to(0));
        assert_eq!(view.cursor().line_no, 0);
        // Past EOF clamps to the last line.
        assert!(view.go_to(u64::MAX));
        assert_eq!(view.cursor().line_no, 2);
    }

    #[test]
    fn select_clamps_and_feeds_the_bottom_bar() {
        let info = SharedCursorInfo::new();
        let settings = TextViewSettings {
            cursor_info: info.clone(),
            ..TextViewSettings::default()
        };
        let mut view = view_with(b"alpha\nbeta\n", Size::new(60, 6), settings);
        assert_eq!(info.read().name_str(), "Text");
        assert!(view.select(2, 100));
        assert_eq!(view.selection().get_selection(0), Some((2, 10)));
        assert!(info.read().has_selection);
        assert_eq!(info.read().selection_start, 2);
    }

    #[test]
    fn the_cursor_bar_shows_the_line_and_column() {
        let mut view = view_of(b"alpha\nbeta\n", Size::new(60, 6));
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Right, KeyModifier::None), '\0');
        let mut out = [b' '; CURSOR_BAR_CAPACITY];
        let len = format_text_cursor_bar(&mut out, view.snapshot(), view.cursor());
        let text = core::str::from_utf8(&out[..len]).expect("ascii");
        assert_eq!(text, "NO Selection  Ln:2  Col:2");

        let mut surface = Surface::new(60, 1);
        view.paint_cursor_information(&mut surface, 60, 1);
        assert!(read(&surface, 0, 0, 25).starts_with("NO Selection  Ln:2"));
        // A zero-sized bar is a no-op.
        let mut empty = Surface::new(1, 1);
        view.paint_cursor_information(&mut empty, 0, 0);
    }

    #[test]
    fn enter_raises_an_open_request_for_the_selection() {
        let mut view = view_of(b"alpha\nbeta\n", Size::new(60, 6));
        assert!(view.pending_open().is_none());
        // Nothing selected: no request.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Enter, KeyModifier::None), '\0');
        assert!(view.pending_open().is_none());

        assert!(view.select(0, 5));
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Enter, KeyModifier::None), '\0');
        let request = view.take_pending_open().expect("open request");
        assert_eq!(request.start, 0);
        assert_eq!(request.size, 5);
        assert!(view.pending_open().is_none(), "taken once");
    }

    #[test]
    fn the_mouse_wheel_scrolls_the_viewport() {
        let mut body = String::new();
        for i in 0..60 {
            body.push_str("line ");
            body.push_str(&i.to_string());
            body.push('\n');
        }
        let mut view = view_of(body.as_bytes(), Size::new(60, 8));
        let first = view.visible_lines().first().map(|line| line.line_no);
        assert_eq!(first, Some(0));
        assert!(processed(OnMouseEvent::on_mouse_event(
            &mut view,
            &MouseEvent::Wheel(MouseWheelDirection::Down)
        )));
        let scrolled = view.visible_lines().first().map(|line| line.line_no);
        assert!(scrolled > first, "scrolled down: {scrolled:?}");
        OnMouseEvent::on_mouse_event(&mut view, &MouseEvent::Wheel(MouseWheelDirection::Up));
        assert_eq!(view.visible_lines().first().map(|line| line.line_no), first);
    }

    #[test]
    fn unhandled_keys_are_ignored() {
        let mut view = view_of(b"alpha\n", Size::new(60, 6));
        assert!(!processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::F12, KeyModifier::Alt),
            '\0'
        )));
    }

    #[test]
    fn debug_app_paints_the_fixture() {
        let script = "
            Paint.Enable(false)
            Paint('text view with three lines')
            CheckHash(0xE92A877705555804)
        ";
        let mut app = App::debug(60, 10, script).build().expect("debug app");
        let mut window = Window::new("Test", layout!("a:c,w:56,h:8"), window::Flags::None);
        window.add(view_of(b"alpha\nbeta\ngamma\n", Size::new(54, 6)));
        app.add_window(window);
        app.run();
    }
}
