//! `DissasmViewer` keyboard matrix and viewport cursor
//! (spec `02_VIEWER_DISSASM` §8, §9, §11).
//!
//! C++ anchors: `Instance::OnKeyEvent` / `MoveTo` / `MoveScrollTo` /
//! `OnMouseWheel` (`DissasmKeyEvents.cpp`), command table
//! (`Config.hpp:7-20`, `131-174`), `CursorDissasm`
//! (`DissasmViewer.hpp:515-529`, `Instance.cpp:1570-1573`),
//! `ProcessSpaceKey` (`Instance.cpp:1532-1568`),
//! `DissasmZoneProcessSpaceKey` jump-target parsing and landing
//! (`DissasmX86.cpp:960-1053`), `GetZonesIndexesFromLinePosition`
//! (`Instance.cpp:1226-1254`), `RecomputeDissasmLayout`
//! (`Instance.cpp:1445-1451`).
//!
//! Everything that needs a disassembler or a dialog is surfaced to
//! the shell as a [`DissasmKeyResponse`]; cursor movement, viewport
//! scrolling and the jump history are resolved here.

use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::selection::Selection;

use super::jumps::{CursorState, JumpsHolder};
use super::struct_collapse::{change_zone_collapse_state, CollapseOutcome};
use super::zone::{DissasmParseZoneType, ZoneEntry};

/// C++ `COMMAND_*` IDs (`Config.hpp:7-20`).
pub mod command_id {
    /// F6 (disabled in C++).
    pub const ADD_NEW_TYPE: u32 = 100;
    /// F9 (disabled in C++).
    pub const ADD_SHOW_FILE_CONTENT: u32 = 101;
    /// F8.
    pub const EXPORT_ASM_FILE: u32 = 102;
    /// Ctrl+Q.
    pub const JUMP_BACK: u32 = 103;
    /// Ctrl+E.
    pub const JUMP_FORWARD: u32 = 104;
    /// F2.
    pub const DISSAM_GOTO_ENTRYPOINT: u32 = 105;
    /// C.
    pub const ADD_OR_EDIT_COMMENT: u32 = 106;
    /// Delete.
    pub const REMOVE_COMMENT: u32 = 107;
    /// F1 (disabled in C++).
    pub const AVAILABLE_KEYS: u32 = 108;
    /// F7.
    pub const SHOW_ONLY_DISSASM: u32 = 109;
    /// Ctrl+S.
    pub const SAVE_DISSASM_CACHE: u32 = 110;
    /// Ctrl+K.
    pub const QUERY_FUNCTION_NAME: u32 = 111;
    /// Ctrl+L.
    pub const QUERY_MITRE_TECHNIQUE: u32 = 112;
    /// N.
    pub const RENAME_LABEL: u32 = 113;
}

/// C++ `LayoutDissasm` (`DissasmViewer.hpp:414-422`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayoutDissasm {
    /// Rows available for content (`height - 1`).
    pub visible_rows: u32,
    /// `width - 1`.
    pub total_characters_per_line: u32,
    /// Characters per text line after the left margin.
    pub text_size: u32,
    /// Left margin (C++ init 5).
    pub starting_text_line_offset: u32,
    /// Structures start collapsed (C++ init `true`).
    pub structures_initial_collapsed_state: bool,
    /// Document line count (`UpdateLayoutTotalLines`).
    pub total_lines_size: u32,
}

impl LayoutDissasm {
    /// The C++ constructor defaults (`Instance.cpp:188-193`).
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            visible_rows: 1,
            total_characters_per_line: 1,
            text_size: 1,
            starting_text_line_offset: 5,
            structures_initial_collapsed_state: true,
            total_lines_size: 0,
        }
    }

    /// C++ `RecomputeDissasmLayout` (`Instance.cpp:1445-1451`).
    pub const fn recompute(&mut self, width: u32, height: u32) {
        self.visible_rows = height.saturating_sub(1);
        self.total_characters_per_line = width.saturating_sub(1);
        let widest = if self.total_characters_per_line > self.starting_text_line_offset {
            self.total_characters_per_line
        } else {
            self.starting_text_line_offset
        };
        self.text_size = widest.saturating_sub(self.starting_text_line_offset);
    }
}

/// C++ `LinePosition` — a document line plus a column.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinePosition {
    /// Document line.
    pub line: u32,
    /// Column offset within the line.
    pub offset: u32,
}

impl LinePosition {
    /// C++ `LinePositionToOffset` (`Instance.cpp:229-232`).
    #[must_use]
    pub const fn to_offset(self, text_size: u32) -> u64 {
        (self.line as u64)
            .saturating_mul(text_size as u64)
            .saturating_add(self.offset as u64)
    }
}

/// C++ `CursorDissasm` (`DissasmViewer.hpp:515-529`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CursorDissasm {
    /// First document line in view.
    pub start_view_line: u32,
    /// Cursor row inside the view.
    pub line_in_view: u32,
    /// Cursor column.
    pub offset: u32,
    /// Set when the viewport scrolled (drives the pre-cache
    /// Clear-vs-Reset).
    pub has_moved_view: bool,
}

impl CursorDissasm {
    /// C++ `ToLinePosition` (`Instance.cpp:1570-1573`).
    #[must_use]
    pub const fn to_line_position(self) -> LinePosition {
        LinePosition {
            line: self.start_view_line.saturating_add(self.line_in_view),
            offset: self.offset,
        }
    }

    /// C++ `saveState`.
    #[must_use]
    pub const fn save_state(self) -> CursorState {
        CursorState {
            start_view_line: self.start_view_line,
            line_in_view: self.line_in_view,
        }
    }

    /// C++ `restorePosition`.
    pub const fn restore_position(&mut self, old_state: CursorState) {
        self.line_in_view = old_state.line_in_view;
        self.start_view_line = old_state.start_view_line;
    }
}

/// C++ `ZoneLocation` (`DissasmViewer.hpp:556-560`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneLocation {
    /// Index into `parseZones`.
    pub zone_index: u32,
    /// First covered line, relative to the zone start.
    pub starting_line: u32,
    /// Last covered line, relative to the zone start.
    pub ending_line: u32,
}

/// C++ `GetZonesIndexesFromLinePosition` (`Instance.cpp:1226-1254`):
/// the zones intersecting `[line_start, line_end]` with the
/// zone-relative covered span (`line_end < line_start` is clamped).
#[must_use]
pub fn zones_from_line_position(
    zones: &[ZoneEntry],
    line_start: u32,
    line_end: u32,
) -> Vec<ZoneLocation> {
    let line_end = u32::max(line_end, line_start);
    let zones_count = zones.len() as u32;
    let mut result: Vec<ZoneLocation> = Vec::new();
    let mut zone_index: u32 = 0;
    while zone_index < zones_count
        && zones
            .get(zone_index as usize)
            .is_some_and(|z| line_start >= z.header().ending_line_index)
    {
        zone_index = zone_index.saturating_add(1);
    }
    let mut line = line_start;
    while line <= line_end && zone_index < zones_count {
        let Some(zone) = zones.get(zone_index as usize) else {
            break;
        };
        let header = zone.header();
        if header.start_line_index <= line
            && line < header.ending_line_index
            && result.last().is_none_or(|last| last.zone_index != zone_index)
        {
            let rel = line.saturating_sub(header.start_line_index);
            result.push(ZoneLocation {
                zone_index,
                starting_line: rel,
                ending_line: rel,
            });
        } else if line >= header.ending_line_index {
            zone_index = zone_index.saturating_add(1);
        } else if let Some(last) = result.last_mut() {
            last.ending_line = last.ending_line.saturating_add(1);
        }
        if line == u32::MAX {
            break;
        }
        line = line.saturating_add(1);
    }
    result
}

/// What the shell must do after a key (dialogs, disassembler-backed
/// actions and plugin callbacks live outside this module).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DissasmKeyResponse {
    /// Not a viewer key — forward to `ViewControl`.
    NotHandled,
    /// Consumed; state already updated.
    Handled,
    /// Space / F2: follow the jump on the cursor line (or go to the
    /// zone entry point) — see [`DissasmInput::process_space_key`].
    ProcessSpaceKey {
        /// `true` for F2 (`COMMAND_DISSAM_GOTO_ENTRYPOINT`).
        go_to_entry_point: bool,
    },
    /// Enter: export the selection to a temp buffer.
    OpenSelection,
    /// X: add a collapsible zone over the selection.
    AddCollapsibleZone,
    /// C: comment dialog.
    AddOrEditComment,
    /// Delete: remove the comment on the cursor line.
    RemoveComment,
    /// N: rename dialog.
    RenameLabel,
    /// Ctrl+S / Escape: persist the sidecar cache (Escape is also
    /// forwarded to `ViewControl` afterwards — see
    /// [`DissasmInput::escape_forwards`]).
    SaveCache,
    /// F7: `ShowOnlyDissasm` toggled (new value).
    ShowOnlyDissasm(bool),
    /// F8: export the disassembly text.
    ExportAsmFile,
    /// Ctrl+K: LLM function-name query.
    QueryFunctionName,
    /// Ctrl+L: LLM MITRE query.
    QueryMitreTechnique,
}

/// Outcome of `ProcessSpaceKey` zone resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpaceKeyOutcome {
    /// Cursor is not on exactly one zone (C++ warning box).
    NotSingleZone,
    /// The zone was collapsed/expanded (title line) — no jump.
    ToggledZone,
    /// A structure/text zone: nothing to follow (C++ warns on F2).
    NotCodeZone,
    /// Follow the jump inside code zone `zone_index` at the
    /// zone-relative `starting_line` (`offset_to_reach` set for F2).
    FollowJump {
        /// Index into `parseZones`.
        zone_index: u32,
        /// Zone-relative line of the cursor.
        starting_line: u32,
        /// `Some(entryPoint)` for F2, `None` for Space.
        offset_to_reach: Option<u64>,
    },
}

/// Mouse wheel directions (spec §8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseWheel {
    /// Wheel up.
    Up,
    /// Wheel down.
    Down,
    /// Wheel left.
    Left,
    /// Wheel right.
    Right,
}

/// The C++ `Instance` input state: cursor, layout, jump history,
/// selection and the `ShowOnlyDissasm` flag.
pub struct DissasmInput {
    /// C++ `Cursor`.
    pub cursor: CursorDissasm,
    /// C++ `Layout`.
    pub layout: LayoutDissasm,
    /// C++ `jumps_holder`.
    pub jumps: JumpsHolder,
    /// Selection over line-position offsets.
    pub selection: Selection,
    /// C++ `config.ShowOnlyDissasm`.
    pub show_only_dissasm: bool,
}

impl Default for DissasmInput {
    fn default() -> Self {
        Self::new()
    }
}

fn to_i32(value: u32) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

impl DissasmInput {
    /// Fresh state with the C++ layout defaults.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cursor: CursorDissasm::default(),
            layout: LayoutDissasm::initial(),
            jumps: JumpsHolder::default(),
            selection: Selection::new(),
            show_only_dissasm: false,
        }
    }

    /// C++ `MoveScrollTo` (`DissasmKeyEvents.cpp:88-123`): moves the
    /// cursor by `lines`/`offset`, rolling overflow into
    /// `start_view_line` and flagging `has_moved_view`.
    pub fn move_scroll_to(&mut self, offset: i32, lines: i32) {
        if self.layout.total_lines_size == 0 {
            return;
        }
        self.cursor.has_moved_view = false;
        self.cursor.offset = self.cursor.offset.wrapping_add_signed(offset);
        if lines < 0 {
            let line_in_view = to_i32(self.cursor.line_in_view);
            if lines.saturating_neg() >= line_in_view {
                let remaining = lines.saturating_add(line_in_view);
                self.cursor.line_in_view = 0;
                if remaining != 0 {
                    self.cursor.start_view_line =
                        self.cursor.start_view_line.wrapping_add_signed(remaining);
                    self.cursor.has_moved_view = true;
                }
            } else {
                self.cursor.line_in_view = self.cursor.line_in_view.wrapping_add_signed(lines);
            }
        } else {
            self.cursor.line_in_view = self.cursor.line_in_view.wrapping_add_signed(lines);
            let last_row = self.layout.visible_rows.saturating_sub(1);
            if self.cursor.line_in_view > last_row {
                let diff = self.cursor.line_in_view.abs_diff(last_row);
                self.cursor.start_view_line = self.cursor.start_view_line.saturating_add(diff);
                self.cursor.line_in_view = self.cursor.line_in_view.saturating_sub(diff);
                self.cursor.has_moved_view = true;
            }
        }
    }

    /// C++ `MoveTo` (`DissasmKeyEvents.cpp:37-52`): scroll plus the
    /// selection drag protocol anchored at the line-position offset.
    pub fn move_to(&mut self, offset: i32, lines: i32, select: bool) {
        let text_size = self.layout.text_size;
        let zone = if select {
            self.selection
                .begin_selection(self.cursor.to_line_position().to_offset(text_size))
        } else {
            None
        };
        self.move_scroll_to(offset, lines);
        if select {
            if let Some(zone) = zone {
                self.selection
                    .update_selection(zone, self.cursor.to_line_position().to_offset(text_size));
            }
        }
    }

    /// Ctrl+Q (`COMMAND_JUMP_BACK`): restore the previous position.
    pub fn jump_back(&mut self) -> bool {
        if let Some(location) = self.jumps.jump_back() {
            self.cursor.restore_position(location);
            return true;
        }
        false
    }

    /// Ctrl+E (`COMMAND_JUMP_FORWARD`).
    pub fn jump_forward(&mut self) -> bool {
        if let Some(location) = self.jumps.jump_front() {
            self.cursor.restore_position(location);
            return true;
        }
        false
    }

    /// The landing step of `DissasmZoneProcessSpaceKey`
    /// (`DissasmX86.cpp:1050-1053`): remember the current position,
    /// then place the target `diff_lines` (zone-relative document
    /// line, title lines included) at most 5 rows below the view top.
    pub fn land_jump(&mut self, zone_start_line_index: u32, diff_lines: u32) {
        self.jumps.insert(self.cursor.save_state());
        self.cursor.line_in_view = u32::min(5, diff_lines);
        self.cursor.start_view_line = diff_lines
            .saturating_add(zone_start_line_index)
            .saturating_sub(self.cursor.line_in_view);
        self.cursor.has_moved_view = true;
    }

    /// C++ `ProcessSpaceKey` (`Instance.cpp:1532-1568`) zone
    /// resolution: a title line toggles collapse, F2 first expands a
    /// collapsed zone, non-code zones cannot be followed.
    pub fn process_space_key(
        &mut self,
        zones: &mut [ZoneEntry],
        go_to_entry_point: bool,
    ) -> SpaceKeyOutcome {
        let line_pos = self.cursor.to_line_position();
        let found = zones_from_line_position(zones, line_pos.line, line_pos.line);
        let [location] = found.as_slice() else {
            return SpaceKeyOutcome::NotSingleZone;
        };
        let zone_index = location.zone_index as usize;
        let Some(zone) = zones.get(zone_index) else {
            return SpaceKeyOutcome::NotSingleZone;
        };
        let header = zone.header();
        let is_collapsed = header.is_collapsed;
        let zone_type = header.zone_type;
        if go_to_entry_point && is_collapsed {
            self.selection.clear();
            if let CollapseOutcome::Structure { total_lines } =
                change_zone_collapse_state(zones, zone_index, line_pos.line)
            {
                self.layout.total_lines_size = total_lines;
            }
        }
        if !go_to_entry_point && location.starting_line == 0 {
            self.selection.clear();
            if let CollapseOutcome::Structure { total_lines } =
                change_zone_collapse_state(zones, zone_index, line_pos.line)
            {
                self.layout.total_lines_size = total_lines;
            }
            return SpaceKeyOutcome::ToggledZone;
        }
        if zone_type != DissasmParseZoneType::DissasmCodeParseZone {
            return SpaceKeyOutcome::NotCodeZone;
        }
        let offset_to_reach = if go_to_entry_point {
            match zones.get(zone_index) {
                Some(ZoneEntry::Code(code)) => Some(code.zone_details.entry_point),
                _ => None,
            }
        } else {
            None
        };
        SpaceKeyOutcome::FollowJump {
            zone_index: location.zone_index,
            starting_line: location.starting_line,
            offset_to_reach,
        }
    }

    /// Movement keys (`DissasmKeyEvents.cpp:180-251`); `None` when
    /// the key is not a cursor/scroll key.
    fn handle_movement_key(&mut self, key: Key, select: bool) -> Option<DissasmKeyResponse> {
        let ctrl = key.modifier.contains(KeyModifier::Ctrl);
        let alt = key.modifier.contains(KeyModifier::Alt);
        let plain = !ctrl && !alt;
        let cur = self.cursor;
        let layout = self.layout;
        let current_line = cur.start_view_line.saturating_add(cur.line_in_view);
        let rows = to_i32(layout.visible_rows);
        match key.code {
            KeyCode::Down if plain => {
                if current_line.saturating_add(1) <= layout.total_lines_size {
                    self.move_to(0, 1, select);
                }
            }
            KeyCode::Up if plain => {
                if current_line > 0 {
                    self.move_to(0, -1, select);
                } else {
                    self.move_to(to_i32(cur.offset).saturating_neg(), 0, select);
                }
            }
            KeyCode::Left if plain => {
                if cur.offset > 0 {
                    self.move_to(-1, 0, select);
                }
            }
            KeyCode::Right if plain => {
                if cur.offset < layout.text_size {
                    self.move_to(1, 0, select);
                }
            }
            KeyCode::PageDown if plain => {
                if current_line.saturating_add(layout.visible_rows) <= layout.total_lines_size {
                    self.move_to(0, rows, select);
                } else {
                    let rest = layout.total_lines_size.saturating_sub(current_line);
                    self.move_to(0, to_i32(rest), select);
                }
            }
            KeyCode::PageUp if plain => {
                if current_line >= layout.visible_rows {
                    self.move_to(0, rows.saturating_neg(), select);
                } else {
                    self.move_to(0, to_i32(current_line).saturating_neg(), select);
                }
            }
            KeyCode::Home if plain => {
                self.move_to(to_i32(cur.offset).saturating_neg(), 0, select);
            }
            KeyCode::End if plain => {
                let target = to_i32(layout.text_size.saturating_sub(1));
                self.move_to(target.saturating_sub(to_i32(cur.offset)), 0, select);
            }
            // Viewport scroll (Ctrl+arrows; the mouse wheel maps here).
            KeyCode::Up if ctrl => {
                if current_line > 0 {
                    self.move_scroll_to(0, -1);
                }
            }
            KeyCode::Down if ctrl => {
                if current_line.saturating_add(1) < layout.total_lines_size {
                    self.move_scroll_to(0, 1);
                }
            }
            KeyCode::Left if ctrl => {
                if cur.offset >= 1 {
                    self.move_scroll_to(-1, 0);
                }
            }
            KeyCode::Right if ctrl => {
                if cur.offset < layout.text_size {
                    self.move_scroll_to(1, 0);
                }
            }
            _ => return None,
        }
        Some(DissasmKeyResponse::Handled)
    }

    /// C++ `OnKeyEvent` (`DissasmKeyEvents.cpp:174-273`) plus the
    /// command-bar bindings (`Config.hpp`). Shift on a movement key
    /// selects (C++ strips `Key::Shift` before the switch).
    pub fn handle_key(&mut self, key: Key) -> DissasmKeyResponse {
        let select = key.modifier.contains(KeyModifier::Shift);
        if let Some(response) = self.handle_movement_key(key, select) {
            return response;
        }
        let ctrl = key.modifier.contains(KeyModifier::Ctrl);
        let alt = key.modifier.contains(KeyModifier::Alt);
        let plain = !ctrl && !alt && !select;
        match key.code {
            KeyCode::Space if plain => DissasmKeyResponse::ProcessSpaceKey {
                go_to_entry_point: false,
            },
            KeyCode::Enter if plain => DissasmKeyResponse::OpenSelection,
            KeyCode::X if plain => DissasmKeyResponse::AddCollapsibleZone,
            KeyCode::C if plain => DissasmKeyResponse::AddOrEditComment,
            KeyCode::Delete if plain => DissasmKeyResponse::RemoveComment,
            KeyCode::N if plain => DissasmKeyResponse::RenameLabel,
            KeyCode::S if ctrl && !alt => DissasmKeyResponse::SaveCache,
            KeyCode::Escape if plain => DissasmKeyResponse::SaveCache,
            // Command-bar keys (`Config.hpp`).
            KeyCode::Q if ctrl && !alt => {
                self.jump_back();
                DissasmKeyResponse::Handled
            }
            KeyCode::E if ctrl && !alt => {
                self.jump_forward();
                DissasmKeyResponse::Handled
            }
            KeyCode::F2 if plain => DissasmKeyResponse::ProcessSpaceKey {
                go_to_entry_point: true,
            },
            KeyCode::F7 if plain => {
                self.show_only_dissasm = !self.show_only_dissasm;
                DissasmKeyResponse::ShowOnlyDissasm(self.show_only_dissasm)
            }
            KeyCode::F8 if plain => DissasmKeyResponse::ExportAsmFile,
            KeyCode::K if ctrl && !alt => DissasmKeyResponse::QueryFunctionName,
            KeyCode::L if ctrl && !alt => DissasmKeyResponse::QueryMitreTechnique,
            _ => DissasmKeyResponse::NotHandled,
        }
    }

    /// Escape saves the cache **and** still reaches `ViewControl`
    /// (`DissasmKeyEvents.cpp:266-267`); every other consumed key
    /// stops here.
    #[must_use]
    pub fn escape_forwards(key: Key) -> bool {
        key.code == KeyCode::Escape
    }

    /// C++ `OnMouseWheel` (`DissasmKeyEvents.cpp:165-179`): wheel
    /// up/down → Ctrl+Up/Down, left/right → PageUp/PageDown.
    pub fn on_mouse_wheel(&mut self, direction: MouseWheel) -> DissasmKeyResponse {
        let key = match direction {
            MouseWheel::Up => Key::new(KeyCode::Up, KeyModifier::Ctrl),
            MouseWheel::Down => Key::new(KeyCode::Down, KeyModifier::Ctrl),
            MouseWheel::Left => Key::new(KeyCode::PageUp, KeyModifier::None),
            MouseWheel::Right => Key::new(KeyCode::PageDown, KeyModifier::None),
        };
        self.handle_key(key)
    }
}

/// The jump-target operand parse of `DissasmZoneProcessSpaceKey`
/// (`DissasmX86.cpp:985-1011`).
///
/// Only `j*` and `call` instructions follow; `0x...` hex (lowercase)
/// parses until `,`/space with an invalid digit zeroing the value
/// (C++ warns "Invalid jump value!"); a lone decimal digit is
/// relative to `first_offset` (`cachedCodeOffsets[0].offset`);
/// anything else cannot be followed.
#[must_use]
pub fn parse_jump_target(mnemonic: &str, op_str: &str, first_offset: u64) -> Option<u64> {
    let is_branch = mnemonic.starts_with('j') || mnemonic.as_bytes().get(0..4) == Some(b"call");
    if !is_branch {
        return None;
    }
    let bytes = op_str.as_bytes();
    if bytes.first() == Some(&b'0') && bytes.get(1) == Some(&b'x') {
        let mut value: u64 = 0;
        for &b in bytes.iter().skip(2) {
            if b == b',' || b == b' ' {
                break;
            }
            let digit = match b {
                b'0'..=b'9' => u64::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u64::from(b.saturating_sub(b'a')).saturating_add(10),
                _ => return Some(0),
            };
            value = value.saturating_mul(16).saturating_add(digit);
        }
        Some(value)
    } else if bytes.len() == 1 && bytes.first().is_some_and(u8::is_ascii_digit) {
        let digit = u64::from(bytes.first().copied().unwrap_or(b'0').saturating_sub(b'0'));
        Some(first_offset.saturating_add(digit))
    } else {
        None
    }
}

/// Target normalization before landing (`DissasmX86.cpp:1015-1020`):
/// zero or beyond the zone → `None`; below the zone start → rebased
/// by `starting_zone_point`.
#[must_use]
pub const fn normalize_jump_target(computed: u64, starting_zone_point: u64, size: u64) -> Option<u64> {
    if computed == 0 || computed > starting_zone_point.saturating_add(size) {
        return None;
    }
    if computed < starting_zone_point {
        return Some(computed.saturating_add(starting_zone_point));
    }
    Some(computed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissasm_viewer::zone::{
        DisassemblyZone, DissasmCodeZone, DissasmParseStructureZone,
    };

    fn make_input(total_lines: u32, visible_rows: u32) -> DissasmInput {
        let mut input = DissasmInput::new();
        input.layout.recompute(80, visible_rows.saturating_add(1));
        input.layout.total_lines_size = total_lines;
        input
    }

    fn key(code: KeyCode, modifier: KeyModifier) -> Key {
        Key::new(code, modifier)
    }

    fn cursor_line(input: &DissasmInput) -> u32 {
        input
            .cursor
            .start_view_line
            .saturating_add(input.cursor.line_in_view)
    }

    #[test]
    fn layout_recompute_matches_cpp() {
        let mut layout = LayoutDissasm::initial();
        layout.recompute(80, 25);
        assert_eq!(layout.visible_rows, 24);
        assert_eq!(layout.total_characters_per_line, 79);
        assert_eq!(layout.text_size, 74); // 79 - 5
        layout.recompute(3, 1);
        assert_eq!(layout.text_size, 0); // max(2, 5) - 5
    }

    #[test]
    fn down_rolls_into_start_view_line_and_flags_moved() {
        let mut input = make_input(100, 10);
        for _ in 0..9 {
            input.handle_key(key(KeyCode::Down, KeyModifier::None));
        }
        assert_eq!(input.cursor.line_in_view, 9);
        assert!(!input.cursor.has_moved_view);
        input.handle_key(key(KeyCode::Down, KeyModifier::None));
        // Overflow: view scrolls by one, cursor stays on the last row.
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (1, 9)
        );
        assert!(input.cursor.has_moved_view);
        // Up walks back inside the view without scrolling.
        input.handle_key(key(KeyCode::Up, KeyModifier::None));
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (1, 8)
        );
        assert!(!input.cursor.has_moved_view);
    }

    #[test]
    fn page_keys_and_bounds() {
        let mut input = make_input(30, 10);
        input.handle_key(key(KeyCode::PageDown, KeyModifier::None));
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (1, 9)
        );
        input.handle_key(key(KeyCode::PageDown, KeyModifier::None));
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (11, 9)
        );
        // Near the end: clamps to totalLinesSize.
        input.handle_key(key(KeyCode::PageDown, KeyModifier::None));
        assert_eq!(cursor_line(&input), 30);
        // Down past the end is ignored.
        input.handle_key(key(KeyCode::Down, KeyModifier::None));
        assert_eq!(cursor_line(&input), 30);
        input.handle_key(key(KeyCode::PageUp, KeyModifier::None));
        assert_eq!(cursor_line(&input), 20);
        // Zero total lines: MoveScrollTo is a no-op.
        let mut empty = DissasmInput::new();
        empty.layout.recompute(80, 11);
        empty.handle_key(key(KeyCode::Down, KeyModifier::None));
        assert_eq!(empty.cursor.line_in_view, 0);
    }

    #[test]
    fn horizontal_keys_respect_text_size() {
        let mut input = make_input(10, 10);
        input.handle_key(key(KeyCode::Left, KeyModifier::None)); // at 0: ignored
        assert_eq!(input.cursor.offset, 0);
        input.handle_key(key(KeyCode::End, KeyModifier::None));
        assert_eq!(input.cursor.offset, input.layout.text_size - 1);
        input.handle_key(key(KeyCode::Right, KeyModifier::None));
        assert_eq!(input.cursor.offset, input.layout.text_size); // up to textSize
        input.handle_key(key(KeyCode::Right, KeyModifier::None));
        assert_eq!(input.cursor.offset, input.layout.text_size);
        input.handle_key(key(KeyCode::Home, KeyModifier::None));
        assert_eq!(input.cursor.offset, 0);
    }

    #[test]
    fn ctrl_arrows_scroll_and_wheel_maps() {
        let mut input = make_input(50, 10);
        input.cursor.line_in_view = 3;
        input.cursor.start_view_line = 5;
        input.handle_key(key(KeyCode::Down, KeyModifier::Ctrl));
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (5, 4)
        );
        input.on_mouse_wheel(MouseWheel::Up);
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (5, 3)
        );
        // Ctrl+Up at line 0 is ignored.
        let mut top = make_input(50, 10);
        top.handle_key(key(KeyCode::Up, KeyModifier::Ctrl));
        assert_eq!(top.cursor.line_in_view, 0);
        // Wheel left → PageUp response is Handled.
        assert_eq!(
            input.on_mouse_wheel(MouseWheel::Left),
            DissasmKeyResponse::Handled
        );
    }

    #[test]
    fn shift_movement_builds_selection() {
        let mut input = make_input(50, 10);
        input.handle_key(key(KeyCode::Down, KeyModifier::Shift));
        input.handle_key(key(KeyCode::Down, KeyModifier::Shift));
        let text_size = u64::from(input.layout.text_size);
        assert_eq!(input.selection.get_selection(0), Some((0, 2 * text_size)));
    }

    #[test]
    fn ctrl_q_and_ctrl_e_walk_the_jump_history() {
        let mut input = make_input(500, 10);
        input.cursor.start_view_line = 10;
        input.cursor.line_in_view = 2;
        // Following a jump saves the current state and lands the target.
        input.land_jump(100, 40);
        assert_eq!(input.cursor.line_in_view, 5);
        assert_eq!(input.cursor.start_view_line, 100 + 40 - 5);
        assert!(input.cursor.has_moved_view);
        // Ctrl+Q returns to the saved position.
        assert_eq!(
            input.handle_key(key(KeyCode::Q, KeyModifier::Ctrl)),
            DissasmKeyResponse::Handled
        );
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (10, 2)
        );
        // Ctrl+E lands on the same entry (JumpBack returned it before
        // decrementing — C++ parity).
        input.handle_key(key(KeyCode::E, KeyModifier::Ctrl));
        assert_eq!(
            (input.cursor.start_view_line, input.cursor.line_in_view),
            (10, 2)
        );
        // Nothing further forward.
        assert!(!input.jump_forward());
    }

    #[test]
    fn command_keys_surface_to_the_shell() {
        let mut input = make_input(10, 10);
        assert_eq!(
            input.handle_key(key(KeyCode::Space, KeyModifier::None)),
            DissasmKeyResponse::ProcessSpaceKey {
                go_to_entry_point: false
            }
        );
        assert_eq!(
            input.handle_key(key(KeyCode::F2, KeyModifier::None)),
            DissasmKeyResponse::ProcessSpaceKey {
                go_to_entry_point: true
            }
        );
        assert_eq!(
            input.handle_key(key(KeyCode::Enter, KeyModifier::None)),
            DissasmKeyResponse::OpenSelection
        );
        assert_eq!(
            input.handle_key(key(KeyCode::X, KeyModifier::None)),
            DissasmKeyResponse::AddCollapsibleZone
        );
        assert_eq!(
            input.handle_key(key(KeyCode::C, KeyModifier::None)),
            DissasmKeyResponse::AddOrEditComment
        );
        assert_eq!(
            input.handle_key(key(KeyCode::Delete, KeyModifier::None)),
            DissasmKeyResponse::RemoveComment
        );
        assert_eq!(
            input.handle_key(key(KeyCode::N, KeyModifier::None)),
            DissasmKeyResponse::RenameLabel
        );
        assert_eq!(
            input.handle_key(key(KeyCode::S, KeyModifier::Ctrl)),
            DissasmKeyResponse::SaveCache
        );
        assert_eq!(
            input.handle_key(key(KeyCode::Escape, KeyModifier::None)),
            DissasmKeyResponse::SaveCache
        );
        assert!(DissasmInput::escape_forwards(key(KeyCode::Escape, KeyModifier::None)));
        assert!(!DissasmInput::escape_forwards(key(KeyCode::S, KeyModifier::Ctrl)));
        assert_eq!(
            input.handle_key(key(KeyCode::F7, KeyModifier::None)),
            DissasmKeyResponse::ShowOnlyDissasm(true)
        );
        assert_eq!(
            input.handle_key(key(KeyCode::F7, KeyModifier::None)),
            DissasmKeyResponse::ShowOnlyDissasm(false)
        );
        assert_eq!(
            input.handle_key(key(KeyCode::F8, KeyModifier::None)),
            DissasmKeyResponse::ExportAsmFile
        );
        assert_eq!(
            input.handle_key(key(KeyCode::K, KeyModifier::Ctrl)),
            DissasmKeyResponse::QueryFunctionName
        );
        assert_eq!(
            input.handle_key(key(KeyCode::L, KeyModifier::Ctrl)),
            DissasmKeyResponse::QueryMitreTechnique
        );
        assert_eq!(
            input.handle_key(key(KeyCode::F5, KeyModifier::None)),
            DissasmKeyResponse::NotHandled
        );
    }

    fn structure(start: u32, end: u32, extended: u32, collapsed: bool) -> ZoneEntry {
        let mut z = DissasmParseStructureZone::default();
        z.zone.start_line_index = start;
        z.zone.ending_line_index = end;
        z.zone.extended_size = extended;
        z.zone.is_collapsed = collapsed;
        ZoneEntry::Structure(z)
    }

    fn code(start: u32, end: u32, entry: u64) -> ZoneEntry {
        let mut z = DissasmCodeZone::default();
        z.zone.start_line_index = start;
        z.zone.ending_line_index = end;
        z.zone_details = DisassemblyZone {
            starting_zone_point: 0x1000,
            size: 0x100,
            entry_point: entry,
            ..DisassemblyZone::default()
        };
        ZoneEntry::Code(Box::new(z))
    }

    #[test]
    fn zones_from_line_position_reports_relative_spans() {
        let zones = vec![
            structure(0, 5, 0, false),
            code(5, 25, 0x1010),
            structure(25, 30, 0, false),
        ];
        // Single line inside the code zone.
        assert_eq!(
            zones_from_line_position(&zones, 12, 12),
            vec![ZoneLocation {
                zone_index: 1,
                starting_line: 7,
                ending_line: 7
            }]
        );
        // A range crossing two zones. C++ quirk: the line on which
        // the scan advances to the next zone (line 5 here) is consumed
        // by the `zoneIndex++` branch and never attributed, so the
        // second span starts at zone-relative line 1, not 0.
        let found = zones_from_line_position(&zones, 3, 7);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0],
            ZoneLocation {
                zone_index: 0,
                starting_line: 3,
                ending_line: 4
            }
        );
        assert_eq!(
            found[1],
            ZoneLocation {
                zone_index: 1,
                starting_line: 1,
                ending_line: 2
            }
        );
        // Beyond every zone → empty; reversed range clamps.
        assert!(zones_from_line_position(&zones, 40, 45).is_empty());
        assert_eq!(zones_from_line_position(&zones, 12, 3).len(), 1);
    }

    #[test]
    fn space_follow_jump_resolves_zone_and_toggles_title() {
        let mut zones = vec![structure(0, 5, 0, false), code(5, 25, 0x1010)];
        let mut input = make_input(24, 10);
        // Cursor on an inner code line → follow jump.
        input.cursor.start_view_line = 10;
        input.cursor.line_in_view = 2;
        assert_eq!(
            input.process_space_key(&mut zones, false),
            SpaceKeyOutcome::FollowJump {
                zone_index: 1,
                starting_line: 7,
                offset_to_reach: None
            }
        );
        // F2 carries the entry point.
        assert_eq!(
            input.process_space_key(&mut zones, true),
            SpaceKeyOutcome::FollowJump {
                zone_index: 1,
                starting_line: 7,
                offset_to_reach: Some(0x1010)
            }
        );
        // Space on a structure zone's title line toggles it.
        input.cursor.start_view_line = 0;
        input.cursor.line_in_view = 0;
        assert_eq!(
            input.process_space_key(&mut zones, false),
            SpaceKeyOutcome::ToggledZone
        );
        assert!(zones[0].header().is_collapsed);
        // Space on an inner structure line: not a code zone.
        let mut zones2 = vec![structure(0, 5, 0, false)];
        input.cursor.line_in_view = 2;
        assert_eq!(
            input.process_space_key(&mut zones2, false),
            SpaceKeyOutcome::NotCodeZone
        );
        // Outside every zone.
        input.cursor.start_view_line = 40;
        assert_eq!(
            input.process_space_key(&mut zones, false),
            SpaceKeyOutcome::NotSingleZone
        );
    }

    #[test]
    fn jump_target_parsing_matches_cpp() {
        assert_eq!(parse_jump_target("jmp", "0x401a2b", 0), Some(0x0040_1a2b));
        assert_eq!(parse_jump_target("je", "0x10, eax", 0), Some(0x10));
        assert_eq!(parse_jump_target("call", "0x1F", 0), Some(0)); // uppercase → 0
        assert_eq!(parse_jump_target("jmp", "5", 0x1000), Some(0x1005)); // lone digit
        assert_eq!(parse_jump_target("jmp", "eax", 0x1000), None);
        assert_eq!(parse_jump_target("mov", "0x401000", 0), None);
        // Normalization.
        assert_eq!(normalize_jump_target(0, 0x1000, 0x100), None);
        assert_eq!(normalize_jump_target(0x2000, 0x1000, 0x100), None);
        assert_eq!(normalize_jump_target(0x10, 0x1000, 0x100), Some(0x1010));
        assert_eq!(normalize_jump_target(0x1050, 0x1000, 0x100), Some(0x1050));
    }
}
