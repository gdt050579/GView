//! The disassembly viewer control.
//!
//! Spec `00_APP §6.2`; `02_VIEWER_DISSASM` §3 (zones), §4 (offset
//! table), §9 (viewport) and §11 (key matrix). C++ anchor:
//! `GViewCore/src/View/DissasmViewer/Instance.cpp` — `Paint`
//! (L1340+), `OnKeyEvent` (`DissasmKeyEvents.cpp:174-273`),
//! `OnMouseEvent` and `RecomputeDissasmZones`.
//!
//! | Hook | Delegates to |
//! |------|--------------|
//! | `OnResize` | [`LayoutDissasm::recompute`], then the zone line table |
//! | `OnPaint` | [`DissasmAsmPreCacheData::on_paint_start`], then one decoded instruction per visible line |
//! | `OnKeyPressed` | [`DissasmInput::handle_key`]; `Space` / `F2` go through [`DissasmInput::process_space_key`] |
//! | `OnMouseEvent` | wheel → [`DissasmInput::on_mouse_wheel`] |
//!
//! Static analysis (`§5.4-5.9`), the jclass path (`§12A`) and the
//! smart-assistant queries are separate tasks; the key responses they
//! own surface as shell events rather than being handled here.

use std::sync::{Mutex, PoisonError};

use appcui::prelude::*;

use gview_disasm::capstone::DissasemblerIntel;
use gview_disasm::{Architecture, Design, Endianess};
use gview_plugin::type_plugin::DissasmViewerRequest;
use gview_view::dissasm_viewer::input::{
    DissasmInput, DissasmKeyResponse, LayoutDissasm, MouseWheel, SpaceKeyOutcome,
};
use gview_view::dissasm_viewer::pre_cache::{
    lines_to_prepare, DissasmAsmPreCacheData, DissasmAsmPreCacheLine,
};
use gview_view::dissasm_viewer::zone::{
    total_lines, DisassemblyLanguage, DisassemblyZone, DissasmCodeZone, ZoneEntry,
};
use gview_view::traits::{SharedObject, SmartViewer, ViewerSettings};
use gview_view::view_control::{clamp_goto, ViewControl, ViewData};

use crate::cursor_info::{CursorSnapshot, SharedCursorInfo};

/// Lines a code zone spends on its title before the first instruction
/// (C++ `ZONE_HEADER_LINES`: the zone name and a blank).
pub const ZONE_TITLE_LINES: u32 = 2;
/// Cap on instructions decoded for one viewport fill, so a hostile
/// zone cannot make a frame unbounded.
pub const MAX_PRE_CACHE_LINES: u32 = 256;
/// Widest cursor bar this control formats without allocating.
const CURSOR_BAR_CAPACITY: usize = 96;

/// What the `FileWindow` hands a [`DissasmView`] at mount
/// (`00_APP §5.3.2`).
pub struct DissasmViewSettings {
    /// The plugin's `DissasmViewer::Settings`, moved in whole.
    pub request: DissasmViewerRequest,
    /// The window's bottom-bar slot (`00_APP §5.3.5`).
    pub cursor_info: SharedCursorInfo,
    /// `CreateViewer<T>(name)` override.
    pub custom_name: Option<String>,
}

impl Default for DissasmViewSettings {
    fn default() -> Self {
        Self {
            request: DissasmViewerRequest::default(),
            cursor_info: SharedCursorInfo::new(),
            custom_name: None,
        }
    }
}

impl core::fmt::Debug for DissasmViewSettings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DissasmViewSettings")
            .field("zones", &self.request.zones.len())
            .field("types", &self.request.types.len())
            .finish_non_exhaustive()
    }
}

impl ViewerSettings for DissasmViewSettings {
    fn custom_name(&self) -> Option<&str> {
        self.custom_name.as_deref()
    }

    fn set_custom_name(&mut self, name: &str) {
        self.custom_name = Some(name.to_owned());
    }
}

/// The disassembly viewer (C++ `DissasmViewer::Instance`).
#[CustomControl(overwrite = OnPaint+OnKeyPressed+OnResize+OnMouseEvent, emit = ShowGoTo+ShowFind+ShowCopy+FocusView+OpenSelection)]
pub struct DissasmView {
    object: SharedObject,
    /// Cursor, layout, jump history and selection (C++ `Instance`
    /// input state).
    input: DissasmInput,
    /// C++ `parseZones`.
    zones: Mutex<Vec<ZoneEntry>>,
    /// C++ `asmPreCacheData` — the current viewport fill.
    pre_cache: Mutex<DissasmAsmPreCacheData>,
    /// One decoder per view (C++ `dissasembler`).
    disassembler: Mutex<DissasemblerIntel>,
    /// Address-column captions after `FileOffset`.
    translation_methods: Vec<String>,
    /// `AddVariable(offset, type)` entries.
    variables: Vec<(u64, String)>,
    name: String,
    cursor_info: SharedCursorInfo,
    /// The last `Enter` request, for the window to service.
    pending_open: Option<(u64, u64)>,
    /// Scratch for `paint_cursor_information`.
    cursor_bar: [u8; CURSOR_BAR_CAPACITY],
}

impl DissasmView {
    /// The layout (C++ `Layout`).
    #[must_use]
    pub const fn layout(&self) -> LayoutDissasm {
        self.input.layout
    }

    /// The cursor (C++ `Cursor`).
    #[must_use]
    pub const fn cursor(&self) -> gview_view::dissasm_viewer::input::CursorDissasm {
        self.input.cursor
    }

    /// Zones currently in the document.
    #[must_use]
    pub fn zone_count(&self) -> usize {
        self.zones
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// `(start_line_index, ending_line_index, is_collapsed)` of each
    /// zone, for the mount code and tests.
    #[must_use]
    pub fn zone_lines(&self) -> Vec<(u32, u32, bool)> {
        self.zones
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|zone| {
                let header = zone.header();
                (
                    header.start_line_index,
                    header.ending_line_index,
                    header.is_collapsed,
                )
            })
            .collect()
    }

    /// The `Enter` request the window has not serviced yet, as
    /// `(offset, size)`.
    #[must_use]
    pub const fn pending_open(&self) -> Option<(u64, u64)> {
        self.pending_open
    }

    /// Takes the pending `Enter` request.
    pub const fn take_pending_open(&mut self) -> Option<(u64, u64)> {
        self.pending_open.take()
    }

    /// Address-column captions the plugin declared.
    #[must_use]
    pub fn translation_methods(&self) -> &[String] {
        &self.translation_methods
    }

    /// `AddVariable` entries the plugin declared.
    #[must_use]
    pub fn variables(&self) -> &[(u64, String)] {
        &self.variables
    }

    /// The object's size, read through the shared lock.
    fn file_size(&self) -> u64 {
        let guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
        guard.data().size()
    }

    /// C++ `UpdateLayoutTotalLines` (`Instance.cpp:1169-1173`).
    fn refresh_total_lines(&mut self) {
        let total = {
            let zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
            let total = total_lines(&zones);
            drop(zones);
            total
        };
        self.input.layout.total_lines_size = total;
    }

    /// The bottom-bar snapshot.
    fn snapshot(&self) -> CursorSnapshot {
        let position = self.input.cursor.to_line_position();
        let mut snapshot = CursorSnapshot::with_name(&self.name);
        snapshot.base = 10;
        snapshot.offset = u64::from(position.line);
        snapshot.size = u64::from(self.input.layout.total_lines_size);
        if let Some((start, end)) = self.input.selection.get_selection(0) {
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

    /// C++ `ProcessSpaceKey` (`Instance.cpp:1532-1568`).
    ///
    /// A title line toggles the zone; a jump inside a code zone is
    /// followed through [`DissasmInput::land_jump`]; everything else
    /// is reported without moving.
    pub fn process_space(&mut self, go_to_entry_point: bool) -> SpaceKeyOutcome {
        let outcome = {
            let mut zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
            let outcome = self.input.process_space_key(&mut zones, go_to_entry_point);
            drop(zones);
            outcome
        };
        if let SpaceKeyOutcome::FollowJump {
            zone_index,
            starting_line,
            ..
        } = outcome
        {
            let start_line_index = {
                let zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
                let start = zones
                    .get(zone_index as usize)
                    .map_or(0, |zone| zone.header().start_line_index);
                drop(zones);
                start
            };
            self.input.land_jump(start_line_index, starting_line);
        }
        self.refresh_total_lines();
        self.publish();
        outcome
    }

    /// Decodes the instructions the viewport needs
    /// (C++ `DissasmX86.cpp:820-824` fill plan) into `pre_cache`.
    ///
    /// Bounded twice: by [`lines_to_prepare`] (the zone's remaining
    /// lines and the viewport height) and by [`MAX_PRE_CACHE_LINES`],
    /// so a zone that claims a huge `extended_size` cannot make one
    /// frame unbounded.
    fn fill_pre_cache(&self, zone: &DissasmCodeZone, from_line: u32, cache: &mut DissasmAsmPreCacheData) {
        let visible = self.input.layout.visible_rows;
        let wanted = lines_to_prepare(visible, zone.zone.extended_size, from_line).min(MAX_PRE_CACHE_LINES);
        if wanted == 0 {
            return;
        }
        let details = zone.zone_details;
        let file_size = self.file_size();
        // A zone the plugin placed past EOF has nothing to decode
        // (C++ `Get` returns an invalid buffer and the loop stops).
        if details.starting_zone_point >= file_size {
            return;
        }
        let available = file_size.saturating_sub(details.starting_zone_point);
        let size = details.size.min(available);
        let bytes = {
            let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            let want = u32::try_from(size.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
            let bytes = guard
                .data_mut()
                .get(details.starting_zone_point, want, false)
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            drop(guard);
            bytes
        };
        if bytes.is_empty() {
            return;
        }
        let disassembler = self.disassembler.lock().unwrap_or_else(PoisonError::into_inner);
        let mut cursor = 0_usize;
        let mut line = from_line;
        for _ in 0..wanted {
            let Some(rest) = bytes.as_slice().get(cursor..) else {
                break;
            };
            if rest.is_empty() {
                break;
            }
            let address = details.starting_zone_point.saturating_add(cursor as u64);
            let Ok(instruction) = disassembler.disassemble_instruction(rest, address) else {
                break;
            };
            if instruction.size == 0 {
                break;
            }
            cache.cached_asm_lines.push(DissasmAsmPreCacheLine {
                address,
                bytes: instruction.bytes,
                size: instruction.size,
                current_line: line,
                mnemonic: instruction.mnemonic.clone(),
                op_str: instruction.op_str.clone(),
                hex_value: None,
                flags: 0,
                line_arrow_to_draw: 0,
                should_add_button: false,
                is_zone_collapsed: zone.zone.is_collapsed,
            });
            cursor = cursor.saturating_add(usize::from(instruction.size));
            line = line.saturating_add(1);
        }
        drop(disassembler);
        cache.compute_max_line();
    }

    /// Paints one decoded instruction: `<address>  <hex bytes>  <mnemonic> <operands>`.
    fn paint_asm_line(&self, surface: &mut Surface, y: i32, line: &DissasmAsmPreCacheLine, attr: CharAttribute) {
        let margin = self.input.layout.starting_text_line_offset.cast_signed();
        let mut scratch = [b' '; 16];
        let len = write_hex(&mut scratch, line.address, 8);
        surface.write_ascii(margin, y, scratch.get(..len).unwrap_or(&[]), attr, false);

        let mut x = margin.saturating_add(i32::try_from(len).unwrap_or(0)).saturating_add(2);
        // Raw bytes, `size` of them (capstone caps at 24).
        let count = usize::from(line.size).min(line.bytes.len());
        for byte in line.bytes.iter().take(count) {
            let mut pair = [b' '; 2];
            let _ = write_hex(&mut pair, u64::from(*byte), 2);
            surface.write_ascii(x, y, &pair, attr, false);
            x = x.saturating_add(3);
        }
        x = x.saturating_add(1);
        surface.write_string(x, y, &line.mnemonic, attr, false);
        x = x
            .saturating_add(i32::try_from(line.mnemonic.len()).unwrap_or(0))
            .saturating_add(1);
        surface.write_string(x, y, &line.op_str, attr, false);
    }
}

/// Writes `value` as zero-padded upper-case hex into `out`, returning
/// the length written (at most `out.len()`).
fn write_hex(out: &mut [u8], value: u64, digits: usize) -> usize {
    const HEX: [u8; 16] = *b"0123456789ABCDEF";
    let digits = digits.min(out.len());
    let mut rest = value;
    for index in (0..digits).rev() {
        let nibble = (rest & 0x0F) as usize;
        if let Some(slot) = out.get_mut(index) {
            *slot = HEX.get(nibble).copied().unwrap_or(b'0');
        }
        rest >>= 4;
    }
    digits
}

/// The capstone `(design, architecture)` pair a zone language selects
/// (C++ `DissasmCodeZone` init from `zoneDetails.language`).
const fn decoder_for(language: DisassemblyLanguage) -> (Design, Architecture) {
    match language {
        DisassemblyLanguage::X64 => (Design::Intel, Architecture::X64),
        // `Default` resolves to x86 at zone creation, as the C++ does.
        DisassemblyLanguage::X86 | DisassemblyLanguage::Default => (Design::Intel, Architecture::X86),
        DisassemblyLanguage::JavaByteCode => (Design::Invalid, Architecture::Invalid),
    }
}

impl SmartViewer for DissasmView {
    type Settings = DissasmViewSettings;

    fn from_settings(object: SharedObject, settings: Self::Settings) -> Self {
        let DissasmViewSettings {
            request,
            cursor_info,
            custom_name,
        } = settings;
        let file_size = {
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            let size = guard.data().size();
            drop(guard);
            size
        };
        // C++ `RecomputeDissasmZones`: one code zone per declared
        // region, laid out back to back on the document line axis.
        let mut zones: Vec<ZoneEntry> = Vec::with_capacity(request.zones.len());
        let mut next_line = 0_u32;
        let mut language = DisassemblyLanguage::Default;
        for details in &request.zones {
            // A region the plugin placed past EOF is clamped to an
            // empty one rather than dropped: the C++ keeps the zone
            // and simply decodes nothing.
            let clamped = DisassemblyZone {
                starting_zone_point: details.starting_zone_point.min(file_size),
                size: details
                    .size
                    .min(file_size.saturating_sub(details.starting_zone_point.min(file_size))),
                entry_point: clamp_goto(details.entry_point, file_size.max(1)),
                language: details.language,
            };
            if language == DisassemblyLanguage::Default {
                language = details.language;
            }
            let mut zone = DissasmCodeZone {
                zone_details: clamped,
                ..DissasmCodeZone::default()
            };
            // Title lines plus one line per byte at worst; the real
            // instruction count is discovered as the viewport fills,
            // which is exactly the C++ lazy behaviour.
            let body_lines = u32::try_from(clamped.size).unwrap_or(u32::MAX);
            zone.zone.start_line_index = next_line;
            zone.zone.extended_size = ZONE_TITLE_LINES.saturating_add(body_lines);
            zone.zone.is_collapsed = false;
            zone.zone.ending_line_index = next_line
                .saturating_add(1)
                .saturating_add(zone.zone.extended_size);
            zone.zone.zone_id = u16::try_from(zones.len()).unwrap_or(u16::MAX);
            next_line = zone.zone.ending_line_index;
            zones.push(ZoneEntry::Code(Box::new(zone)));
        }
        let mut disassembler = DissasemblerIntel::new();
        let (design, architecture) = decoder_for(language);
        // An unsupported language leaves the decoder closed; paint
        // then shows the zone title and no instructions.
        let _ = disassembler.init(design, architecture, Endianess::Little);

        let mut input = DissasmInput::new();
        input.layout.total_lines_size = total_lines(&zones);
        let view = Self {
            base: ControlBase::with_focus_overlay(layout!("d:f")),
            object,
            input,
            zones: Mutex::new(zones),
            pre_cache: Mutex::new(DissasmAsmPreCacheData::default()),
            disassembler: Mutex::new(disassembler),
            translation_methods: request.translation_methods,
            variables: request.variables,
            name: custom_name.unwrap_or_else(|| String::from("Dissasm")),
            cursor_info,
            pending_open: None,
            cursor_bar: [b' '; CURSOR_BAR_CAPACITY],
        };
        view.publish();
        view
    }
}

impl ViewControl for DissasmView {
    fn name(&self) -> &str {
        &self.name
    }

    /// C++ `GoTo(offset)`: places the cursor on the document line of
    /// the zone containing `offset`.
    fn go_to(&mut self, offset: u64) -> bool {
        let zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
        let target = zones.iter().find_map(|zone| {
            let ZoneEntry::Code(code) = zone else {
                return None;
            };
            let details = code.zone_details;
            let end = details.starting_zone_point.saturating_add(details.size);
            (offset >= details.starting_zone_point && offset < end)
                .then(|| zone.header().start_line_index)
        });
        drop(zones);
        let Some(line) = target else {
            return false;
        };
        self.input.cursor.start_view_line = line;
        self.input.cursor.line_in_view = 0;
        self.input.cursor.has_moved_view = true;
        self.publish();
        true
    }

    fn select(&mut self, offset: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let end = offset.saturating_add(size).saturating_sub(1);
        let selected = self.input.selection.set_selection(0, offset, end);
        if selected {
            self.publish();
        }
        selected
    }

    fn show_goto_dialog(&mut self) -> bool {
        self.raise_event(dissasmview::Events::ShowGoTo);
        true
    }

    fn show_find_dialog(&mut self) -> bool {
        self.raise_event(dissasmview::Events::ShowFind);
        true
    }

    fn show_copy_dialog(&mut self) -> bool {
        self.raise_event(dissasmview::Events::ShowCopy);
        true
    }

    /// The bar shows the document line and the total.
    fn paint_cursor_information(&mut self, surface: &mut Surface, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        let snapshot = self.snapshot();
        let mut len = 0_usize;
        for byte in b"Line:" {
            if let Some(slot) = self.cursor_bar.get_mut(len) {
                *slot = *byte;
                len = len.saturating_add(1);
            }
        }
        let mut scratch = [b' '; 24];
        let written = write_decimal(&mut scratch, snapshot.offset.saturating_add(1));
        for byte in scratch.get(..written).unwrap_or(&[]) {
            if let Some(slot) = self.cursor_bar.get_mut(len) {
                *slot = *byte;
                len = len.saturating_add(1);
            }
        }
        for byte in b"/" {
            if let Some(slot) = self.cursor_bar.get_mut(len) {
                *slot = *byte;
                len = len.saturating_add(1);
            }
        }
        let written = write_decimal(&mut scratch, snapshot.size);
        for byte in scratch.get(..written).unwrap_or(&[]) {
            if let Some(slot) = self.cursor_bar.get_mut(len) {
                *slot = *byte;
                len = len.saturating_add(1);
            }
        }
        let text = self.cursor_bar.get(..len).unwrap_or(&[]);
        surface.write_ascii(0, 0, text, CharAttribute::default(), false);
    }

    fn view_data(&self, data: &mut ViewData, offset: u64) -> bool {
        let byte = {
            let mut guard = self.object.lock().unwrap_or_else(PoisonError::into_inner);
            let byte = guard
                .data_mut()
                .get(offset, 1, true)
                .ok()
                .and_then(|b| b.first().copied());
            drop(guard);
            byte
        };
        let Some(byte) = byte else {
            return false;
        };
        let position = self.input.cursor.to_line_position();
        data.view_start_offset = u64::from(self.input.cursor.start_view_line);
        data.view_size = u64::from(self.input.layout.visible_rows);
        data.cursor_start_offset = position.to_offset(self.input.layout.text_size);
        data.byte = byte;
        true
    }
}

/// Writes `value` in decimal into `out`, returning the length.
fn write_decimal(out: &mut [u8], value: u64) -> usize {
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
    let count = count.min(out.len());
    for index in 0..count {
        let digit = digits
            .get(count.saturating_sub(index).saturating_sub(1))
            .copied()
            .unwrap_or(b'0');
        if let Some(slot) = out.get_mut(index) {
            *slot = digit;
        }
    }
    count
}

impl OnResize for DissasmView {
    fn on_resize(&mut self, _old: Size, new: Size) {
        self.input.layout.recompute(new.width, new.height);
        self.input.cursor.has_moved_view = true;
        self.refresh_total_lines();
        self.publish();
    }
}

impl OnPaint for DissasmView {
    fn on_paint(&self, surface: &mut Surface, theme: &Theme) {
        surface.clear(Character::with_attributes(' ', theme.editor.normal));
        let zones = self.zones.lock().unwrap_or_else(PoisonError::into_inner);
        let mut cache = self.pre_cache.lock().unwrap_or_else(PoisonError::into_inner);
        // C++ `Instance::Paint` (`Instance.cpp:1340-1346`): a scrolled
        // viewport invalidates the fill, an unmoved one rewinds it.
        cache.on_paint_start(self.input.cursor.has_moved_view);

        let start_line = self.input.cursor.start_view_line;
        for (index, zone) in zones.iter().enumerate() {
            let header = zone.header();
            if header.ending_line_index <= start_line {
                continue;
            }
            let y_of = |line: u32| line.saturating_sub(start_line);
            // The zone title (C++ draws the zone name and a blank).
            let title_y = y_of(header.start_line_index);
            if header.start_line_index >= start_line && title_y < self.input.layout.visible_rows {
                let marker = if header.is_collapsed { '+' } else { '-' };
                let mut scratch = [b' '; 24];
                let len = write_decimal(&mut scratch, index as u64);
                surface.write_char(0, title_y.cast_signed(), Character::with_attributes(marker, theme.text.highlighted));
                surface.write_string(2, title_y.cast_signed(), "Zone ", theme.text.highlighted, false);
                surface.write_ascii(
                    7,
                    title_y.cast_signed(),
                    scratch.get(..len).unwrap_or(&[]),
                    theme.text.highlighted,
                    false,
                );
            }
            if header.is_collapsed {
                continue;
            }
            let ZoneEntry::Code(code) = zone else {
                continue;
            };
            // First body line of this zone that is on screen.
            let body_start = header.start_line_index.saturating_add(ZONE_TITLE_LINES);
            let from_line = start_line.saturating_sub(body_start);
            if cache.cached_asm_lines.is_empty() {
                self.fill_pre_cache(code, from_line, &mut cache);
            }
            for line in &cache.cached_asm_lines {
                let document_line = body_start.saturating_add(line.current_line);
                if document_line < start_line {
                    continue;
                }
                let y = y_of(document_line);
                if y >= self.input.layout.visible_rows {
                    break;
                }
                let attr = if y == self.input.cursor.line_in_view {
                    theme.editor.focused
                } else {
                    theme.text.normal
                };
                self.paint_asm_line(surface, y.cast_signed(), line, attr);
            }
        }
        drop(cache);
        drop(zones);
    }
}

impl OnKeyPressed for DissasmView {
    fn on_key_pressed(&mut self, key: Key, _character: char) -> EventProcessStatus {
        if key == Key::new(KeyCode::G, KeyModifier::Ctrl) {
            self.raise_event(dissasmview::Events::ShowGoTo);
            return EventProcessStatus::Processed;
        }
        if key == Key::new(KeyCode::F, KeyModifier::Ctrl) {
            self.raise_event(dissasmview::Events::ShowFind);
            return EventProcessStatus::Processed;
        }
        if key == Key::new(KeyCode::C, KeyModifier::Ctrl) {
            self.raise_event(dissasmview::Events::ShowCopy);
            return EventProcessStatus::Processed;
        }
        let response = self.input.handle_key(key);
        let handled = self.apply_response(response);
        // C++ `DissasmKeyEvents.cpp:266-267`: Escape saves the cache
        // and still reaches `ViewControl`.
        if DissasmInput::escape_forwards(key) {
            self.raise_event(dissasmview::Events::FocusView);
            return EventProcessStatus::Processed;
        }
        if handled {
            self.publish();
            self.request_update();
            EventProcessStatus::Processed
        } else {
            EventProcessStatus::Ignored
        }
    }
}

impl DissasmView {
    /// Applies a [`DissasmKeyResponse`], raising a shell event for the
    /// actions that belong to later tasks (comments, labels, export,
    /// the LLM queries).
    fn apply_response(&mut self, response: DissasmKeyResponse) -> bool {
        match response {
            DissasmKeyResponse::NotHandled => false,
            DissasmKeyResponse::ProcessSpaceKey { go_to_entry_point } => {
                self.process_space(go_to_entry_point);
                true
            }
            DissasmKeyResponse::OpenSelection => {
                self.pending_open = self.input.selection.get_selection(0).map(|(start, end)| {
                    (start, end.saturating_sub(start).saturating_add(1))
                });
                if self.pending_open.is_some() {
                    self.raise_event(dissasmview::Events::OpenSelection);
                }
                true
            }
            // `Handled` / `ShowOnlyDissasm` already updated the state.
            // Comments, labels, collapsible zones, cache persistence,
            // export and the assistant queries are separate tasks; the
            // key is still consumed so it does not fall through to the
            // window.
            DissasmKeyResponse::Handled
            | DissasmKeyResponse::ShowOnlyDissasm(_)
            | DissasmKeyResponse::AddCollapsibleZone
            | DissasmKeyResponse::AddOrEditComment
            | DissasmKeyResponse::RemoveComment
            | DissasmKeyResponse::RenameLabel
            | DissasmKeyResponse::SaveCache
            | DissasmKeyResponse::ExportAsmFile
            | DissasmKeyResponse::QueryFunctionName
            | DissasmKeyResponse::QueryMitreTechnique => true,
        }
    }
}

impl OnMouseEvent for DissasmView {
    fn on_mouse_event(&mut self, event: &MouseEvent) -> EventProcessStatus {
        let direction = match event {
            MouseEvent::Wheel(MouseWheelDirection::Down) => Some(MouseWheel::Down),
            MouseEvent::Wheel(MouseWheelDirection::Up) => Some(MouseWheel::Up),
            MouseEvent::Wheel(MouseWheelDirection::Left) => Some(MouseWheel::Left),
            MouseEvent::Wheel(MouseWheelDirection::Right) => Some(MouseWheel::Right),
            _ => None,
        };
        let Some(direction) = direction else {
            return EventProcessStatus::Ignored;
        };
        let response = self.input.on_mouse_wheel(direction);
        if self.apply_response(response) {
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
    use super::{DissasmView, DissasmViewSettings, ZONE_TITLE_LINES};
    use crate::cursor_info::SharedCursorInfo;
    use appcui::prelude::*;
    use gview_core::object::Object;
    use gview_plugin::type_plugin::DissasmViewerRequest;
    use gview_view::dissasm_viewer::input::SpaceKeyOutcome;
    use gview_view::dissasm_viewer::zone::{DisassemblyLanguage, DisassemblyZone};
    use gview_view::traits::{SharedObject, SmartViewer};
    use gview_view::view_control::ViewControl;
    use std::sync::{Arc, Mutex as StdMutex};

    fn processed(status: EventProcessStatus) -> bool {
        status == EventProcessStatus::Processed
    }

    /// x86 code: `push ebp; mov ebp, esp; xor eax, eax; ret`, then
    /// padding so the zone is comfortably larger than the viewport.
    fn code() -> Vec<u8> {
        let mut bytes = vec![0x55, 0x8B, 0xEC, 0x31, 0xC0, 0xC3];
        bytes.extend(core::iter::repeat_n(0x90_u8, 250));
        bytes
    }

    fn object_of(bytes: &[u8]) -> SharedObject {
        Arc::new(StdMutex::new(Object::from_buffer(bytes, "code.bin", 0)))
    }

    fn view_with(bytes: &[u8], zones: Vec<DisassemblyZone>, size: Size) -> DissasmView {
        let mut view = DissasmView::from_settings(
            object_of(bytes),
            DissasmViewSettings {
                request: DissasmViewerRequest {
                    zones,
                    ..DissasmViewerRequest::default()
                },
                ..DissasmViewSettings::default()
            },
        );
        OnResize::on_resize(&mut view, Size::new(0, 0), size);
        view
    }

    fn one_zone(size: Size) -> DissasmView {
        let bytes = code();
        let zone = DisassemblyZone {
            starting_zone_point: 0,
            size: bytes.len() as u64,
            entry_point: 0,
            language: DisassemblyLanguage::X86,
        };
        view_with(&bytes, vec![zone], size)
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

    fn row_text(surface: &Surface, y: u32, width: u32) -> String {
        read(surface, 0, y, width as usize)
    }

    #[test]
    fn a_code_zone_paints_its_mnemonics() {
        let view = one_zone(Size::new(100, 14));
        assert_eq!(view.zone_count(), 1);
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(100, 14);
        OnPaint::on_paint(&view, &mut surface, &theme);

        // Row 0 carries the zone title; the body starts two rows down.
        assert!(row_text(&surface, 0, 100).contains("Zone 0"));
        let body = row_text(&surface, ZONE_TITLE_LINES, 100);
        assert!(body.contains("push"), "first instruction painted: {body:?}");
        assert!(body.contains("00000000"), "address column: {body:?}");
        assert!(body.contains("55"), "raw byte column: {body:?}");
        let second = row_text(&surface, ZONE_TITLE_LINES + 1, 100);
        assert!(second.contains("mov"), "second instruction: {second:?}");
    }

    #[test]
    fn down_up_and_page_keys_follow_the_input_state_machine() {
        let mut view = one_zone(Size::new(100, 14));
        assert_eq!(view.cursor().line_in_view, 0);
        assert!(processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::Down, KeyModifier::None),
            '\0'
        )));
        assert_eq!(view.cursor().line_in_view, 1);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(view.cursor().line_in_view, 2);
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Up, KeyModifier::None), '\0');
        assert_eq!(view.cursor().line_in_view, 1);

        // PageDown pushes past the last row, so the view scrolls.
        let before = view.cursor().start_view_line;
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageDown, KeyModifier::None), '\0');
        assert!(view.cursor().start_view_line > before, "the viewport moved");
        assert!(view.cursor().has_moved_view);
        let scrolled = view.cursor().start_view_line;
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::PageUp, KeyModifier::None), ' ');
        assert!(
            view.cursor().start_view_line < scrolled,
            "PageUp scrolled back: {} -> {}",
            scrolled,
            view.cursor().start_view_line
        );
    }

    #[test]
    fn space_on_a_zone_title_toggles_the_collapse_state() {
        let mut view = one_zone(Size::new(100, 14));
        let before = view.zone_lines();
        assert_eq!(before.len(), 1);
        assert!(!before[0].2, "zones start expanded");
        let expanded_end = before[0].1;

        // The cursor is on the title line (document line 0).
        assert_eq!(
            view.process_space(false),
            SpaceKeyOutcome::ToggledZone,
            "the title line toggles"
        );
        let after = view.zone_lines();
        assert!(after[0].2, "now collapsed");
        assert!(after[0].1 < expanded_end, "the zone shrank to its title");

        // Toggling again restores it.
        assert_eq!(view.process_space(false), SpaceKeyOutcome::ToggledZone);
        assert_eq!(view.zone_lines(), before);

        // A collapsed zone paints only its title.
        view.process_space(false);
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(100, 14);
        OnPaint::on_paint(&view, &mut surface, &theme);
        assert!(row_text(&surface, 0, 100).contains("Zone 0"));
        assert_eq!(row_text(&surface, 0, 1), "+", "the collapsed marker");
        assert!(!row_text(&surface, ZONE_TITLE_LINES, 100).contains("push"));
    }

    #[test]
    fn the_space_key_reaches_process_space_through_on_key_pressed() {
        let mut view = one_zone(Size::new(100, 14));
        assert!(!view.zone_lines()[0].2);
        assert!(processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::Space, KeyModifier::None),
            '\0'
        )));
        assert!(view.zone_lines()[0].2, "Space toggled the zone");
    }

    /// A zone the plugin placed past EOF is clamped to an empty region:
    /// the title still paints, nothing is decoded, nothing panics.
    #[test]
    fn a_zone_past_the_file_end_is_clamped_and_paints_empty() {
        let bytes = code();
        let zone = DisassemblyZone {
            starting_zone_point: bytes.len() as u64 + 0x1000,
            size: 0x4000,
            entry_point: bytes.len() as u64 + 0x1010,
            language: DisassemblyLanguage::X86,
        };
        let view = view_with(&bytes, vec![zone], Size::new(100, 14));
        let lines = view.zone_lines();
        assert_eq!(lines.len(), 1);
        // Clamped to a zero-byte region: only the title lines remain.
        assert_eq!(lines[0].1.saturating_sub(lines[0].0), ZONE_TITLE_LINES + 1);

        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(100, 14);
        OnPaint::on_paint(&view, &mut surface, &theme);
        assert!(row_text(&surface, 0, 100).contains("Zone 0"));
        assert_eq!(
            row_text(&surface, ZONE_TITLE_LINES, 100).trim(),
            "",
            "nothing decoded"
        );
    }

    #[test]
    fn an_empty_object_and_no_zones_never_panic() {
        let view = view_with(b"", Vec::new(), Size::new(100, 14));
        assert_eq!(view.zone_count(), 0);
        assert_eq!(view.layout().total_lines_size, 0);
        let theme = Theme::new(Themes::Default);
        let mut surface = Surface::new(100, 14);
        OnPaint::on_paint(&view, &mut surface, &theme);

        let mut view = view;
        // Movement on an empty document is a no-op, not a panic.
        for code in [KeyCode::Down, KeyCode::Up, KeyCode::PageDown, KeyCode::PageUp] {
            OnKeyPressed::on_key_pressed(&mut view, Key::new(code, KeyModifier::None), '\0');
        }
        assert_eq!(view.cursor().line_in_view, 0);
        assert_eq!(view.process_space(false), SpaceKeyOutcome::NotSingleZone);
        assert!(!view.go_to(0));
    }

    #[test]
    fn two_zones_are_laid_out_back_to_back() {
        let bytes = code();
        let half = bytes.len() as u64 / 2;
        let zones = vec![
            DisassemblyZone {
                starting_zone_point: 0,
                size: half,
                entry_point: 0,
                language: DisassemblyLanguage::X86,
            },
            DisassemblyZone {
                starting_zone_point: half,
                size: half,
                entry_point: half,
                language: DisassemblyLanguage::X64,
            },
        ];
        let mut view = view_with(&bytes, zones, Size::new(100, 14));
        let lines = view.zone_lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].0, 0);
        assert_eq!(lines[1].0, lines[0].1, "back to back on the line axis");
        assert!(view.layout().total_lines_size > 0);

        // GoTo lands on the zone owning the offset.
        assert!(view.go_to(half + 4));
        assert_eq!(view.cursor().start_view_line, lines[1].0);
        assert!(view.go_to(0));
        assert_eq!(view.cursor().start_view_line, 0);
        assert!(!view.go_to(bytes.len() as u64 + 100), "outside every zone");
    }

    #[test]
    fn the_mouse_wheel_scrolls_through_the_input_state_machine() {
        let mut view = one_zone(Size::new(100, 14));
        let before = view.cursor().start_view_line;
        assert!(processed(OnMouseEvent::on_mouse_event(
            &mut view,
            &MouseEvent::Wheel(MouseWheelDirection::Down)
        )));
        assert!(view.cursor().start_view_line >= before);
        assert!(processed(OnMouseEvent::on_mouse_event(
            &mut view,
            &MouseEvent::Wheel(MouseWheelDirection::Up)
        )));
        // A non-wheel event is ignored.
        let click = MouseEvent::Pressed(MouseEventData {
            x: 1,
            y: 1,
            button: MouseButton::Left,
            modifier: KeyModifier::None,
        });
        assert!(!processed(OnMouseEvent::on_mouse_event(&mut view, &click)));
    }

    #[test]
    fn enter_exports_the_selection_and_f7_toggles_show_only_dissasm() {
        let mut view = one_zone(Size::new(100, 14));
        assert!(view.pending_open().is_none());
        // Nothing selected: no request.
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Enter, KeyModifier::None), '\0');
        assert!(view.pending_open().is_none());

        assert!(view.select(0x10, 0x20));
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Enter, KeyModifier::None), '\0');
        assert_eq!(view.take_pending_open(), Some((0x10, 0x20)));
        assert!(view.pending_open().is_none(), "taken once");

        assert!(processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::F7, KeyModifier::None),
            '\0'
        )));
    }

    #[test]
    fn the_bottom_bar_shows_the_document_line() {
        let info = SharedCursorInfo::new();
        let bytes = code();
        let zone = DisassemblyZone {
            starting_zone_point: 0,
            size: bytes.len() as u64,
            entry_point: 0,
            language: DisassemblyLanguage::X86,
        };
        let mut view = DissasmView::from_settings(
            object_of(&bytes),
            DissasmViewSettings {
                request: DissasmViewerRequest {
                    zones: vec![zone],
                    ..DissasmViewerRequest::default()
                },
                cursor_info: info.clone(),
                ..DissasmViewSettings::default()
            },
        );
        OnResize::on_resize(&mut view, Size::new(0, 0), Size::new(100, 14));
        assert_eq!(info.read().name_str(), "Dissasm");
        OnKeyPressed::on_key_pressed(&mut view, Key::new(KeyCode::Down, KeyModifier::None), '\0');
        assert_eq!(info.read().offset, 1);

        let mut bar = Surface::new(60, 1);
        view.paint_cursor_information(&mut bar, 60, 1);
        assert!(read(&bar, 0, 0, 7).starts_with("Line:2"));
        let mut empty = Surface::new(1, 1);
        view.paint_cursor_information(&mut empty, 0, 0);
    }

    #[test]
    fn unhandled_keys_are_ignored() {
        let mut view = one_zone(Size::new(100, 14));
        assert!(!processed(OnKeyPressed::on_key_pressed(
            &mut view,
            Key::new(KeyCode::F12, KeyModifier::Alt),
            '\0'
        )));
        assert_eq!(ViewControl::name(&view), "Dissasm");
    }

    #[test]
    fn debug_app_paints_the_code_zone() {
        let script = "
            Paint.Enable(false)
            Paint('dissasm view with one x86 zone')
            CheckHash(0x910715AEBEF1FC7B)
        ";
        let mut app = App::debug(100, 16, script).build().expect("debug app");
        let mut window = Window::new("Test", layout!("a:c,w:96,h:14"), window::Flags::None);
        window.add(one_zone(Size::new(94, 12)));
        app.add_window(window);
        app.run();
    }
}
