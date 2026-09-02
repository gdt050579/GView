//! The ELF type plugin: `PopulateWindow` and the `TypeInterface`
//! methods.
//!
//! Spec `06_TYPE_PLUGINS` §ELF `PopulateWindow` / `SmartAssistant`;
//! C++ `elf.cpp` `CreateBufferView` / `PopulateWindow` /
//! `UpdateSettings`, `ELFFile.cpp` `GetColorForBuffer` /
//! `GetColorForBufferIntel` / `GetSmartAssistantContext`, `elf.hpp`
//! colours and panel ids.
//!
//! `PopulateWindow` (`elf.cpp:150-178`), in order:
//!
//! 1. `elf->Update()` — [`ElfFile::parse_cache`] over the window object;
//! 2. the buffer viewer (`CreateBufferView`): zones for the header
//!    (`Header32` / `Header64`), the program header table (`PHT32` /
//!    `PHT64`, `e_phnum * e_phentsize` bytes), the section header table
//!    (`SHT32` / `SHT64`), one zone per section named from the section
//!    name table (the loop stops at the first section without a name —
//!    truncated binaries); the entry point translated through the
//!    containing segment (`0` when none); the `VA` translation list;
//!    opcode colouring for the Intel family;
//! 3. panels gated by `HasPanel`: `Information` (right), `Segments` /
//!    `Sections` (bottom), the three Go panels, `StaticSymbols` /
//!    `DynamicSymbols` (bottom), `OpCodes` (right).
//!
//! [`ElfOpcodeColorizer`] is `GetColorForBuffer`: with a non-zero
//! `showOpcodesMask` it marks the `\x7fELF` magic (`Header` bit) and,
//! inside executable segments of Intel binaries, `FF 15` (call),
//! `FF 25` (jump), `CC` (breakpoint), `55 8B EC` (function start) and
//! `8B E5 5D C3` (function end). Unlike the PE plugin, the Intel
//! heuristics ignore the individual mask bits (C++ parity).

use std::sync::{Mutex, PoisonError};

use appcui::graphics::{CharAttribute, CharFlags, Color};
use gview_core::zones::ZonesList;
use gview_plugin::panel::{fmt, PanelContent};
use gview_plugin::type_plugin::{
    BufferViewerRequest, KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata, TypePlugin,
    ViewerRequest, WindowHandle,
};
use gview_view::buffer_viewer::color::{BufferColor, PositionToColorCallback};
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::parse::{is_intel_machine, ElfError, ElfFile, PanelId, ELF32_EHDR_SIZE, ELF64_EHDR_SIZE};
use crate::names;
use crate::parse::{EI_ABIVERSION, EI_CLASS, EI_DATA, EI_OSABI, EI_PAD, EI_VERSION};
use crate::validate::{validate, MAGIC, MAGIC_BYTES};

/// `GView::Dissasembly::Opcodes` bits (`GView.hpp:816`).
pub mod opcodes {
    /// `Header`.
    pub const HEADER: u32 = 1;
    /// `Call`.
    pub const CALL: u32 = 2;
    /// `Jmp`.
    pub const JMP: u32 = 8;
    /// `Breakpoint`.
    pub const BREAKPOINT: u32 = 32;
    /// `FunctionStart`.
    pub const FUNCTION_START: u32 = 64;
    /// `FunctionEnd`.
    pub const FUNCTION_END: u32 = 128;
    /// `All`.
    pub const ALL: u32 = 0xFFFF_FFFF;
}

/// `UpdateSettings` `Description`.
pub const DESCRIPTION: &str = "Executable and Linkable Format (for UNIX systems)";
/// `UpdateSettings` `Priority`.
pub const PRIORITY: u32 = 1;
/// `SetOffsetTranslationList({ "VA" })`.
pub const TRANSLATION_METHODS: [&str; 1] = ["VA"];

fn attr(fore: Color, back: Color) -> CharAttribute {
    CharAttribute::new(fore, back, CharFlags::None)
}

/// `elf.cpp` zone colours.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ElfColors {
    /// `HEADER_COLOR` (Olive).
    pub header: CharAttribute,
    /// `PHT_COLOR` (Magenta).
    pub pht: CharAttribute,
    /// `SHT_COLOR` (`DarkRed`).
    pub sht: CharAttribute,
    /// `SHT_CONTENT_COLOR` (Silver).
    pub sht_content: CharAttribute,
}

impl Default for ElfColors {
    fn default() -> Self {
        Self {
            header: attr(Color::Olive, Color::Transparent),
            pht: attr(Color::Magenta, Color::Transparent),
            sht: attr(Color::DarkRed, Color::Transparent),
            sht_content: attr(Color::Silver, Color::Transparent),
        }
    }
}

/// `elf.hpp` opcode colours.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OpcodeColors {
    /// `INS_CALL_COLOR` (White on Silver).
    pub call: CharAttribute,
    /// `INS_JUMP_COLOR` (Yellow on `DarkRed`).
    pub jump: CharAttribute,
    /// `INS_BREAKPOINT_COLOR` (Green on `DarkBlue`).
    pub breakpoint: CharAttribute,
    /// `START_FUNCTION_COLOR` (Yellow on Olive).
    pub function_start: CharAttribute,
    /// `END_FUNCTION_COLOR` (Black on Olive).
    pub function_end: CharAttribute,
    /// `EXE_MARKER_COLOR` (Yellow on `DarkRed`).
    pub exe_marker: CharAttribute,
}

impl Default for OpcodeColors {
    fn default() -> Self {
        Self {
            call: attr(Color::White, Color::Silver),
            jump: attr(Color::Yellow, Color::DarkRed),
            breakpoint: attr(Color::Green, Color::DarkBlue),
            function_start: attr(Color::Yellow, Color::Olive),
            function_end: attr(Color::Black, Color::Olive),
            exe_marker: attr(Color::Yellow, Color::DarkRed),
        }
    }
}

/// The panels `PopulateWindow` can add (the C++ `TabPage` classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    /// `Panels::Information`.
    Information,
    /// `Panels::Segments`.
    Segments,
    /// `Panels::Sections`.
    Sections,
    /// `Panels::GoInformation`.
    GoInformation,
    /// `Panels::GoFiles`.
    GoFiles,
    /// `Panels::GoFunctions`.
    GoFunctions,
    /// `Panels::StaticSymbols`.
    StaticSymbols,
    /// `Panels::DynamicSymbols`.
    DynamicSymbols,
    /// `Panels::OpCodes`.
    OpCodes,
}

impl Panel {
    /// Tab caption of the C++ panel class.
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::Information => "Informa&tion",
            Self::Segments => "Se&gments",
            Self::Sections => "&Sections",
            Self::GoInformation => "GoInfo&rmation",
            Self::GoFiles => "Go&Modules",
            Self::GoFunctions => "G&oFunctions",
            Self::StaticSymbols => "St&aticSymbols",
            Self::DynamicSymbols => "D&ynamicSymbols",
            Self::OpCodes => "Op&Codes",
        }
    }

    /// Stable panel identifier for the shell.
    #[must_use]
    pub const fn panel_id(self) -> &'static str {
        match self {
            Self::Information => "elf.information",
            Self::Segments => "elf.segments",
            Self::Sections => "elf.sections",
            Self::GoInformation => "elf.go.information",
            Self::GoFiles => "elf.go.files",
            Self::GoFunctions => "elf.go.functions",
            Self::StaticSymbols => "elf.static_symbols",
            Self::DynamicSymbols => "elf.dynamic_symbols",
            Self::OpCodes => "elf.opcodes",
        }
    }

    /// The `HasPanel` bit that gates this panel.
    #[must_use]
    pub const fn gate(self) -> PanelId {
        match self {
            Self::Information => PanelId::Information,
            Self::Segments => PanelId::Segments,
            Self::Sections => PanelId::Sections,
            Self::GoInformation | Self::GoFiles | Self::GoFunctions => PanelId::GoInformation,
            Self::StaticSymbols => PanelId::StaticSymbols,
            Self::DynamicSymbols => PanelId::DynamicSymbols,
            Self::OpCodes => PanelId::OpCodes,
        }
    }
}

/// Panels in C++ `PopulateWindow` order: `(panel, vertical)`.
pub const PANEL_ORDER: [(Panel, bool); 9] = [
    (Panel::Information, true),
    (Panel::Segments, false),
    (Panel::Sections, false),
    (Panel::GoInformation, true),
    (Panel::GoFiles, true),
    (Panel::GoFunctions, false),
    (Panel::StaticSymbols, false),
    (Panel::DynamicSymbols, false),
    (Panel::OpCodes, true),
];

/// The `BufferViewer::Settings` of `CreateBufferView` (`elf.cpp:32-148`).
#[must_use]
pub fn buffer_view_request(elf: &ElfFile, colors: &ElfColors) -> BufferViewerRequest {
    let mut zones = ZonesList::new();
    let header = &elf.header;
    let (ehdr_size, header_name, pht_name, sht_name) = if elf.is64 {
        (ELF64_EHDR_SIZE as u64, "Header64", "PHT64", "SHT64")
    } else {
        (ELF32_EHDR_SIZE as u64, "Header32", "PHT32", "SHT32")
    };
    zones.add_sized(0, ehdr_size, colors.header, header_name);
    let pht_size = u64::from(header.phnum).saturating_mul(u64::from(header.phentsize));
    zones.add_sized(header.phoff, pht_size, colors.pht, pht_name);
    let sht_size = u64::from(header.shnum).saturating_mul(u64::from(header.shentsize));
    zones.add_sized(header.shoff, sht_size, colors.sht, sht_name);
    // One zone per section; the loop stops where names run out.
    for (section, name) in elf.sections.iter().zip(elf.section_names.iter()) {
        zones.add_sized(section.offset, section.size, colors.sht_content, name.as_str());
    }
    BufferViewerRequest {
        zones,
        bookmarks: Vec::new(),
        entry_point: Some(elf.entry_point_file_offset()),
        translation_methods: TRANSLATION_METHODS.iter().map(|s| (*s).to_owned()).collect(),
        dissasm_settings: DissasmSettings::default(),
        position_to_color: is_intel_machine(header.machine),
    }
}

/// C++ `ELFFile::GetColorForBuffer` state: the machine, the executable
/// segment ranges and `showOpcodesMask`.
#[derive(Clone, Debug, PartialEq)]
pub struct ElfOpcodeColorizer {
    /// `e_machine`.
    pub machine: u16,
    /// `executableZonesFAs`.
    pub executable_zones: Vec<(u64, u64)>,
    /// `showOpcodesMask` (0 until the `OpCodes` panel reads
    /// `Type.ELF` / `OpCodes.Mask`).
    pub show_opcodes_mask: u32,
    /// Colours.
    pub colors: OpcodeColors,
}

impl ElfOpcodeColorizer {
    /// Colorizer for a parsed file with the given mask.
    #[must_use]
    pub fn new(elf: &ElfFile, show_opcodes_mask: u32) -> Self {
        Self {
            machine: elf.header.machine,
            executable_zones: elf.executable_zones.clone(),
            show_opcodes_mask,
            colors: OpcodeColors::default(),
        }
    }

    /// C++ `GetColorForBufferIntel` (no mask bits consulted).
    #[must_use]
    pub fn color_for_buffer_intel(&self, offset: u64, buf: &[u8]) -> Option<BufferColor> {
        let first = *buf.first()?;
        let range = |len: u64, color: CharAttribute| {
            Some(BufferColor {
                start: offset,
                end: offset.wrapping_add(len),
                color,
            })
        };
        match first {
            0xFF if buf.len() >= 6 => match buf.get(1)? {
                0x15 => range(5, self.colors.call),
                0x25 => range(5, self.colors.jump),
                _ => None,
            },
            0xCC => range(0, self.colors.breakpoint),
            0x55 if buf.len() >= 3 && buf.get(1..3)? == [0x8B, 0xEC] => range(2, self.colors.function_start),
            0x8B if buf.len() >= 4 && buf.get(1..4)? == [0xE5, 0x5D, 0xC3] => range(3, self.colors.function_end),
            _ => None,
        }
    }

    /// Whether `offset` lies in an executable segment.
    #[must_use]
    pub fn is_executable(&self, offset: u64) -> bool {
        self.executable_zones
            .iter()
            .any(|&(start, end)| offset >= start && offset < end)
    }
}

impl PositionToColorCallback for ElfOpcodeColorizer {
    /// C++ `GetColorForBuffer`.
    fn color_for_buffer(&mut self, offset: u64, buf: &[u8]) -> Option<BufferColor> {
        let first = *buf.first()?;
        if self.show_opcodes_mask == 0 {
            return None;
        }
        if first == 0x7F && self.show_opcodes_mask & opcodes::HEADER == opcodes::HEADER {
            if let Some(head) = buf.get(..4) {
                if head == MAGIC_BYTES {
                    return Some(BufferColor {
                        start: offset,
                        end: offset.wrapping_add(3),
                        color: self.colors.exe_marker,
                    });
                }
            }
            // "do not break": fall through to the machine switch.
        }
        if is_intel_machine(self.machine) && self.is_executable(offset) {
            return self.color_for_buffer_intel(offset, buf);
        }
        None
    }
}

/// The ELF `TypeInterface` (C++ `ELF::ELFFile` as a type instance).
pub struct ElfPlugin {
    colors: ElfColors,
    state: Mutex<Option<ElfFile>>,
    object: Mutex<Option<SharedObject>>,
    last_command: Mutex<Option<String>>,
    show_opcodes_mask: Mutex<u32>,
}

impl Default for ElfPlugin {
    fn default() -> Self {
        Self {
            colors: ElfColors::default(),
            state: Mutex::new(None),
            object: Mutex::new(None),
            last_command: Mutex::new(None),
            show_opcodes_mask: Mutex::new(0),
        }
    }
}

impl core::fmt::Debug for ElfPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let parsed = self.state.lock().is_ok_and(|s| s.is_some());
        f.debug_struct("ElfPlugin").field("parsed", &parsed).finish_non_exhaustive()
    }
}

impl ElfPlugin {
    /// The parsed file after `PopulateWindow`.
    #[must_use]
    pub fn file(&self) -> Option<ElfFile> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The last `RunCommand` name (the C++ `RunCommand` is empty; the
    /// name is recorded for the shell).
    #[must_use]
    pub fn last_command(&self) -> Option<String> {
        self.last_command.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// `showOpcodesMask`.
    #[must_use]
    pub fn show_opcodes_mask(&self) -> u32 {
        *self.show_opcodes_mask.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets `showOpcodesMask` (the `OpCodes` panel's `Update`).
    pub fn set_show_opcodes_mask(&self, mask: u32) {
        *self.show_opcodes_mask.lock().unwrap_or_else(PoisonError::into_inner) = mask;
    }

    /// The `PositionToColorInterface` for the current file.
    #[must_use]
    pub fn colorizer(&self) -> Option<ElfOpcodeColorizer> {
        self.file().map(|elf| ElfOpcodeColorizer::new(&elf, self.show_opcodes_mask()))
    }
}

impl TypePlugin for ElfPlugin {
    fn name(&self) -> &'static str {
        "ELF"
    }

    fn validate(buf: &[u8], extension: &str) -> bool {
        validate(buf, extension)
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// C++ `UpdateSettings` (`elf.cpp:171-177`).
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: vec![Pattern::Magic(MAGIC_BYTES.to_vec())],
            priority: PRIORITY,
            description: String::from(DESCRIPTION),
            extensions: Vec::new(),
            commands: Vec::new(),
            opcodes_mask: Some(opcodes::ALL),
        }
    }

    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        let elf = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            ElfFile::parse_cache(guard.data_mut()).map_err(|e: ElfError| PluginError::Window(e.to_string()))?
        };
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));

        win.create_viewer(ViewerRequest::buffer(buffer_view_request(&elf, &self.colors)))?;
        for (panel, vertical) in PANEL_ORDER {
            if elf.has_panel(panel.gate()) {
                win.add_panel(
                    PanelRequest {
                        caption: String::from(panel.caption()),
                        panel_id: String::from(panel.panel_id()),
                    },
                    vertical,
                );
            }
        }
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some(elf);
        Ok(())
    }

    fn run_command(&mut self, command: &str) {
        *self.last_command.lock().unwrap_or_else(PoisonError::into_inner) = Some(command.to_owned());
    }

    /// C++ `UpdateKeys`: nothing registered.
    fn register_keys(&self, _keys: &mut dyn KeyRegistry) {}


    /// C++ `Panels::Information::UpdateGeneralInformation` +
    /// `UpdateHeader` (`Types/ELF/src/Panels/Information.cpp:17-158`):
    /// the `Info` category (`File`, `Size`), the `Header` category and
    /// then every `e_ident` / `Elf_Ehdr` field, each rendered
    /// `"%-16s (%s)"` (decimal padded to 16, then hex) — or
    /// `"%-16s (%s) %s"` for `Type`, which appends the description.
    ///
    /// The C++ has two identical branches for 32- and 64-bit headers;
    /// the Rust parser already widens both into one [`ElfHeader`], so
    /// one branch reproduces both.
    fn panel_content(&self, panel_id: &str) -> Option<PanelContent> {
        if panel_id != Panel::Information.panel_id() {
            return None;
        }
        let elf = self.file()?;
        let object = self.object.lock().unwrap_or_else(PoisonError::into_inner).clone()?;
        let (name, size) = {
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            (guard.name().to_owned(), guard.data().size())
        };
        let header = &elf.header;
        let ident = |index: usize| header.ident.get(index).copied().unwrap_or(0);
        // `*(uint32*) header.e_ident` and the two `EI_PAD` words, read
        // little-endian like the C++ `reinterpret_cast` on x86.
        let word_at = |index: usize| -> u32 {
            u32::from_le_bytes([
                ident(index),
                ident(index.saturating_add(1)),
                ident(index.saturating_add(2)),
                ident(index.saturating_add(3)),
            ])
        };
        let row = |caption: &str, value: u64| (String::from(caption), fmt::dec_and_hex(value, 16));
        // `"%-16s (%s)"` with a name instead of the decimal form.
        let named = |caption: &str, text: &str, value: u64| {
            (String::from(caption), format!("{} ({})", fmt::pad(text, 16), fmt::hex(value)))
        };
        let (type_name, type_description) = names::type_name_and_description(header.e_type);
        let os_abi = ident(EI_OSABI);
        let mut rows = vec![
            (String::from("Info"), String::new()),
            (String::from("File"), name),
            row("Size", size),
            (String::from("Header"), String::new()),
            row("Magic", u64::from(word_at(0))),
            named("Class", names::class_name(ident(EI_CLASS)), u64::from(ident(EI_CLASS))),
            named("Data", names::data_name(ident(EI_DATA)), u64::from(ident(EI_DATA))),
            named(
                "Version",
                names::version_name(ident(EI_VERSION)),
                u64::from(ident(EI_VERSION)),
            ),
            // C++ quirk: the OS ABI row prints the *version* byte in
            // its hex column (`nf.ToString(header.e_ident[EI_VERSION], hex)`).
            named("OS ABI", names::os_abi_name(os_abi), u64::from(ident(EI_VERSION))),
            named(
                "ABI Version",
                names::abi_version_name(os_abi, ident(EI_ABIVERSION)),
                u64::from(ident(EI_ABIVERSION)),
            ),
            row("PAD1", u64::from(word_at(EI_PAD))),
            // C++ `(*(uint32*)(e_ident + EI_PAD + 4)) << 8`.
            row("PAD2", u64::from(word_at(EI_PAD.saturating_add(4)) << 8)),
            (
                String::from("Type"),
                format!(
                    "{} ({}) {type_description}",
                    fmt::pad(type_name, 16),
                    fmt::hex(u64::from(header.e_type))
                ),
            ),
            named(
                "Machine",
                names::machine_description(header.machine),
                u64::from(header.machine),
            ),
            named(
                "Version",
                names::version_name(header.version as u8),
                u64::from(header.version),
            ),
            row("Entry Point", header.entry),
            row("PHT File Offset", header.phoff),
            row("SHT File Offset", header.shoff),
            row("Processor Flags", u64::from(header.flags)),
            row("ELF Header Size", u64::from(header.ehsize)),
            row("PHT Entry Size", u64::from(header.phentsize)),
            row("PHT # Entries", u64::from(header.phnum)),
            row("SH Size", u64::from(header.shentsize)),
            row("SHT # Entries", u64::from(header.shnum)),
            row("SHT String Index", u64::from(header.shstrndx)),
        ];
        rows.shrink_to_fit();
        Some(PanelContent::KeyValue(rows))
    }

    /// C++ `SetPositionToColorCallback(elf)` (`elf.cpp`
    /// `CreateBufferView`, gated on an Intel machine).
    fn position_to_color(&self) -> Option<Box<dyn PositionToColorCallback + Send>> {
        self.colorizer()
            .filter(|c| is_intel_machine(c.machine))
            .map(|c| Box::new(c) as Box<dyn PositionToColorCallback + Send>)
    }

    /// C++ `GetSmartAssistantContext` (`ELFFile.cpp`): `Name`,
    /// `ContentSize` and, when present, `SectionNames`.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        let elf = self
            .file()
            .ok_or_else(|| PluginError::Assistant(String::from("PopulateWindow was not called")))?;
        let bound = self
            .object
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(SharedObject::clone)
            .ok_or_else(|| PluginError::Assistant(String::from("no object bound")))?;
        let (name, size) = {
            let object = bound.lock().unwrap_or_else(PoisonError::into_inner);
            (object.name().to_owned(), object.data().size())
        };
        let mut context = serde_json::json!({
            "Name": name,
            "ContentSize": size,
        });
        if !elf.section_names.is_empty() {
            if let Some(map) = context.as_object_mut() {
                map.insert(
                    String::from("SectionNames"),
                    JsonValue::Array(elf.section_names.iter().map(|n| JsonValue::String(n.clone())).collect()),
                );
            }
        }
        Ok(context)
    }
}

/// Sanity: the `Validate` magic and the INI pattern agree.
#[must_use]
pub const fn pattern_matches_validate_magic() -> bool {
    u32::from_le_bytes(MAGIC_BYTES) == MAGIC
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::parse::tests::{build_elf, typical, SectionSpec, SegmentSpec};
    use crate::parse::{machine, PT_LOAD, SHT_NOBITS};
    use gview_core::object::Object;
    use gview_plugin::type_plugin::{CommandDef, ViewerKind};
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Default)]
    struct MockWindow {
        object: Option<SharedObject>,
        viewers: Vec<ViewerRequest>,
        panels: Vec<(String, bool)>,
    }

    impl WindowHandle for MockWindow {
        fn object(&self) -> SharedObject {
            self.object
                .clone()
                .unwrap_or_else(|| Arc::new(StdMutex::new(Object::from_buffer(b"", "x", 0))))
        }
        fn add_panel(&mut self, panel: PanelRequest, vertical: bool) -> bool {
            self.panels.push((panel.caption, vertical));
            true
        }
        fn create_viewer(&mut self, request: ViewerRequest) -> Result<u32, PluginError> {
            self.viewers.push(request);
            Ok(self.viewers.len() as u32 - 1)
        }
        fn views_count(&self) -> u32 {
            self.viewers.len() as u32
        }
        fn set_view_by_index(&mut self, _index: u32) -> bool {
            true
        }
        fn current_view(&self) -> Option<u32> {
            None
        }
    }

    fn window_for(image: &[u8], name: &str) -> MockWindow {
        MockWindow {
            object: Some(Arc::new(StdMutex::new(Object::from_buffer(image, name, 0)))),
            ..MockWindow::default()
        }
    }

    /// `color_for_buffer` as a comparable triple (`BufferColor` has no
    /// `PartialEq`).
    fn cb(c: &mut ElfOpcodeColorizer, offset: u64, buf: &[u8]) -> Option<(u64, u64, CharAttribute)> {
        PositionToColorCallback::color_for_buffer(c, offset, buf).map(|b| (b.start, b.end, b.color))
    }

    fn zone_names(request: &BufferViewerRequest) -> Vec<(String, u64, u64)> {
        (0..request.zones.count())
            .filter_map(|i| request.zones.zone(i).map(|z| (z.name.clone(), z.low, z.high)))
            .collect()
    }

    #[test]
    fn populate_creates_buffer_view_zones_and_panels_for_x86_64() {
        for is64 in [false, true] {
            let image = typical(is64, machine::EM_X86_64);
            let plugin = ElfPlugin::create_instance();
            let mut win = window_for(&image, "a.out");
            plugin.populate_window(&mut win).expect("populate");
            let elf = plugin.file().expect("parsed");

            assert_eq!(win.viewers.len(), 1);
            assert_eq!(win.viewers[0].kind, ViewerKind::Buffer);
            let buffer = win.viewers[0].buffer.as_ref().expect("buffer settings");
            let zones = zone_names(buffer);
            let (ehdr, hname, pname, sname) = if is64 {
                (ELF64_EHDR_SIZE as u64, "Header64", "PHT64", "SHT64")
            } else {
                (ELF32_EHDR_SIZE as u64, "Header32", "PHT32", "SHT32")
            };
            assert_eq!(zones[0], (String::from(hname), 0, ehdr - 1));
            let pht = u64::from(elf.header.phnum) * u64::from(elf.header.phentsize);
            assert_eq!(zones[1], (String::from(pname), elf.header.phoff, elf.header.phoff + pht - 1));
            let sht = u64::from(elf.header.shnum) * u64::from(elf.header.shentsize);
            assert_eq!(zones[2], (String::from(sname), elf.header.shoff, elf.header.shoff + sht - 1));
            // Sections: the NULL section (size 0) is skipped by AddZone;
            // every other section gets a zone named from .shstrtab.
            let names: Vec<&str> = zones.iter().skip(3).map(|(n, _, _)| n.as_str()).collect();
            assert_eq!(
                names,
                [".text", ".data", ".symtab", ".strtab", ".dynsym", ".dynstr", ".note.go.buildid", ".shstrtab"]
            );
            let text = elf.sections[1];
            assert_eq!(zones[3].1, text.offset);
            assert_eq!(zones[3].2, text.offset + text.size - 1);
            assert_eq!(buffer.entry_point, Some(text.offset + 0x10));
            assert_eq!(buffer.translation_methods, ["VA"]);
            assert!(buffer.position_to_color);
            assert!(buffer.bookmarks.is_empty());
            assert_eq!(buffer.dissasm_settings, DissasmSettings::default());

            assert_eq!(
                win.panels,
                [
                    (String::from("Informa&tion"), true),
                    (String::from("Se&gments"), false),
                    (String::from("&Sections"), false),
                    (String::from("St&aticSymbols"), false),
                    (String::from("D&ynamicSymbols"), false),
                    (String::from("Op&Codes"), true),
                ]
            );
        }
    }

    #[test]
    fn go_binary_adds_three_go_panels_and_arm_has_no_opcodes() {
        let sections = vec![
            SectionSpec::new(".text", 1, 0x1000, vec![0xC3; 0x10]),
            SectionSpec::new(".gopclntab", 1, 0x2000, vec![0xFA, 0xFF, 0xFF, 0xFF, 0, 0, 1, 8]),
            SectionSpec::new(".bss", SHT_NOBITS, 0x3000, vec![0; 0x20]),
        ];
        let segments = vec![SegmentSpec {
            p_type: PT_LOAD,
            flags: 5,
            first_section: 0,
            last_section: 0,
            extra_memsz: 0,
        }];
        let image = build_elf(true, machine::EM_AARCH64, 0x1004, &sections, &segments);
        let plugin = ElfPlugin::create_instance();
        let mut win = window_for(&image, "go-arm64");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(
            win.panels,
            [
                (String::from("Informa&tion"), true),
                (String::from("Se&gments"), false),
                (String::from("&Sections"), false),
                (String::from("GoInfo&rmation"), true),
                (String::from("Go&Modules"), true),
                (String::from("G&oFunctions"), false),
            ]
        );
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        assert!(!buffer.position_to_color);
        let elf = plugin.file().expect("parsed");
        assert_eq!(buffer.entry_point, Some(elf.sections[1].offset + 4));
        // .bss keeps a zone (sh_size > 0), like the C++.
        assert!(zone_names(buffer).iter().any(|(n, _, _)| n == ".bss"));
        assert!(plugin.colorizer().is_some());
    }

    #[test]
    fn missing_section_names_stop_the_section_zones() {
        let mut image = typical(false, machine::EM_386);
        image[50..52].copy_from_slice(&0xFFFF_u16.to_le_bytes()); // shstrndx → SHN_XINDEX
        let plugin = ElfPlugin::create_instance();
        let mut win = window_for(&image, "nonames");
        plugin.populate_window(&mut win).expect("populate");
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        assert_eq!(buffer.zones.count(), 3, "header, PHT, SHT only");
        // No Go panel without names either.
        assert!(!win.panels.iter().any(|(c, _)| c.starts_with("Go")));
    }

    #[test]
    fn broken_headers_fail_populate_without_viewers() {
        let plugin = ElfPlugin::create_instance();
        let mut win = window_for(b"\x7fELF\x02\x01\x01", "tiny");
        let err = plugin.populate_window(&mut win).expect_err("truncated header");
        assert!(matches!(err, PluginError::Window(_)));
        assert!(win.viewers.is_empty());
        assert!(win.panels.is_empty());
        assert!(plugin.file().is_none());
        assert!(plugin.colorizer().is_none());
        assert!(format!("{plugin:?}").contains("parsed: false"));
    }


    /// Field list and value formatting of C++
    /// `Panels::Information::UpdateGeneralInformation` +
    /// `UpdateHeader` (`Types/ELF/src/Panels/Information.cpp`).
    #[test]
    fn information_panel_matches_cpp_field_list() {
        let plugin = ElfPlugin::create_instance();
        assert!(
            plugin.panel_content(Panel::Information.panel_id()).is_none(),
            "no panel before populate_window"
        );

        let image = typical(true, machine::EM_X86_64);
        let mut win = window_for(&image, "bin");
        plugin.populate_window(&mut win).expect("populate");
        let content = plugin.panel_content(Panel::Information.panel_id()).expect("panel");
        let PanelContent::KeyValue(rows) = &content else {
            panic!("Information is a key/value panel");
        };
        let fields: Vec<&str> = rows.iter().map(|(f, _)| f.as_str()).collect();
        assert_eq!(
            fields,
            [
                "Info",
                "File",
                "Size",
                "Header",
                "Magic",
                "Class",
                "Data",
                "Version",
                "OS ABI",
                "ABI Version",
                "PAD1",
                "PAD2",
                "Type",
                "Machine",
                "Version",
                "Entry Point",
                "PHT File Offset",
                "SHT File Offset",
                "Processor Flags",
                "ELF Header Size",
                "PHT Entry Size",
                "PHT # Entries",
                "SH Size",
                "SHT # Entries",
                "SHT String Index",
            ]
        );
        let elf = plugin.file().expect("parsed");
        assert_eq!(rows[1].1, "bin");
        assert_eq!(rows[2].1, fmt::dec_and_hex(image.len() as u64, 16));
        // `*(uint32*) e_ident` = 0x464C457F little-endian.
        assert_eq!(rows[4].1, fmt::dec_and_hex(0x464C_457F, 16));
        assert_eq!(rows[5].1, format!("{} (0x2)", fmt::pad("64", 16)), "ELFCLASS64");
        assert_eq!(rows[6].1, format!("{} (0x1)", fmt::pad("2LSB (Little)", 16)));
        assert_eq!(
            rows[12].1,
            format!(
                "{} ({}) {}",
                fmt::pad(names::type_name_and_description(elf.header.e_type).0, 16),
                fmt::hex(u64::from(elf.header.e_type)),
                names::type_name_and_description(elf.header.e_type).1
            )
        );
        assert_eq!(
            rows[13].1,
            format!(
                "{} ({})",
                fmt::pad(names::machine_description(machine::EM_X86_64), 16),
                fmt::hex(u64::from(machine::EM_X86_64))
            )
        );
        assert_eq!(
            names::machine_description(machine::EM_X86_64),
            "Advanced Micro Devices X86-64 processor",
            "verbatim from GetNameFromElfMachine"
        );
        assert_eq!(rows[15].1, fmt::dec_and_hex(elf.header.entry, 16), "Entry Point");
        assert!(plugin.panel_content(Panel::Sections.panel_id()).is_none());
    }

    /// A header that fails to parse leaves no state: `None`, no panic.
    #[test]
    fn information_panel_without_state_is_none() {
        let plugin = ElfPlugin::create_instance();
        let mut win = window_for(b"\x7fELF\x02\x01\x01", "tiny");
        assert!(plugin.populate_window(&mut win).is_err());
        assert!(plugin.panel_content(Panel::Information.panel_id()).is_none());
    }

    /// `00_APP §5.3.3`: the boxed hook is `None` before
    /// `populate_window`, and afterwards colours exactly what
    /// [`ElfOpcodeColorizer`] colours (same ranges as
    /// `opcode_colorizer_matches_cpp_heuristics`).
    #[test]
    fn position_to_color_hooks_wrap_the_colorizer() {
        let plugin = ElfPlugin::create_instance();
        assert!(plugin.position_to_color().is_none(), "before populate_window");
        assert!(plugin.container_enumerator().is_none());
        assert!(plugin.container_opener().is_none());
        assert!(plugin.panel_content("elf.information").is_none());

        let image = typical(true, machine::EM_X86_64);
        let mut win = window_for(&image, "ops");
        plugin.populate_window(&mut win).expect("populate");
        plugin.set_show_opcodes_mask(opcodes::ALL);

        let elf = plugin.file().expect("parsed");
        let text_offset = elf.sections[1].offset;
        let colors = OpcodeColors::default();
        let mut hook = plugin.position_to_color().expect("hook");
        let mut direct = plugin.colorizer().expect("colorizer");
        for (offset, bytes) in [
            (0_u64, b"\x7fELF\x02".as_slice()),
            (text_offset, &[0xCC, 0, 0, 0]),
            (text_offset, &[0x55, 0x8B, 0xEC]),
            (text_offset, &[0x8B, 0xE5, 0x5D, 0xC3]),
            (text_offset, &[0x90, 0x90]),
        ] {
            let boxed = hook.color_for_buffer(offset, bytes).map(|b| (b.start, b.end, b.color));
            assert_eq!(
                boxed,
                cb(&mut direct, offset, bytes),
                "hook and colorizer disagree at {offset:#x}"
            );
        }
        assert_eq!(
            hook.color_for_buffer(0, b"\x7fELF\x02").map(|b| b.color),
            Some(colors.exe_marker)
        );

        // A non-Intel machine gets no callback at all (the C++
        // `SetPositionToColorCallback` gate).
        let arm = typical(true, machine::EM_AARCH64);
        let mut win = window_for(&arm, "arm");
        plugin.populate_window(&mut win).expect("populate");
        assert!(plugin.position_to_color().is_none(), "AArch64 does not colour opcodes");
    }

    #[test]
    fn opcode_colorizer_matches_cpp_heuristics() {
        let image = typical(true, machine::EM_X86_64);
        let plugin = ElfPlugin::create_instance();
        let mut win = window_for(&image, "ops");
        plugin.populate_window(&mut win).expect("populate");
        let elf = plugin.file().expect("parsed");
        let text = elf.sections[1];
        let colors = OpcodeColors::default();

        // Mask 0: nothing (the C++ CHECK).
        let mut off = plugin.colorizer().expect("colorizer");
        assert_eq!(off.show_opcodes_mask, 0);
        assert_eq!(cb(&mut off, text.offset, &[0xCC, 0, 0, 0]), None);
        assert_eq!(cb(&mut off, 0, b"\x7fELF"), None);

        plugin.set_show_opcodes_mask(opcodes::ALL);
        assert_eq!(plugin.show_opcodes_mask(), opcodes::ALL);
        let mut c = plugin.colorizer().expect("colorizer");
        assert_eq!(c.machine, machine::EM_X86_64);
        assert_eq!(c.executable_zones, elf.executable_zones);

        // Header marker at offset 0 (outside executable zones).
        assert_eq!(
            cb(&mut c, 0, b"\x7fELF\x02"),
            Some((0, 3, colors.exe_marker))
        );
        assert_eq!(cb(&mut c, 0, b"\x7fEL"), None, "needs 4 bytes");
        assert_eq!(cb(&mut c, 0, b"\x7fELG"), None);
        // Header bit off: no marker, fall through to Intel (not executable → None).
        c.show_opcodes_mask = opcodes::CALL;
        assert_eq!(cb(&mut c, 0, b"\x7fELF"), None);
        c.show_opcodes_mask = opcodes::ALL;

        // Intel heuristics inside the executable zone.
        let at = text.offset + 8;
        let expect = |end: u64, color: CharAttribute| Some((at, end, color));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x15, 1, 2, 3, 4]), expect(at + 5, colors.call));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x25, 1, 2, 3, 4]), expect(at + 5, colors.jump));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x15, 1, 2, 3]), None, "needs 6 bytes");
        assert_eq!(cb(&mut c, at, &[0xFF, 0x35, 1, 2, 3, 4]), None);
        assert_eq!(cb(&mut c, at, &[0xCC]), expect(at, colors.breakpoint));
        assert_eq!(cb(&mut c, at, &[0x55, 0x8B, 0xEC]), expect(at + 2, colors.function_start));
        assert_eq!(cb(&mut c, at, &[0x55, 0x8B]), None);
        assert_eq!(cb(&mut c, at, &[0x55, 0x8B, 0xED]), None);
        assert_eq!(cb(&mut c, at, &[0x8B, 0xE5, 0x5D, 0xC3]), expect(at + 3, colors.function_end));
        assert_eq!(cb(&mut c, at, &[0x8B, 0xE5, 0x5D, 0xC2]), None);
        assert_eq!(cb(&mut c, at, &[0x90, 0x90]), None);
        assert_eq!(cb(&mut c, at, &[]), None);
        // Same bytes outside the executable zone: nothing.
        let data = elf.sections[2].offset;
        assert_eq!(cb(&mut c, data, &[0xCC]), None);
        assert_eq!(cb(&mut c, text.offset + text.size, &[0xCC]), None, "end is exclusive");
        // The individual Intel bits are not consulted (C++ parity).
        c.show_opcodes_mask = opcodes::HEADER;
        assert_eq!(cb(&mut c, at, &[0xCC]), expect(at, colors.breakpoint));
        // Non-Intel machine: no Intel colouring even when executable.
        c.machine = machine::EM_ARM;
        assert_eq!(cb(&mut c, at, &[0xCC]), None);
        assert!(c.is_executable(at));
        assert_eq!(
            cb(&mut c, 0, b"\x7fELF"),
            Some((0, 3, colors.exe_marker))
        );
    }

    #[test]
    fn metadata_keys_commands_and_assistant_context() {
        struct Keys(Vec<String>);
        impl KeyRegistry for Keys {
            fn register_key(&mut self, command: &CommandDef) -> bool {
                self.0.push(command.name.clone());
                true
            }
        }
        let meta = ElfPlugin::metadata();
        assert_eq!(meta.pattern, [Pattern::Magic(vec![0x7F, 0x45, 0x4C, 0x46])]);
        assert_eq!(meta.pattern[0].to_ini_string(), "magic:7F 45 4C 46");
        assert_eq!(meta.priority, 1);
        assert_eq!(meta.description, DESCRIPTION);
        assert_eq!(meta.opcodes_mask, Some(0xFFFF_FFFF));
        assert!(meta.commands.is_empty());
        assert!(meta.extensions.is_empty());
        assert!(pattern_matches_validate_magic());
        assert_eq!(ElfPlugin::validate(b"\x7fELF\x01", ".so"), validate(b"\x7fELF\x01", ".so"));

        let mut plugin = ElfPlugin::create_instance();
        assert_eq!(plugin.name(), "ELF");
        assert!(plugin.smart_assistant_context("", "").is_err());
        plugin.run_command("Anything");
        assert_eq!(plugin.last_command().as_deref(), Some("Anything"));
        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert!(keys.0.is_empty());

        let image = typical(true, machine::EM_386);
        let mut win = window_for(&image, "ctx.elf");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("what", "what").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.elf");
        assert_eq!(ctx["ContentSize"], image.len() as u64);
        assert_eq!(ctx["SectionNames"][1], ".text");
        assert_eq!(ctx["SectionNames"].as_array().map(Vec::len), Some(9));
        assert!(ctx.get("ContentType").is_none());
        assert!(format!("{plugin:?}").contains("parsed: true"));

        // Without section names the array is omitted.
        let mut nonames = image;
        nonames[62..64].copy_from_slice(&0_u16.to_le_bytes());
        let mut win = window_for(&nonames, "n.elf");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("", "").expect("ctx");
        assert!(ctx.get("SectionNames").is_none());
    }

    #[test]
    fn colors_panels_and_constants() {
        let colors = ElfColors::default();
        assert_eq!(colors.header, attr(Color::Olive, Color::Transparent));
        assert_eq!(colors.pht, attr(Color::Magenta, Color::Transparent));
        assert_eq!(colors.sht, attr(Color::DarkRed, Color::Transparent));
        assert_eq!(colors.sht_content, attr(Color::Silver, Color::Transparent));
        let ops = OpcodeColors::default();
        assert_eq!(ops.call, attr(Color::White, Color::Silver));
        assert_eq!(ops.jump, attr(Color::Yellow, Color::DarkRed));
        assert_eq!(ops.breakpoint, attr(Color::Green, Color::DarkBlue));
        assert_eq!(ops.function_start, attr(Color::Yellow, Color::Olive));
        assert_eq!(ops.function_end, attr(Color::Black, Color::Olive));
        assert_eq!(ops.exe_marker, attr(Color::Yellow, Color::DarkRed));
        assert_eq!(PANEL_ORDER.len(), 9);
        assert_eq!(Panel::GoFiles.caption(), "Go&Modules");
        assert_eq!(Panel::GoFiles.gate(), PanelId::GoInformation);
        assert_eq!(Panel::OpCodes.panel_id(), "elf.opcodes");
        assert_eq!(Panel::DynamicSymbols.gate(), PanelId::DynamicSymbols);
        assert_eq!(opcodes::HEADER | opcodes::CALL | opcodes::JMP, 11);
        assert_eq!(opcodes::BREAKPOINT + opcodes::FUNCTION_START + opcodes::FUNCTION_END, 224);
        assert_eq!(TRANSLATION_METHODS, ["VA"]);
    }
}
