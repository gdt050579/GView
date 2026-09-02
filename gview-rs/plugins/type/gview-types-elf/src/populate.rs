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
use gview_plugin::type_plugin::{
    BufferViewerRequest, KeyRegistry, PanelRequest, Pattern, PluginError, PluginMetadata, TypePlugin,
    ViewerRequest, WindowHandle,
};
use gview_view::buffer_viewer::color::{BufferColor, PositionToColorCallback};
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::parse::{is_intel_machine, ElfError, ElfFile, PanelId, ELF32_EHDR_SIZE, ELF64_EHDR_SIZE};
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
