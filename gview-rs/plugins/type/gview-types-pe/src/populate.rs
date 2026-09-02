//! The PE type plugin: `PopulateWindow` and the `TypeInterface`
//! methods.
//!
//! Spec `06_TYPE_PLUGINS` §PE `PopulateWindow` / `SmartAssistant`; C++
//! `pe.cpp` `CreateBufferView` / `CreateDissasmView` /
//! `PopulateWindow`, `PEFile.cpp` `GetMachine`, `GetSubsystem`,
//! `GetSmartAssistantContext`, panel mask.
//!
//! `PopulateWindow` (`pe.cpp:261-333`), in order:
//!
//! 1. `pe->Update()` — [`PeFile::parse_cache`] over the window object;
//! 2. buffer viewer (`CreateBufferView`): zones for the DOS header,
//!    NT header, section table (`SectDef`), every section with raw
//!    data (bookmarks 1..=9 on the first nine), the data directories
//!    (`Security` is a file offset, the others are RVAs), the COFF
//!    symbol and string tables; bookmark 0 on the overlay; the
//!    `RVA` / `VA` translation list; the dissasm defaults per machine;
//!    opcode colouring for I386 / IA64 / AMD64; F7 at the entry point;
//! 3. dissasm viewer (`CreateDissasmView`): the `.text` section as a
//!    code zone starting at the entry point (x86 / x64 by PE32+), the
//!    same translation list, the `ImageDOSHeader` type at offset 0,
//!    and import memory mappings (empty until the import parser
//!    lands);
//! 4. panels gated by the panel mask (`HasPanel`): Information,
//!    Headers, Sections (bottom), Directories, then the optional ones
//!    (Imports / Exports / Resources / Icons / Symbols / Go / `OpCodes`).
//!
//! The analysis-engine facts (`InitPePredicates`, `IsPe`,
//! `HasOverlayData`, static heuristics) belong to the HDF tasks; the
//! HDF-dependent side effects are skipped here without changing the
//! window layout.

use std::sync::{Mutex, PoisonError};

use appcui::graphics::{CharAttribute, CharFlags, Color};
use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::zones::ZonesList;
use gview_disasm::{Architecture, Design, Endianess};
use gview_plugin::type_plugin::{
    BufferViewerRequest, CommandDef, DissasmViewerRequest, KeyRegistry, PanelRequest, Pattern,
    PluginError, PluginMetadata, TypePlugin, ViewerRequest, WindowHandle,
};
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::dissasm_viewer::zone::{DisassemblyLanguage, DisassemblyZone};
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::header::{DirectoryType, PeError, PeFile, INSPECTED_DIRECTORIES, PE_INVALID_ADDRESS};
use crate::validate::{validate, IMAGE_DOS_HEADER_SIZE, IMAGE_NT_HEADERS32_SIZE, IMAGE_SECTION_HEADER_SIZE};

/// C++ `OVERLAY_BOOKMARK_VALUE`.
pub const OVERLAY_BOOKMARK_VALUE: u8 = 0;
/// `PE::IMAGE_SIZEOF_SYMBOL`.
pub const IMAGE_SIZEOF_SYMBOL: u64 = 18;
/// Sections that get a bookmark (`tr < 9` → slots 1..=9).
pub const BOOKMARKED_SECTIONS: usize = 9;
/// `PE_COMMAND_DIGITAL_SIGNATURE`.
pub const CMD_DIGITAL_SIGNATURE: u32 = 0;
/// `PE_COMMAND_AREA_HIGHLIGHTER`.
pub const CMD_AREA_HIGHLIGHTER: u32 = 1;
/// The `ImageDOSHeader` structure definition registered with the
/// dissasm viewer (`settings.AddType`, `pe.cpp`).
pub const IMAGE_DOS_HEADER_TYPE: &str = "UInt16 e_magic;\nUInt16 e_cblp;\nUInt16 e_cp;\nUInt16 e_crlc;\nUInt16 e_res[4];";

/// C++ `MachineType` values the plugin switches on.
pub mod machine {
    /// `I386`.
    pub const I386: u16 = 0x014C;
    /// `ARM`.
    pub const ARM: u16 = 0x01C0;
    /// `THUMB`.
    pub const THUMB: u16 = 0x01C2;
    /// `ARMNT`.
    pub const ARMNT: u16 = 0x01C4;
    /// `IA64`.
    pub const IA64: u16 = 0x0200;
    /// `AMD64`.
    pub const AMD64: u16 = 0x8664;
    /// `ARM64`.
    pub const ARM64: u16 = 0xAA64;
}

/// C++ `Panels::IDs` (bit positions of `panelsMask`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PanelId {
    /// `Information`.
    Information = 0,
    /// `Directories`.
    Directories = 1,
    /// `Exports`.
    Exports = 2,
    /// `Sections`.
    Sections = 3,
    /// `Headers`.
    Headers = 4,
    /// `Resources`.
    Resources = 5,
    /// `Icons`.
    Icons = 6,
    /// `Imports`.
    Imports = 7,
    /// `TLS`.
    Tls = 8,
    /// `Symbols`.
    Symbols = 9,
    /// `GoInformation`.
    GoInformation = 10,
    /// `OpCodes`.
    OpCodes = 11,
}

/// C++ `peCols`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PeColors {
    /// `colMZ` (Olive).
    pub mz: CharAttribute,
    /// `colPE` (Magenta).
    pub pe: CharAttribute,
    /// `colSectDef` (`DarkRed`).
    pub sect_def: CharAttribute,
    /// `colSect` (Silver).
    pub sect: CharAttribute,
    /// `colDir[15]`: Aqua, Red, Green…, Security = Teal.
    pub dir: [CharAttribute; INSPECTED_DIRECTORIES],
}

fn attr(fore: Color) -> CharAttribute {
    CharAttribute::new(fore, Color::Transparent, CharFlags::None)
}

impl Default for PeColors {
    fn default() -> Self {
        let mut dir = [attr(Color::Green); INSPECTED_DIRECTORIES];
        if let Some(first) = dir.first_mut() {
            *first = attr(Color::Aqua);
        }
        if let Some(second) = dir.get_mut(1) {
            *second = attr(Color::Red);
        }
        if let Some(security) = dir.get_mut(DirectoryType::Security as usize) {
            *security = attr(Color::Teal);
        }
        Self {
            mz: attr(Color::Olive),
            pe: attr(Color::Magenta),
            sect_def: attr(Color::DarkRed),
            sect: attr(Color::Silver),
            dir,
        }
    }
}

/// C++ `GetMachine`.
#[must_use]
pub const fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x0184 => "ALPHA",
        0x0284 => "ALPHA 64",
        0x01D3 => "AM 33",
        machine::AMD64 => "AMD 64",
        machine::ARM => "ARM",
        machine::ARM64 => "ARM64",
        0xC0EE => "CEE",
        0x0CEF => "CEF",
        0x0EBC => "EBC",
        machine::I386 => "Intel 386",
        machine::IA64 => "Intel IA64",
        0x9041 => "M 32R",
        0x0466 => "MIP SFPU 16",
        0x0266 => "MIP 16",
        0x0366 => "MIP SFPU",
        0x01F0 => "POWER PC",
        0x01F1 => "POWER PC (FP)",
        0x01F2 => "Xbox 360 (Xenon)",
        0x0168 => "R 10000",
        0x0162 => "R 3000",
        0x0166 => "MIPS@ little indian",
        0x01A2 => "Hitachi SH3",
        0x01A3 => "Hitachi SH3 (DSP)",
        0x01A4 => "Hitachi SH2 (E)",
        0x01A6 => "Hitachi SH4",
        0x01A8 => "Hitachi SH5",
        machine::THUMB => "Thumb",
        0x0520 => "Tricore",
        0 => "Unknown",
        0x0169 => "WCEMIPSV2",
        machine::ARMNT => "ARM Thumb-2",
        _ => "",
    }
}

/// C++ `GetSubsystem`.
#[must_use]
pub const fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native",
        2 => "Windows GUI (Graphics)",
        3 => "Windows CUI (Console)",
        9 => "Windows CE GUI (Graphics)",
        7 => "Posix CUI (Console)",
        10 => "EFI Applications",
        11 => "Boot Service Driver",
        12 => "EFI routine driver",
        13 => "EFI Rom",
        8 => "Native Windows",
        5 => "OS2 CUI (Console)",
        14 => "XBOX",
        _ => "",
    }
}

/// Dissasm dialog defaults per machine (`CreateBufferView` switch).
#[must_use]
pub const fn dissasm_settings_for(machine: u16) -> DissasmSettings {
    match machine {
        machine::I386 => DissasmSettings {
            design: Design::Intel,
            architecture: Architecture::X86,
            endianess: Endianess::Little,
        },
        machine::IA64 | machine::AMD64 => DissasmSettings {
            design: Design::Intel,
            architecture: Architecture::X64,
            endianess: Endianess::Little,
        },
        machine::ARM | machine::ARMNT => DissasmSettings {
            design: Design::Arm,
            architecture: Architecture::X86,
            endianess: Endianess::Little,
        },
        machine::ARM64 => DissasmSettings {
            design: Design::Arm,
            architecture: Architecture::X64,
            endianess: Endianess::Little,
        },
        _ => DissasmSettings {
            design: Design::Invalid,
            architecture: Architecture::Invalid,
            endianess: Endianess::Invalid,
        },
    }
}

/// `SetPositionToColorCallback` applies to I386 / IA64 / AMD64.
#[must_use]
pub const fn colors_opcodes(machine: u16) -> bool {
    matches!(machine, machine::I386 | machine::IA64 | machine::AMD64)
}

/// C++ panel mask after `Update()`: the four defaults, `OpCodes` for
/// Intel machines, Symbols when a COFF symbol table is present. The
/// import / export / resource / TLS / Go panels need their parsers.
#[must_use]
pub fn panel_mask(pe: &PeFile) -> u64 {
    let mut mask = 0_u64;
    for id in [PanelId::Information, PanelId::Directories, PanelId::Sections, PanelId::Headers] {
        mask |= 1_u64 << (id as u8);
    }
    if colors_opcodes(pe.file_header.machine) {
        mask |= 1_u64 << (PanelId::OpCodes as u8);
    }
    if pe.file_header.pointer_to_symbol_table != 0 && pe.file_header.number_of_symbols != 0 {
        mask |= 1_u64 << (PanelId::Symbols as u8);
    }
    mask
}

/// C++ `HasPanel`.
#[must_use]
pub const fn has_panel(mask: u64, id: PanelId) -> bool {
    mask & (1_u64 << (id as u8)) != 0
}

/// The `BufferViewer::Settings` of `CreateBufferView` (`pe.cpp:36-116`).
/// `strings_table_size` is the `u32` the C++ reads at the strings
/// table offset (`obj->GetData().Copy`), when readable.
#[must_use]
pub fn buffer_view_request(pe: &PeFile, colors: &PeColors, strings_table_size: Option<u32>) -> BufferViewerRequest {
    let mut zones = ZonesList::new();
    zones.add_sized(0, IMAGE_DOS_HEADER_SIZE as u64, colors.mz, "DOS Header");
    zones.add_sized(pe.pe_start, IMAGE_NT_HEADERS32_SIZE as u64, colors.pe, "NT Header");
    let mut bookmarks = Vec::new();
    if !pe.sections.is_empty() {
        zones.add_sized(
            pe.section_table_offset,
            (pe.sections.len() as u64).saturating_mul(IMAGE_SECTION_HEADER_SIZE as u64),
            colors.sect_def,
            "SectDef",
        );
    }
    if pe.has_overlay {
        bookmarks.push((OVERLAY_BOOKMARK_VALUE, pe.computed_size));
    }
    for (index, section) in pe.sections.iter().enumerate() {
        if section.pointer_to_raw_data != 0 && section.size_of_raw_data > 0 {
            zones.add_sized(
                u64::from(section.pointer_to_raw_data),
                u64::from(section.size_of_raw_data),
                colors.sect,
                section.name_str(),
            );
            if index < BOOKMARKED_SECTIONS {
                bookmarks.push((index.saturating_add(1) as u8, u64::from(section.pointer_to_raw_data)));
            }
        }
    }
    for (index, dir) in pe.optional.data_directory.iter().take(INSPECTED_DIRECTORIES).enumerate() {
        if dir.virtual_address == 0 || dir.size == 0 {
            continue;
        }
        let color = colors.dir.get(index).copied().unwrap_or(colors.sect);
        let name = DirectoryType::name(index as u32);
        if index == DirectoryType::Security as usize {
            zones.add_sized(u64::from(dir.virtual_address), u64::from(dir.size), color, name);
        } else {
            let fa = pe.rva_to_fa(u64::from(dir.virtual_address));
            if fa != PE_INVALID_ADDRESS {
                zones.add_sized(fa, u64::from(dir.size), color, name);
            }
        }
    }
    let symbol_table = u64::from(pe.file_header.pointer_to_symbol_table);
    if symbol_table > 0 {
        let symbols_size = u64::from(pe.file_header.number_of_symbols).saturating_mul(IMAGE_SIZEOF_SYMBOL);
        zones.add_sized(symbol_table, symbols_size, colors.sect_def, "SymbolTable");
        let strings_offset = symbol_table.saturating_add(symbols_size);
        zones.add_sized(
            strings_offset,
            u64::from(strings_table_size.unwrap_or(0)),
            colors.pe,
            "StringsTable",
        );
    }
    let entry = pe.rva_to_fa(u64::from(pe.entry_point_rva));
    BufferViewerRequest {
        zones,
        bookmarks,
        entry_point: (entry != PE_INVALID_ADDRESS).then_some(entry),
        translation_methods: vec![String::from("RVA"), String::from("VA")],
        dissasm_settings: dissasm_settings_for(pe.file_header.machine),
        position_to_color: colors_opcodes(pe.file_header.machine),
    }
}

/// The `DissasmViewer::Settings` of `CreateDissasmView`
/// (`pe.cpp:117-160`): the `.text` zone (when the Sections panel is
/// on), translation list, `ImageDOSHeader` type and variable.
#[must_use]
pub fn dissasm_view_request(pe: &PeFile, mask: u64) -> DissasmViewerRequest {
    let mut request = DissasmViewerRequest {
        translation_methods: vec![String::from("RVA"), String::from("VA")],
        types: vec![(String::from("ImageDOSHeader"), String::from(IMAGE_DOS_HEADER_TYPE))],
        variables: vec![(0, String::from("ImageDOSHeader"))],
        ..DissasmViewerRequest::default()
    };
    if has_panel(mask, PanelId::Sections) {
        if let Some(text) = pe.sections.iter().find(|s| s.name_str() == ".text") {
            let entry = pe.rva_to_fa(u64::from(pe.entry_point_rva));
            request.zones.push(DisassemblyZone {
                starting_zone_point: u64::from(text.pointer_to_raw_data),
                size: u64::from(text.size_of_raw_data),
                entry_point: entry,
                language: if pe.is_pe64 {
                    DisassemblyLanguage::X64
                } else {
                    DisassemblyLanguage::X86
                },
            });
        }
    }
    request
}

/// Panels added by `PopulateWindow`, in C++ order: `(id, vertical)`.
pub const PANEL_ORDER: [(PanelId, bool); 9] = [
    (PanelId::Information, true),
    (PanelId::Headers, true),
    (PanelId::Sections, false),
    (PanelId::Directories, true),
    (PanelId::Imports, true),
    (PanelId::Exports, true),
    (PanelId::Resources, false),
    (PanelId::Icons, true),
    (PanelId::Symbols, false),
];

impl PanelId {
    /// Tab caption of the C++ panel class.
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::Information => "&Information",
            Self::Directories => "&Directories",
            Self::Exports => "&Exports",
            Self::Sections => "&Sections",
            Self::Headers => "&Headers",
            Self::Resources => "&Resources",
            Self::Icons => "Ic&ons",
            Self::Imports => "Im&ports",
            Self::Tls => "&TLS",
            Self::Symbols => "S&ymbols",
            Self::GoInformation => "&Go",
            Self::OpCodes => "Op&Codes",
        }
    }

    /// Stable panel identifier for the shell.
    #[must_use]
    pub const fn panel_id(self) -> &'static str {
        match self {
            Self::Information => "pe.information",
            Self::Directories => "pe.directories",
            Self::Exports => "pe.exports",
            Self::Sections => "pe.sections",
            Self::Headers => "pe.headers",
            Self::Resources => "pe.resources",
            Self::Icons => "pe.icons",
            Self::Imports => "pe.imports",
            Self::Tls => "pe.tls",
            Self::Symbols => "pe.symbols",
            Self::GoInformation => "pe.go",
            Self::OpCodes => "pe.opcodes",
        }
    }
}

/// The PE `TypeInterface` (C++ `PE::PEFile` as a type instance).
pub struct PePlugin {
    colors: PeColors,
    state: Mutex<Option<PeFile>>,
    object: Mutex<Option<SharedObject>>,
    last_command: Mutex<Option<String>>,
}

impl Default for PePlugin {
    fn default() -> Self {
        Self {
            colors: PeColors::default(),
            state: Mutex::new(None),
            object: Mutex::new(None),
            last_command: Mutex::new(None),
        }
    }
}

impl core::fmt::Debug for PePlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let parsed = self.state.lock().is_ok_and(|s| s.is_some());
        f.debug_struct("PePlugin").field("parsed", &parsed).finish_non_exhaustive()
    }
}

impl PePlugin {
    /// The parsed headers after `PopulateWindow`.
    #[must_use]
    pub fn file(&self) -> Option<PeFile> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The last `RunCommand` name.
    #[must_use]
    pub fn last_command(&self) -> Option<String> {
        self.last_command.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// C++ `PE_COMMANDS`.
    #[must_use]
    pub fn commands() -> Vec<CommandDef> {
        vec![
            CommandDef::new(
                "DigitalSignature",
                Key::new(KeyCode::F8, KeyModifier::Alt),
                "Validate digital signature",
                CMD_DIGITAL_SIGNATURE,
            ),
            CommandDef::new(
                "AreaHighlighter",
                Key::new(KeyCode::F9, KeyModifier::Alt),
                "Highlight portions of code base on an input file",
                CMD_AREA_HIGHLIGHTER,
            ),
        ]
    }
}

impl TypePlugin for PePlugin {
    fn name(&self) -> &'static str {
        "PE"
    }

    fn validate(buf: &[u8], extension: &str) -> bool {
        validate(buf, extension)
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// C++ `UpdateSettings` (`pe.cpp:334-346`).
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: vec![Pattern::Magic(vec![0x4D, 0x5A])],
            priority: 1,
            description: String::from("Portable executable format for Windows OS binaries"),
            extensions: Vec::new(),
            commands: Self::commands(),
            opcodes_mask: Some(0xFFFF_FFFF),
        }
    }

    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        let (pe, strings_table_size) = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            let pe = PeFile::parse_cache(guard.data_mut()).map_err(|e: PeError| PluginError::Window(e.to_string()))?;
            let strings = if pe.file_header.pointer_to_symbol_table > 0 {
                let offset = u64::from(pe.file_header.pointer_to_symbol_table)
                    .saturating_add(u64::from(pe.file_header.number_of_symbols).saturating_mul(IMAGE_SIZEOF_SYMBOL));
                guard.data_mut().copy_object::<u32>(offset).ok()
            } else {
                None
            };
            (pe, strings)
        };
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));
        let mask = panel_mask(&pe);

        win.create_viewer(ViewerRequest::buffer(buffer_view_request(&pe, &self.colors, strings_table_size)))?;
        win.create_viewer(ViewerRequest::dissasm(dissasm_view_request(&pe, mask)))?;
        for (id, vertical) in PANEL_ORDER {
            if has_panel(mask, id) {
                win.add_panel(
                    PanelRequest {
                        caption: String::from(id.caption()),
                        panel_id: String::from(id.panel_id()),
                    },
                    vertical,
                );
            }
        }
        if has_panel(mask, PanelId::OpCodes) {
            win.add_panel(
                PanelRequest {
                    caption: String::from(PanelId::OpCodes.caption()),
                    panel_id: String::from(PanelId::OpCodes.panel_id()),
                },
                true,
            );
        }
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some(pe);
        Ok(())
    }

    fn run_command(&mut self, command: &str) {
        *self.last_command.lock().unwrap_or_else(PoisonError::into_inner) = Some(command.to_owned());
    }

    fn register_keys(&self, keys: &mut dyn KeyRegistry) {
        for command in Self::commands() {
            keys.register_key(&command);
        }
    }

    /// C++ `GetSmartAssistantContext` (`PEFile.cpp:769-805`); the
    /// `Exports` / `Imports` / `Resources` arrays appear once those
    /// tables are parsed.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        let pe = self
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
        Ok(serde_json::json!({
            "Name": name,
            "ContentType": "PE",
            "ContentSize": size,
            "Image Base": pe.image_base,
            "Machine": machine_name(pe.file_header.machine),
            "Subsystem": subsystem_name(pe.optional.subsystem),
            "Number Sections": pe.section_count(),
        }))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::header::tests::{build_image, Sect};
    use crate::header::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};
    use gview_core::object::Object;
    use gview_plugin::type_plugin::ViewerKind;
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

    const TEXT: Sect = Sect {
        name: b".text",
        va: 0x1000,
        vsize: 0x800,
        raw: 0x400,
        rawsize: 0x800,
        chars: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    };
    const DATA: Sect = Sect {
        name: b".data",
        va: 0x2000,
        vsize: 0x300,
        raw: 0xC00,
        rawsize: 0x400,
        chars: IMAGE_SCN_MEM_READ,
    };

    fn window_for(image: &[u8], name: &str) -> MockWindow {
        MockWindow {
            object: Some(Arc::new(StdMutex::new(Object::from_buffer(image, name, 0)))),
            ..MockWindow::default()
        }
    }

    #[test]
    fn populate_creates_buffer_and_dissasm_views_with_zones() {
        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0x20);
        let plugin = PePlugin::create_instance();
        let mut win = window_for(&image, "app.exe");
        plugin.populate_window(&mut win).expect("populate");

        assert_eq!(win.viewers.len(), 2);
        assert_eq!(win.viewers[0].kind, ViewerKind::Buffer);
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer settings");
        // DOS, NT, SectDef, .text, .data.
        assert_eq!(buffer.zones.count(), 5);
        let names: Vec<String> = (0..buffer.zones.count())
            .filter_map(|i| buffer.zones.zone(i).map(|z| z.name.clone()))
            .collect();
        assert_eq!(names, ["DOS Header", "NT Header", "SectDef", ".text", ".data"]);
        assert_eq!(buffer.zones.zone(1).map(|z| z.low), Some(0x80));
        assert_eq!(buffer.entry_point, Some(0x410));
        assert_eq!(buffer.translation_methods, ["RVA", "VA"]);
        assert_eq!(buffer.dissasm_settings.architecture, Architecture::X86);
        assert_eq!(buffer.dissasm_settings.design, Design::Intel);
        assert!(buffer.position_to_color);
        // Overlay bookmark 0, sections 1 and 2.
        assert_eq!(buffer.bookmarks, [(0, 0x1000), (1, 0x400), (2, 0xC00)]);

        assert_eq!(win.viewers[1].kind, ViewerKind::Dissasm);
        let dissasm = win.viewers[1].dissasm.as_ref().expect("dissasm settings");
        assert_eq!(dissasm.zones.len(), 1);
        assert_eq!(dissasm.zones[0].starting_zone_point, 0x400);
        assert_eq!(dissasm.zones[0].size, 0x800);
        assert_eq!(dissasm.zones[0].entry_point, 0x410);
        assert_eq!(dissasm.zones[0].language, DisassemblyLanguage::X86);
        assert_eq!(dissasm.translation_methods, ["RVA", "VA"]);
        assert_eq!(dissasm.types[0].0, "ImageDOSHeader");
        assert_eq!(dissasm.variables, [(0, String::from("ImageDOSHeader"))]);

        // Default panels + OpCodes (I386): Information, Headers,
        // Sections(bottom), Directories, OpCodes.
        assert_eq!(
            win.panels,
            [
                (String::from("&Information"), true),
                (String::from("&Headers"), true),
                (String::from("&Sections"), false),
                (String::from("&Directories"), true),
                (String::from("Op&Codes"), true),
            ]
        );
        let pe = plugin.file().expect("parsed");
        assert!(pe.has_overlay);
        assert_eq!(pe.overlay_size, 0x20);
    }

    #[test]
    fn pe64_uses_x64_language_and_arm_has_no_opcode_panel() {
        let image = build_image(true, 0x1_4000_0000, 0x1000, &[TEXT], 0);
        let plugin = PePlugin::create_instance();
        let mut win = window_for(&image, "app64.exe");
        plugin.populate_window(&mut win).expect("populate");
        let dissasm = win.viewers[1].dissasm.as_ref().expect("dissasm");
        assert_eq!(dissasm.zones[0].language, DisassemblyLanguage::X64);
        // Machine still I386 in the fixture: dissasm defaults x86.
        assert_eq!(win.viewers[0].buffer.as_ref().map(|b| b.dissasm_settings.architecture), Some(Architecture::X86));

        // ARM machine: no OpCodes panel, ARM dissasm defaults.
        let mut image = build_image(false, 0x40_0000, 0x1010, &[TEXT], 0);
        image[0x84..0x86].copy_from_slice(&machine::ARM64.to_le_bytes());
        let mut win = window_for(&image, "arm.exe");
        plugin.populate_window(&mut win).expect("populate");
        assert!(!win.panels.iter().any(|(c, _)| c == "Op&Codes"));
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        assert_eq!(buffer.dissasm_settings.design, Design::Arm);
        assert_eq!(buffer.dissasm_settings.architecture, Architecture::X64);
        assert!(!buffer.position_to_color);
        let mask = panel_mask(&plugin.file().expect("pe"));
        assert!(!has_panel(mask, PanelId::OpCodes));
        assert!(has_panel(mask, PanelId::Information));
    }

    #[test]
    fn directory_and_symbol_zones() {
        let mut image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0x200);
        let opt = 0x80 + 4 + 20;
        let dirs = opt + 96;
        // Export at RVA 0x2000 (→ FA 0xC00), Security at file offset 0x1000.
        image[dirs..dirs + 4].copy_from_slice(&0x2000_u32.to_le_bytes());
        image[dirs + 4..dirs + 8].copy_from_slice(&0x40_u32.to_le_bytes());
        let sec = dirs + 4 * 8;
        image[sec..sec + 4].copy_from_slice(&0x1000_u32.to_le_bytes());
        image[sec + 4..sec + 8].copy_from_slice(&0x100_u32.to_le_bytes());
        // Invalid RVA directory (below sections): skipped.
        image[dirs + 8..dirs + 12].copy_from_slice(&0x10_u32.to_le_bytes());
        image[dirs + 12..dirs + 16].copy_from_slice(&0x10_u32.to_le_bytes());
        // COFF symbol table: 2 symbols at 0x1100, strings size 0x30.
        let fh = 0x80 + 4;
        image[fh + 8..fh + 12].copy_from_slice(&0x1100_u32.to_le_bytes());
        image[fh + 12..fh + 16].copy_from_slice(&2_u32.to_le_bytes());
        let strings_at = 0x1100 + 2 * 18;
        image[strings_at..strings_at + 4].copy_from_slice(&0x30_u32.to_le_bytes());

        let plugin = PePlugin::create_instance();
        let mut win = window_for(&image, "sym.exe");
        plugin.populate_window(&mut win).expect("populate");
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        let zones: Vec<(String, u64, u64)> = (0..buffer.zones.count())
            .filter_map(|i| buffer.zones.zone(i).map(|z| (z.name.clone(), z.low, z.high)))
            .collect();
        assert!(zones.contains(&(String::from("Export"), 0xC00, 0xC00 + 0x40 - 1)));
        assert!(zones.contains(&(String::from("Security"), 0x1000, 0x1000 + 0x100 - 1)));
        assert!(!zones.iter().any(|(n, _, _)| n == "Import"));
        assert!(zones.contains(&(String::from("SymbolTable"), 0x1100, 0x1100 + 36 - 1)));
        assert!(zones.contains(&(String::from("StringsTable"), strings_at as u64, strings_at as u64 + 0x30 - 1)));
        assert!(win.panels.iter().any(|(c, v)| c == "S&ymbols" && !v));
    }

    #[test]
    fn metadata_commands_keys_and_assistant_context() {
        struct Keys(Vec<String>);
        impl KeyRegistry for Keys {
            fn register_key(&mut self, command: &CommandDef) -> bool {
                self.0.push(command.name.clone());
                true
            }
        }
        let meta = PePlugin::metadata();
        assert_eq!(meta.pattern, [Pattern::Magic(vec![0x4D, 0x5A])]);
        assert_eq!(meta.priority, 1);
        assert_eq!(meta.opcodes_mask, Some(0xFFFF_FFFF));
        assert_eq!(meta.commands.len(), 2);
        assert_eq!(meta.commands[0].name, "DigitalSignature");
        assert_eq!(meta.commands[1].key, Key::new(KeyCode::F9, KeyModifier::Alt));
        assert_eq!(PePlugin::validate(b"MZ", ".exe"), validate(b"MZ", ".exe"));

        let mut plugin = PePlugin::create_instance();
        assert_eq!(plugin.name(), "PE");
        assert!(plugin.smart_assistant_context("", "").is_err());
        plugin.run_command("AreaHighlighter");
        assert_eq!(plugin.last_command().as_deref(), Some("AreaHighlighter"));

        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert_eq!(keys.0, ["DigitalSignature", "AreaHighlighter"]);

        let image = build_image(false, 0x40_0000, 0x1010, &[TEXT, DATA], 0);
        let mut win = window_for(&image, "ctx.exe");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("what", "what").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.exe");
        assert_eq!(ctx["ContentType"], "PE");
        assert_eq!(ctx["ContentSize"], image.len() as u64);
        assert_eq!(ctx["Image Base"], 0x40_0000_u64);
        assert_eq!(ctx["Machine"], "Intel 386");
        assert_eq!(ctx["Subsystem"], "Unknown");
        assert_eq!(ctx["Number Sections"], 2);
        assert!(format!("{plugin:?}").contains("parsed: true"));
    }

    #[test]
    fn broken_headers_fail_populate_without_viewers() {
        let plugin = PePlugin::create_instance();
        let mut win = window_for(b"MZ\x90\x00", "tiny.exe");
        let err = plugin.populate_window(&mut win).expect_err("no NT headers");
        assert!(matches!(err, PluginError::Window(_)));
        assert!(win.viewers.is_empty());
        assert!(plugin.file().is_none());
    }

    #[test]
    fn name_tables_and_colors() {
        assert_eq!(machine_name(machine::AMD64), "AMD 64");
        assert_eq!(machine_name(0x0166), "MIPS@ little indian");
        assert_eq!(machine_name(0x1234), "");
        assert_eq!(subsystem_name(2), "Windows GUI (Graphics)");
        assert_eq!(subsystem_name(16), "");
        let colors = PeColors::default();
        assert_eq!(colors.dir[0], attr(Color::Aqua));
        assert_eq!(colors.dir[1], attr(Color::Red));
        assert_eq!(colors.dir[2], attr(Color::Green));
        assert_eq!(colors.dir[4], attr(Color::Teal));
        assert_eq!(colors.mz, attr(Color::Olive));
        assert_eq!(PanelId::Sections.caption(), "&Sections");
        assert_eq!(PANEL_ORDER.len(), 9);
        assert_eq!(OVERLAY_BOOKMARK_VALUE, 0);
        assert_eq!(IMAGE_SIZEOF_SYMBOL, 18);
    }
}
