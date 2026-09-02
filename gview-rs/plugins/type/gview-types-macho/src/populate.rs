//! The Mach-O type plugin: `PopulateWindow` and the `TypeInterface`
//! methods.
//!
//! Spec `06_TYPE_PLUGINS` §Mach-O `PopulateWindow` / `SmartAssistant`;
//! C++ `MachO.cpp` `CreateBufferView` / `CreateContainerView` /
//! `PopulateWindow` / `UpdateSettings`, `MachOFile.cpp`
//! `GetColorForBuffer` / `GetColorForBufferIntel` / `BeginIteration` /
//! `PopulateItem` / `OnOpenItem` / `UpdateKeys` / `RunCommand` /
//! `GetSmartAssistantContext`, `MachO.hpp` colours, panel ids and
//! `MACHO_COMMANDS`.
//!
//! `PopulateWindow` (`MachO.cpp:186-247`), in order:
//!
//! 1. `machO->Update()` — [`MachoFile::parse_cache`];
//! 2. fat archives get the container viewer first (`FAT_ICON`, the
//!    seven arch columns, the plugin as enumerate / open callbacks);
//! 3. the buffer viewer: for a thin file the `Header` zone, one
//!    `(#i)LC` zone per load command, every section (`offset`, or
//!    `addr` for `__bss`-style sections), the `LC_MAIN` entry point,
//!    `Symbol_Table` / `Symbol_Strings`, one `(#i)Link_Edit` zone per
//!    `linkedit_data_command`, and opcode colouring for i386 / x86-64;
//!    for a fat archive the 8-byte `Header` zone, then — replicating
//!    the C++ `offsetHeaders += sizeof(machO->header)` quirk — the
//!    `Arch #i` zones start at **byte 32** (the thin `mach_header`
//!    size, not the 8-byte fat header) and each member gets a
//!    `#i name` zone at its offset;
//! 4. panels gated by `HasPanel`: `Information` (right), then for thin
//!    files `LoadCommands` / `Segments` / `Sections` (bottom),
//!    `DyldInfo` (right), `Dylib` / `DySymTab` (bottom), the three Go
//!    panels, `OpCodes` (right).
//!
//! [`MachoOpcodeColorizer`] is `GetColorForBuffer`: for i386 / x86-64
//! with a non-zero `showOpcodesMask` it marks `MH_MAGIC` / `MH_CIGAM`
//! (first byte `FE` / `CE`, `Header` bit) and, inside executable
//! segments, the same Intel heuristics as the ELF plugin.
//!
//! `RunCommand("DigitalSignature")` records the command; the C++ code
//! signature walk (`SetCodeSignature`, CMS parsing, the
//! `CodeSignMagic` dialog) is not ported here.

use std::sync::{Mutex, PoisonError};

use appcui::graphics::{CharAttribute, CharFlags, Color};
use appcui::input::{Key, KeyCode, KeyModifier};
use gview_core::zones::ZonesList;
use gview_plugin::panel::{fmt, PanelContent};
use gview_plugin::type_plugin::{
    BufferViewerRequest, CommandDef, ContainerViewerRequest, KeyRegistry, PanelRequest, Pattern, PluginError,
    PluginMetadata, TypePlugin, ViewerRequest, WindowHandle,
};
use gview_view::buffer_viewer::color::{BufferColor, PositionToColorCallback};
use gview_view::buffer_viewer::dissasm_dialog::DissasmSettings;
use gview_view::container_viewer::tree::{EnumerateInterface, TreeItemId, TreeNode};
use gview_view::traits::SharedObject;
use serde_json::Value as JsonValue;

use crate::names;
use crate::parse::{
    arch_info, is_intel_cpu, Arch, MachoError, MachoFile, PanelId, FAT_HEADER_SIZE, MACH_HEADER_64_SIZE, MH_CIGAM,
    MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64,
};
use crate::validate::{validate, FAT_CIGAM, FAT_CIGAM_64, FAT_MAGIC, FAT_MAGIC_64};

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
pub const DESCRIPTION: &str = "Mach file executable object (Mach-O) for OSX based systems (including MachO Fat)";
/// `UpdateSettings` `Priority`.
pub const PRIORITY: u32 = 1;
/// `MACHO_COMMAND_DIGITAL_SIGNATURE`.
pub const CMD_DIGITAL_SIGNATURE: u32 = 0;
/// `FAT_ICON` (16×16, `MachO.cpp:14-29`).
pub const FAT_ICON: &str = concat!(
    "................",
    "................",
    "................",
    "................",
    "WWWW.WWWWW.WWWWW",
    "W....W...W...W..",
    "W....W...W...W..",
    "WWWW.WWWWW...W..",
    "W....W...W...W..",
    "W....W...W...W..",
    "W....W...W...W..",
    "................",
    "................",
    "................",
    "................",
    "................",
);
/// `CreateContainerView` columns.
pub const CONTAINER_COLUMNS: [&str; 7] = [
    "n:CPU type,a:r,w:25",
    "n:CPU subtype,a:r,w:25",
    "n:File type,w:80",
    "n:Offset,a:r,w:12",
    "n:Size,a:r,w:12",
    "n:Align,a:r,w:12",
    "n:Real Align,a:r,w:12",
];
/// The magics `UpdateSettings` emits, in order (thin then fat).
pub const PATTERN_MAGICS: [u32; 8] = [
    MH_MAGIC,
    MH_CIGAM,
    MH_MAGIC_64,
    MH_CIGAM_64,
    FAT_MAGIC,
    FAT_CIGAM,
    FAT_MAGIC_64,
    FAT_CIGAM_64,
];

/// `MAC::FileTypeNames` (`GET_PAIR_FROM_ENUM`).
#[must_use]
pub const fn file_type_name(filetype: u32) -> &'static str {
    match filetype {
        0x1 => "OBJECT",
        0x2 => "EXECUTE",
        0x3 => "FVMLIB",
        0x4 => "CORE",
        0x5 => "PRELOAD",
        0x6 => "DYLIB",
        0x8 => "BUNDLE",
        0x9 => "DYLIB_STUB",
        0xA => "DSYM",
        0xB => "KEXT_BUNDLE",
        _ => "",
    }
}

/// `MAC::FileTypeDescriptions`.
#[must_use]
pub const fn file_type_description(filetype: u32) -> &'static str {
    match filetype {
        0x1 => "Relocatable object file.",
        0x2 => "Demand paged executable file.",
        0x3 => "Fixed VM shared library file.",
        0x4 => "Core file.",
        0x5 => "Preloaded executable file.",
        0x6 => "Dynamically bound shared library.",
        0x8 => "Dynamically bound bundle file.",
        0x9 => "Shared library stub for static | linking only, no section contents.",
        0xA => "Companion file with only debug | sections.",
        0xB => "X86_64 kexts.",
        _ => "",
    }
}

fn attr(fore: Color, back: Color) -> CharAttribute {
    CharAttribute::new(fore, back, CharFlags::None)
}

/// `MachOFile::Colors`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MachoColors {
    /// `header` (Olive).
    pub header: CharAttribute,
    /// `loadCommand` (Magenta).
    pub load_command: CharAttribute,
    /// `section` (Silver).
    pub section: CharAttribute,
    /// `linkEdit` (Teal).
    pub link_edit: CharAttribute,
    /// `arch` (Magenta).
    pub arch: CharAttribute,
    /// `objectName` (`DarkRed`).
    pub object_name: CharAttribute,
    /// `object` (Silver).
    pub object: CharAttribute,
}

impl Default for MachoColors {
    fn default() -> Self {
        Self {
            header: attr(Color::Olive, Color::Transparent),
            load_command: attr(Color::Magenta, Color::Transparent),
            section: attr(Color::Silver, Color::Transparent),
            link_edit: attr(Color::Teal, Color::Transparent),
            arch: attr(Color::Magenta, Color::Transparent),
            object_name: attr(Color::DarkRed, Color::Transparent),
            object: attr(Color::Silver, Color::Transparent),
        }
    }
}

/// `MachO.hpp` opcode colours.
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
    /// `Panels::LoadCommands`.
    LoadCommands,
    /// `Panels::Segments`.
    Segments,
    /// `Panels::Sections`.
    Sections,
    /// `Panels::DyldInfo`.
    DyldInfo,
    /// `Panels::Dylib`.
    Dylib,
    /// `Panels::SymTab`.
    SymTab,
    /// `Panels::GoInformation`.
    GoInformation,
    /// `Panels::GoFiles`.
    GoFiles,
    /// `Panels::GoFunctions`.
    GoFunctions,
    /// `Panels::OpCodes`.
    OpCodes,
}

impl Panel {
    /// Tab caption of the C++ panel class (the `Informa&Tion` casing
    /// is the C++ one).
    #[must_use]
    pub const fn caption(self) -> &'static str {
        match self {
            Self::Information => "Informa&Tion",
            Self::LoadCommands => "Co&mmands",
            Self::Segments => "Se&gments",
            Self::Sections => "&Sections",
            Self::DyldInfo => "&DyldInfo",
            Self::Dylib => "D&ylibs",
            Self::SymTab => "SymTa&b",
            Self::GoInformation => "GoInfo&rmation",
            Self::GoFiles => "Go&Modules",
            Self::GoFunctions => "G&oFunctions",
            Self::OpCodes => "Op&Codes",
        }
    }

    /// Stable panel identifier for the shell.
    #[must_use]
    pub const fn panel_id(self) -> &'static str {
        match self {
            Self::Information => "macho.information",
            Self::LoadCommands => "macho.load_commands",
            Self::Segments => "macho.segments",
            Self::Sections => "macho.sections",
            Self::DyldInfo => "macho.dyld_info",
            Self::Dylib => "macho.dylibs",
            Self::SymTab => "macho.symtab",
            Self::GoInformation => "macho.go.information",
            Self::GoFiles => "macho.go.files",
            Self::GoFunctions => "macho.go.functions",
            Self::OpCodes => "macho.opcodes",
        }
    }

    /// The `HasPanel` bit that gates this panel.
    #[must_use]
    pub const fn gate(self) -> PanelId {
        match self {
            Self::Information => PanelId::Information,
            Self::LoadCommands => PanelId::LoadCommands,
            Self::Segments => PanelId::Segments,
            Self::Sections => PanelId::Sections,
            Self::DyldInfo => PanelId::DyldInfo,
            Self::Dylib => PanelId::Dylib,
            Self::SymTab => PanelId::DySymTab,
            Self::GoInformation | Self::GoFiles | Self::GoFunctions => PanelId::GoInformation,
            Self::OpCodes => PanelId::OpCodes,
        }
    }
}

/// Panels added only for thin files (`if (machO->isMacho)`), in C++
/// order: `(panel, vertical)`. `Information` precedes them for every
/// file.
pub const THIN_PANEL_ORDER: [(Panel, bool); 10] = [
    (Panel::LoadCommands, false),
    (Panel::Segments, false),
    (Panel::Sections, false),
    (Panel::DyldInfo, true),
    (Panel::Dylib, false),
    (Panel::SymTab, false),
    (Panel::GoInformation, true),
    (Panel::GoFiles, true),
    (Panel::GoFunctions, false),
    (Panel::OpCodes, true),
];

/// The `BufferViewer::Settings` of `CreateBufferView` (`MachO.cpp:61-166`).
#[must_use]
pub fn buffer_view_request(macho: &MachoFile, colors: &MachoColors) -> BufferViewerRequest {
    let mut zones = ZonesList::new();
    let mut entry_point = None;
    let mut position_to_color = false;
    if macho.is_macho {
        zones.add_sized(0, macho.header_size(), colors.header, "Header");
        for (i, lc) in macho.load_commands.iter().enumerate() {
            zones.add_sized(lc.offset, u64::from(lc.cmdsize), colors.load_command, format!("(#{i})LC"));
        }
        for section in macho.segments.iter().flat_map(|s| s.sections.iter()) {
            zones.add_sized(section.zone_start(), section.size, colors.section, section.sectname.as_str());
        }
        if let Some(main) = macho.main {
            entry_point = Some(main.entryoff);
        }
        if let Some(symtab) = &macho.symtab {
            let sc = symtab.command;
            zones.add_sized(
                u64::from(sc.symoff),
                u64::from(sc.nsyms).saturating_mul(macho.nlist_size()),
                colors.section,
                "Symbol_Table",
            );
            zones.add_sized(u64::from(sc.stroff), u64::from(sc.strsize), colors.section, "Symbol_Strings");
        }
        for (i, le) in macho.linkedit_datas.iter().enumerate() {
            zones.add_sized(
                u64::from(le.dataoff),
                u64::from(le.datasize),
                colors.link_edit,
                format!("(#{i})Link_Edit"),
            );
        }
        position_to_color = is_intel_cpu(macho.header.cputype);
    } else if macho.is_fat {
        zones.add_sized(0, FAT_HEADER_SIZE as u64, colors.header, "Header");
        // C++ quirk: `offsetHeaders += sizeof(machO->header)` — the thin
        // mach_header size, not the fat header's.
        let mut offset_headers = MACH_HEADER_64_SIZE as u64;
        let struct_size = macho.fat_arch_size();
        for (i, arch) in macho.archs.iter().enumerate() {
            zones.add_sized(offset_headers, struct_size, colors.arch, format!("Arch #{i}"));
            offset_headers = offset_headers.saturating_add(struct_size);
            zones.add_sized(arch.offset, arch.size, colors.object, format!("#{i} {}", arch.info.name));
        }
    }
    BufferViewerRequest {
        zones,
        bookmarks: Vec::new(),
        entry_point,
        translation_methods: Vec::new(),
        dissasm_settings: DissasmSettings::default(),
        position_to_color,
    }
}

/// The `ContainerViewer::Settings` of `CreateContainerView`
/// (`MachO.cpp:168-184`).
#[must_use]
pub fn container_view_request() -> ContainerViewerRequest {
    ContainerViewerRequest {
        icon: Some(String::from(FAT_ICON)),
        columns: CONTAINER_COLUMNS.iter().map(|c| (*c).to_owned()).collect(),
        ..ContainerViewerRequest::default()
    }
}

/// C++ `MachOFile::GetColorForBuffer` state.
#[derive(Clone, Debug, PartialEq)]
pub struct MachoOpcodeColorizer {
    /// `header.cputype`.
    pub cputype: i32,
    /// `executableZonesFAs`.
    pub executable_zones: Vec<(u64, u64)>,
    /// `showOpcodesMask` (0 until the `OpCodes` panel reads
    /// `Type.Mach-O` / `OpCodes.Mask`).
    pub show_opcodes_mask: u32,
    /// Colours.
    pub colors: OpcodeColors,
}

impl MachoOpcodeColorizer {
    /// Colorizer for a parsed file with the given mask.
    #[must_use]
    pub fn new(macho: &MachoFile, show_opcodes_mask: u32) -> Self {
        Self {
            cputype: macho.header.cputype,
            executable_zones: macho.executable_zones.clone(),
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

impl PositionToColorCallback for MachoOpcodeColorizer {
    /// C++ `GetColorForBuffer`: Intel CPUs only.
    fn color_for_buffer(&mut self, offset: u64, buf: &[u8]) -> Option<BufferColor> {
        let first = *buf.first()?;
        if self.show_opcodes_mask == 0 || !is_intel_cpu(self.cputype) {
            return None;
        }
        if (first == 0xFE || first == 0xCE) && self.show_opcodes_mask & opcodes::HEADER == opcodes::HEADER {
            if let Some(head) = buf.get(..4) {
                let magic = u32::from_le_bytes([
                    head.first().copied().unwrap_or(0),
                    head.get(1).copied().unwrap_or(0),
                    head.get(2).copied().unwrap_or(0),
                    head.get(3).copied().unwrap_or(0),
                ]);
                if magic == MH_MAGIC || magic == MH_CIGAM {
                    return Some(BufferColor {
                        start: offset,
                        end: offset.wrapping_add(3),
                        color: self.colors.exe_marker,
                    });
                }
            }
            // "do not break": fall through to the executable-zone check.
        }
        if self.is_executable(offset) {
            return self.color_for_buffer_intel(offset, buf);
        }
        None
    }
}

/// `MachOFile::PopulateItem` column texts for one fat member (spec
/// §3.2; `MachOFile.cpp` `PopulateItem`).
#[must_use]
pub fn arch_columns(arch: &Arch) -> Vec<String> {
    let real_align = 1_u64.checked_shl(arch.align).unwrap_or(0) as u32;
    vec![
        format!("{} ({:#x})", arch.info.name, arch.cputype),
        format!("{} ({:#x})", arch.info.description, arch.cpusubtype),
        format!(
            "{} (0x{:X}) {}",
            file_type_name(arch.filetype),
            arch.filetype,
            file_type_description(arch.filetype)
        ),
        format!("{:#x}", arch.offset),
        format!("{:#x}", arch.size),
        format!("{:#x}", arch.align),
        format!("{real_align:#x}"),
    ]
}

/// Lower-case hex digits for the `%.2x` UUID formatting of
/// `Panels::Information::UpdateUUID`.
const HEX_NIBBLES: [u8; 16] = *b"0123456789abcdef";

/// The Mach-O `TypeInterface` (C++ `MachO::MachOFile` as a type
/// instance).
pub struct MachoPlugin {
    colors: MachoColors,
    state: Mutex<Option<MachoFile>>,
    object: Mutex<Option<SharedObject>>,
    last_command: Mutex<Option<String>>,
    show_opcodes_mask: Mutex<u32>,
    /// `currentItemIndex` of the fat enumeration.
    current_item_index: Mutex<usize>,
}

impl Default for MachoPlugin {
    fn default() -> Self {
        Self {
            colors: MachoColors::default(),
            state: Mutex::new(None),
            object: Mutex::new(None),
            last_command: Mutex::new(None),
            show_opcodes_mask: Mutex::new(0),
            current_item_index: Mutex::new(0),
        }
    }
}

impl core::fmt::Debug for MachoPlugin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let parsed = self.state.lock().is_ok_and(|s| s.is_some());
        f.debug_struct("MachoPlugin").field("parsed", &parsed).finish_non_exhaustive()
    }
}

impl MachoPlugin {
    /// The parsed file after `PopulateWindow`.
    #[must_use]
    pub fn file(&self) -> Option<MachoFile> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The last `RunCommand` name.
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
    pub fn colorizer(&self) -> Option<MachoOpcodeColorizer> {
        self.file().map(|m| MachoOpcodeColorizer::new(&m, self.show_opcodes_mask()))
    }

    /// The `SetEnumerateCallback` snapshot for the container
    /// viewer, or `None` before `PopulateWindow` parsed the file.
    #[must_use]
    pub fn fat_enumerator(&self) -> Option<MachoFatEnumerator> {
        self.file().map(|m| MachoFatEnumerator::new(m.archs))
    }

    /// C++ `MACHO_COMMANDS`.
    #[must_use]
    pub fn commands() -> Vec<CommandDef> {
        vec![CommandDef::new(
            "DigitalSignature",
            Key::new(KeyCode::F8, KeyModifier::Alt),
            "Show digital signature",
            CMD_DIGITAL_SIGNATURE,
        )]
    }

    /// C++ `OnOpenItem`: the bytes of fat member `index` with the name
    /// the shell opens them under (`App::OpenBuffer(buffer,
    /// info.name, path/info.name, BestMatch)`), or `None` when the
    /// index is out of range or the member cannot be read.
    #[must_use]
    pub fn open_arch(&self, index: usize) -> Option<(String, Vec<u8>)> {
        let arch = self.file()?.archs.get(index).cloned()?;
        let size = u32::try_from(arch.size).ok()?;
        if size == 0 {
            return None;
        }
        let object = self.object.lock().unwrap_or_else(PoisonError::into_inner).clone()?;
        let bytes = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            guard.data_mut().copy_to_vec(arch.offset, size, true).ok()?
        };
        Some((arch.info.name, bytes))
    }
}

/// `SetEnumerateCallback` snapshot handed to the container viewer
/// (spec `00_APP §5.3.3`): an owned copy of the fat-binary
/// architecture list with its own cursor, so the control never
/// borrows the plugin.
#[derive(Clone, Debug, Default)]
pub struct MachoFatEnumerator {
    archs: Vec<Arch>,
    cursor: usize,
}

impl MachoFatEnumerator {
    /// Enumerator over the parsed fat members.
    #[must_use]
    pub const fn new(archs: Vec<Arch>) -> Self {
        Self { archs, cursor: 0 }
    }
}

impl EnumerateInterface for MachoFatEnumerator {
    /// C++ `BeginIteration`: `archs.size() > 0`.
    fn begin_iteration(&mut self, _path: &str, _parent: TreeItemId) -> bool {
        self.cursor = 0;
        !self.archs.is_empty()
    }

    /// C++ `PopulateItem`: one fat member per call.
    fn populate_item(&mut self, child: &mut TreeNode) -> bool {
        let Some(arch) = self.archs.get(self.cursor) else {
            return false;
        };
        for (col, text) in arch_columns(arch).iter().enumerate() {
            child.set_text(col, text);
        }
        child.data = self.cursor as u64;
        self.cursor = self.cursor.saturating_add(1);
        self.cursor != self.archs.len()
    }
}

impl EnumerateInterface for MachoPlugin {
    /// C++ `BeginIteration`: `archs.size() > 0`.
    fn begin_iteration(&mut self, _path: &str, _parent: TreeItemId) -> bool {
        *self.current_item_index.lock().unwrap_or_else(PoisonError::into_inner) = 0;
        self.file().is_some_and(|m| !m.archs.is_empty())
    }

    /// C++ `PopulateItem`: one fat member per call.
    fn populate_item(&mut self, child: &mut TreeNode) -> bool {
        let Some(macho) = self.file() else {
            return false;
        };
        let index = *self.current_item_index.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(arch) = macho.archs.get(index) else {
            return false;
        };
        for (col, text) in arch_columns(arch).iter().enumerate() {
            child.set_text(col, text);
        }
        child.data = index as u64;
        let next = index.saturating_add(1);
        *self.current_item_index.lock().unwrap_or_else(PoisonError::into_inner) = next;
        next != macho.archs.len()
    }
}

impl TypePlugin for MachoPlugin {
    fn name(&self) -> &'static str {
        "Mach-O"
    }

    fn validate(buf: &[u8], extension: &str) -> bool {
        validate(buf, extension)
    }

    fn create_instance() -> Box<Self> {
        Box::default()
    }

    /// C++ `UpdateSettings` (`MachO.cpp:249-273`): the eight magics in
    /// memory order (`BinaryToHexString`), priority, description,
    /// opcode mask and the `DigitalSignature` command.
    fn metadata() -> PluginMetadata {
        PluginMetadata {
            pattern: PATTERN_MAGICS.iter().map(|m| Pattern::Magic(m.to_le_bytes().to_vec())).collect(),
            priority: PRIORITY,
            description: String::from(DESCRIPTION),
            extensions: Vec::new(),
            commands: Self::commands(),
            opcodes_mask: Some(opcodes::ALL),
        }
    }

    fn populate_window(&self, win: &mut dyn WindowHandle) -> Result<(), PluginError> {
        let object = win.object();
        let macho = {
            let mut guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            MachoFile::parse_cache(guard.data_mut()).map_err(|e: MachoError| PluginError::Window(e.to_string()))?
        };
        *self.object.lock().unwrap_or_else(PoisonError::into_inner) = Some(SharedObject::clone(&object));

        if macho.is_fat {
            win.create_viewer(ViewerRequest::container(container_view_request()))?;
        }
        win.create_viewer(ViewerRequest::buffer(buffer_view_request(&macho, &self.colors)))?;

        let add = |win: &mut dyn WindowHandle, panel: Panel, vertical: bool| {
            win.add_panel(
                PanelRequest {
                    caption: String::from(panel.caption()),
                    panel_id: String::from(panel.panel_id()),
                },
                vertical,
            );
        };
        if macho.has_panel(PanelId::Information) {
            add(win, Panel::Information, true);
        }
        if macho.is_macho {
            for (panel, vertical) in THIN_PANEL_ORDER {
                if macho.has_panel(panel.gate()) {
                    add(win, panel, vertical);
                }
            }
        }
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some(macho);
        Ok(())
    }

    /// C++ `RunCommand`: only the command name is recorded (the
    /// signature dialog is not ported).
    fn run_command(&mut self, command: &str) {
        *self.last_command.lock().unwrap_or_else(PoisonError::into_inner) = Some(command.to_owned());
    }

    /// C++ `Panels::Information::Update`
    /// (`Types/MachO/src/Panels/Information.cpp:241-259`): a thin
    /// Mach-O renders `UpdateBasicInfo` + `UpdateEntryPoint` +
    /// `UpdateSourceVersion` + `UpdateUUID` + `UpdateVersionMin`; a fat
    /// binary renders `UpdateFatInfo` instead. Rows the C++ guards with
    /// `CHECKRET(...has_value())` are absent when the load command is.
    // One function per C++ `Update*` helper would not match the
    // panel's single `Update()` entry point; the row list follows the
    // C++ call order top to bottom.
    #[allow(clippy::too_many_lines)]
    fn panel_content(&self, panel_id: &str) -> Option<PanelContent> {
        if panel_id != Panel::Information.panel_id() {
            return None;
        }
        let macho = self.file()?;
        let object = self.object.lock().unwrap_or_else(PoisonError::into_inner).clone()?;
        let (name, size) = {
            let guard = object.lock().unwrap_or_else(PoisonError::into_inner);
            (guard.name().to_owned(), guard.data().size())
        };
        if macho.is_fat && !macho.is_macho {
            // `UpdateFatInfo` (`Information.cpp:224-240`).
            return Some(PanelContent::KeyValue(vec![
                (String::from("Fat Binary Info"), String::new()),
                (String::from("File"), name),
                (String::from("Size"), format!("{} bytes", fmt::dec(size))),
                (
                    String::from("Arch"),
                    String::from(if macho.is64 { "x64" } else { "x86" }),
                ),
                // `{ NumericFormatFlags::None, 10 }` — no grouping here.
                (String::from("Objects"), macho.fat_arch_count.to_string()),
            ]));
        }
        if !macho.is_macho {
            return Some(PanelContent::KeyValue(Vec::new()));
        }

        let header = &macho.header;
        let info = arch_info(header.cputype, header.cpusubtype.cast_unsigned());
        // `"%-14s (%s)"` and `"%-14s (0x%X)"`; `%X` is upper case with
        // no padding, i.e. the same text `fmt::hex` produces.
        let wide = |text: &str, value: u64| format!("{} ({})", fmt::pad(text, 14), fmt::hex(value));
        let mut rows = vec![
            (String::from("Info"), String::new()),
            (String::from("File"), name),
            (String::from("Size"), fmt::dec_and_hex(size, 14)),
            (
                String::from("Byte Order"),
                String::from(names::byte_order_name(info.byteorder)),
            ),
            (
                String::from("Magic"),
                wide(
                    if macho.is64 { "MH_MAGIC_64" } else { "MH_MAGIC" },
                    u64::from(header.magic),
                ),
            ),
            (
                String::from("CPU Type"),
                wide(&info.name, u64::from(header.cputype.cast_unsigned())),
            ),
            (
                String::from("CPU Subtype"),
                wide(&info.description, u64::from(header.cpusubtype.cast_unsigned())),
            ),
            (
                String::from("File Type"),
                wide(file_type_name(header.filetype), u64::from(header.filetype)),
            ),
            (
                String::from("Load Commands"),
                wide(&fmt::dec(u64::from(header.ncmds)), u64::from(header.ncmds)),
            ),
            (
                String::from("Size of Commands"),
                fmt::dec_and_hex(u64::from(header.sizeofcmds), 14),
            ),
            (
                String::from("Flags"),
                wide(&fmt::dec(u64::from(header.flags)), u64::from(header.flags)),
            ),
        ];
        // One caption-less row per set flag: `"%-20s %-12s %s"`.
        for (bit, flag_name, description) in names::set_header_flags(header.flags) {
            rows.push((
                String::new(),
                format!(
                    "{} {} {description}",
                    fmt::pad(flag_name, 20),
                    fmt::pad(&format!("({})", fmt::hex(u64::from(*bit))), 12)
                ),
            ));
        }
        if macho.is64 {
            rows.push((
                String::from("Reserved"),
                wide(&fmt::dec(u64::from(header.reserved)), u64::from(header.reserved)),
            ));
        }

        // `UpdateEntryPoint` (`Information.cpp:70-95`).
        if let Some(main) = macho.main {
            rows.push((String::from("Entry Point"), String::new()));
            rows.push((
                String::from("Command"),
                wide(names::load_command_name(main.cmd), u64::from(main.cmd)),
            ));
            rows.push((String::from("Cmd Size"), fmt::dec_and_hex(u64::from(main.cmdsize), 14)));
            rows.push((String::from("EP offset"), fmt::dec_and_hex(main.entryoff, 14)));
            rows.push((String::from("Stack Size"), fmt::dec_and_hex(main.stacksize, 14)));
        }

        // `UpdateSourceVersion` (`Information.cpp:97-124`): the packed
        // `a.b.c.d.e` version, `%-22s (%s)`.
        if let Some(source) = macho.source_version {
            rows.push((String::from("Source Version"), String::new()));
            rows.push((
                String::from("Command"),
                format!(
                    "{} ({})",
                    fmt::pad(names::load_command_name(source.cmd), 22),
                    fmt::hex(u64::from(source.cmd))
                ),
            ));
            rows.push((
                String::from("Cmd Size"),
                format!(
                    "{} ({})",
                    fmt::pad(&fmt::dec(u64::from(source.cmdsize)), 22),
                    fmt::hex(u64::from(source.cmdsize))
                ),
            ));
            let v = source.version;
            let text = format!(
                "{}.{}.{}.{}.{}",
                (v >> 40) & 0x00FF_FFFF,
                (v >> 30) & 0x3FF,
                (v >> 20) & 0x3FF,
                (v >> 10) & 0x3FF,
                v & 0x3FF
            );
            rows.push((
                String::from("Version"),
                format!("{} ({})", fmt::pad(&text, 22), fmt::hex(v)),
            ));
        }

        // `UpdateUUID` (`Information.cpp:126-186`): `%-35s (%s)` with
        // the lower-case `%.2x` UUID text and its `0x…` concatenation.
        if let Some(uuid) = macho.uuid {
            rows.push((String::from("UUID"), String::new()));
            rows.push((
                String::from("Command"),
                format!(
                    "{} ({})",
                    fmt::pad(names::load_command_name(uuid.cmd), 35),
                    fmt::hex(u64::from(uuid.cmd))
                ),
            ));
            rows.push((
                String::from("Cmd Size"),
                format!(
                    "{} ({})",
                    fmt::pad(&fmt::dec(u64::from(uuid.cmdsize)), 35),
                    fmt::hex(u64::from(uuid.cmdsize))
                ),
            ));
            let mut plain = String::with_capacity(36);
            let mut packed = String::from("0x");
            for (index, byte) in uuid.uuid.iter().enumerate() {
                if matches!(index, 4 | 8 | 12) {
                    plain.push('-');
                }
                // `%.2x`: two lower-case nibbles, no allocation.
                for nibble in [byte >> 4, byte & 0x0F] {
                    let digit = char::from(HEX_NIBBLES.get(nibble as usize).copied().unwrap_or(b'0'));
                    plain.push(digit);
                    packed.push(digit);
                }
            }
            rows.push((
                String::from("UUID"),
                format!("{} ({packed})", fmt::pad(&plain, 35)),
            ));
        }

        // `UpdateVersionMin` (`Information.cpp:188-216`).
        if let Some(min) = macho.version_min {
            rows.push((String::from("Version Min"), String::new()));
            rows.push((
                String::from("Command"),
                format!(
                    "{} ({})",
                    fmt::pad(names::load_command_name(min.cmd), 22),
                    fmt::hex(u64::from(min.cmd))
                ),
            ));
            rows.push((
                String::from("Cmd Size"),
                format!(
                    "{} ({})",
                    fmt::pad(&fmt::dec(u64::from(min.cmdsize)), 22),
                    fmt::hex(u64::from(min.cmdsize))
                ),
            ));
            let triple = |packed: u32| {
                format!("{}.{}.{}", packed >> 16, (packed >> 8) & 0xFF, packed & 0xFF)
            };
            rows.push((
                String::from("Version"),
                format!(
                    "{} ({})",
                    fmt::pad(&triple(min.version), 22),
                    fmt::hex(u64::from(min.version))
                ),
            ));
            rows.push((
                String::from("SDK"),
                format!("{} ({})", fmt::pad(&triple(min.sdk), 22), fmt::hex(u64::from(min.sdk))),
            ));
        }
        rows.shrink_to_fit();
        Some(PanelContent::KeyValue(rows))
    }

    /// C++ `SetPositionToColorCallback(macho)` (`MachO.cpp`
    /// `CreateBufferView`).
    fn position_to_color(&self) -> Option<Box<dyn PositionToColorCallback + Send>> {
        self.colorizer()
            .map(|c| Box::new(c) as Box<dyn PositionToColorCallback + Send>)
    }

    /// C++ `SetEnumerateCallback(macho)` — the fat-binary
    /// architecture list (`MachO.cpp` `CreateContainerView`).
    fn container_enumerator(&self) -> Option<Box<dyn EnumerateInterface + Send>> {
        self.fat_enumerator()
            .map(|e| Box::new(e) as Box<dyn EnumerateInterface + Send>)
    }

    /// C++ `UpdateKeys`.
    fn register_keys(&self, keys: &mut dyn KeyRegistry) {
        for command in Self::commands() {
            keys.register_key(&command);
        }
    }

    /// C++ `GetSmartAssistantContext`: `Name` and `ContentSize`.
    fn smart_assistant_context(&self, _prompt: &str, _display: &str) -> Result<JsonValue, PluginError> {
        self.file()
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
            "ContentSize": size,
        }))
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing, clippy::cast_possible_wrap)]
mod tests {
    use super::*;
    use crate::parse::tests::{fat, thin, typical};
    use crate::parse::{lc, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
    use gview_core::object::Object;
    use gview_plugin::type_plugin::ViewerKind;
    use gview_view::container_viewer::tree::ContainerTree;
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

    fn zones(request: &BufferViewerRequest) -> Vec<(String, u64, u64)> {
        (0..request.zones.count())
            .filter_map(|i| request.zones.zone(i).map(|z| (z.name.clone(), z.low, z.high)))
            .collect()
    }

    fn cb(c: &mut MachoOpcodeColorizer, offset: u64, buf: &[u8]) -> Option<(u64, u64, CharAttribute)> {
        PositionToColorCallback::color_for_buffer(c, offset, buf).map(|b| (b.start, b.end, b.color))
    }

    #[test]
    fn thin_populate_creates_buffer_view_zones_and_panels() {
        let (image, _) = typical(true, false);
        let plugin = MachoPlugin::create_instance();
        let mut win = window_for(&image, "a.out");
        plugin.populate_window(&mut win).expect("populate");
        let m = plugin.file().expect("parsed");

        assert_eq!(win.viewers.len(), 1);
        assert_eq!(win.viewers[0].kind, ViewerKind::Buffer);
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        let z = zones(buffer);
        assert_eq!(z[0], (String::from("Header"), 0, 31));
        // 12 load-command zones follow the header.
        assert_eq!(z[1], (String::from("(#0)LC"), 32, 32 + u64::from(m.load_commands[0].cmdsize) - 1));
        assert_eq!(z[12].0, "(#11)LC");
        let text = &m.segments[1].sections[0];
        assert_eq!(z[13], (String::from("__text"), u64::from(text.offset), u64::from(text.offset) + text.size - 1));
        let sc = m.symtab.as_ref().expect("symtab").command;
        assert_eq!(z[14], (String::from("Symbol_Table"), u64::from(sc.symoff), u64::from(sc.symoff) + 2 * 16 - 1));
        assert_eq!(z[15], (String::from("Symbol_Strings"), u64::from(sc.stroff), u64::from(sc.stroff) + u64::from(sc.strsize) - 1));
        assert_eq!(z[16], (String::from("(#0)Link_Edit"), 0x300, 0x30F));
        assert_eq!(z[17], (String::from("(#1)Link_Edit"), 0x400, 0x41F));
        assert_eq!(z.len(), 18);
        assert_eq!(buffer.entry_point, Some(0x40));
        assert!(buffer.position_to_color);
        assert!(buffer.translation_methods.is_empty());
        assert!(buffer.bookmarks.is_empty());

        assert_eq!(
            win.panels,
            [
                (String::from("Informa&Tion"), true),
                (String::from("Co&mmands"), false),
                (String::from("Se&gments"), false),
                (String::from("&Sections"), false),
                (String::from("&DyldInfo"), true),
                (String::from("D&ylibs"), false),
                (String::from("SymTa&b"), false),
                (String::from("Op&Codes"), true),
            ]
        );
    }

    #[test]
    fn arm64_thin_without_tables_has_minimal_panels_and_no_colouring() {
        let image = thin(true, false, CPU_TYPE_ARM64, &[], &[]);
        let plugin = MachoPlugin::create_instance();
        let mut win = window_for(&image, "arm");
        plugin.populate_window(&mut win).expect("populate");
        let buffer = win.viewers[0].buffer.as_ref().expect("buffer");
        assert_eq!(zones(buffer), [(String::from("Header"), 0, 31)]);
        assert!(!buffer.position_to_color);
        assert_eq!(buffer.entry_point, None);
        assert_eq!(win.panels, [(String::from("Informa&Tion"), true), (String::from("Co&mmands"), false)]);
        // 32-bit header zone is 28 bytes.
        let image32 = thin(false, false, CPU_TYPE_ARM64, &[], &[0; 4]);
        let mut win = window_for(&image32, "arm32");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(zones(win.viewers[0].buffer.as_ref().expect("buffer"))[0], (String::from("Header"), 0, 27));
    }

    #[test]
    fn fat_populate_adds_container_view_arch_zones_and_enumerates_members() {
        let (x86, _) = typical(true, false);
        let arm = thin(true, false, CPU_TYPE_ARM64, &[], &[]);
        let image = fat(false, true, &[(CPU_TYPE_X86_64, 3, x86.clone()), (CPU_TYPE_ARM64, 0, arm.clone())]);
        let mut plugin = MachoPlugin::create_instance();
        let mut win = window_for(&image, "universal");
        plugin.populate_window(&mut win).expect("populate");

        assert_eq!(win.viewers.len(), 2);
        assert_eq!(win.viewers[0].kind, ViewerKind::Container);
        let container = win.viewers[0].container.as_ref().expect("container");
        assert_eq!(container.icon.as_deref().map(str::len), Some(256));
        assert_eq!(container.columns.len(), 7);
        assert_eq!(container.columns[0], "n:CPU type,a:r,w:25");
        assert_eq!(container.path_separator, '/');
        assert!(container.properties.is_empty());
        assert_eq!(win.viewers[1].kind, ViewerKind::Buffer);
        let z = zones(win.viewers[1].buffer.as_ref().expect("buffer"));
        // Header 8 bytes; Arch zones start at 32 (C++ quirk), 20 bytes each.
        assert_eq!(z[0], (String::from("Header"), 0, 7));
        assert_eq!(z[1], (String::from("Arch #0"), 32, 51));
        assert_eq!(z[2], (String::from("#0 x86_64"), 0x1000, 0x1000 + x86.len() as u64 - 1));
        assert_eq!(z[3], (String::from("Arch #1"), 52, 71));
        assert_eq!(z[4].0, "#1 arm64");
        assert_eq!(z[4].2, z[4].1 + arm.len() as u64 - 1);
        assert_eq!(win.panels, [(String::from("Informa&Tion"), true)]);

        // Container enumeration through the lazy tree.
        let mut tree = ContainerTree::new('/');
        let root = tree.root();
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        let children = tree.children(root).to_vec();
        assert_eq!(children.len(), 2);
        let first = tree.node(children[0]).expect("node");
        assert_eq!(first.texts[0], "x86_64 (0x1000007)");
        assert_eq!(first.texts[1], "Intel x86-64 (0x3)");
        assert_eq!(first.texts[2], "EXECUTE (0x2) Demand paged executable file.");
        assert_eq!(first.texts[3], "0x1000");
        assert_eq!(first.texts[4], format!("{:#x}", x86.len()));
        assert_eq!(first.texts[5], "0xc");
        assert_eq!(first.texts[6], "0x1000");
        assert_eq!(first.data, 0);
        let second = tree.node(children[1]).expect("node");
        assert_eq!(second.texts[0], "arm64 (0x100000c)");
        assert_eq!(second.data, 1);
        // Idempotent: a second populate adds nothing.
        assert!(tree.populate_item(root, &mut *plugin, &mut |_| false));
        assert_eq!(tree.children(root).len(), 2);

        // OnOpenItem: the member bytes under its arch name.
        let (name, bytes) = plugin.open_arch(1).expect("open");
        assert_eq!(name, "arm64");
        assert_eq!(bytes, arm);
        assert_eq!(plugin.open_arch(0).expect("open").1, x86);
        assert!(plugin.open_arch(2).is_none());
        // 64-bit fat arch zones are 32 bytes.
        let image64 = fat(true, true, &[(CPU_TYPE_ARM64, 0, arm)]);
        let mut win = window_for(&image64, "fat64");
        plugin.populate_window(&mut win).expect("populate");
        let z = zones(win.viewers[1].buffer.as_ref().expect("buffer"));
        assert_eq!(z[1], (String::from("Arch #0"), 32, 63));
    }


    /// Field list and value formatting of C++
    /// `Panels::Information::UpdateBasicInfo` and, for a fat binary,
    /// `UpdateFatInfo` (`Types/MachO/src/Panels/Information.cpp`).
    #[test]
    fn information_panel_matches_cpp_field_list() {
        let plugin = MachoPlugin::create_instance();
        assert!(
            plugin.panel_content(Panel::Information.panel_id()).is_none(),
            "no panel before populate_window"
        );

        let (image, _) = typical(true, false);
        let mut win = window_for(&image, "thin");
        plugin.populate_window(&mut win).expect("populate");
        let content = plugin.panel_content(Panel::Information.panel_id()).expect("panel");
        let PanelContent::KeyValue(rows) = &content else {
            panic!("Information is a key/value panel");
        };
        let fields: Vec<&str> = rows.iter().map(|(f, _)| f.as_str()).collect();
        // The fixed head of `UpdateBasicInfo`, then one caption-less
        // row per set header flag, then the optional load-command
        // blocks.
        assert_eq!(
            &fields[..11],
            [
                "Info",
                "File",
                "Size",
                "Byte Order",
                "Magic",
                "CPU Type",
                "CPU Subtype",
                "File Type",
                "Load Commands",
                "Size of Commands",
                "Flags",
            ]
        );
        let macho = plugin.file().expect("parsed");
        assert_eq!(rows[1].1, "thin");
        assert_eq!(rows[2].1, fmt::dec_and_hex(image.len() as u64, 14));
        assert_eq!(rows[3].1, "LittleEndian");
        assert_eq!(
            rows[4].1,
            format!("{} ({})", fmt::pad("MH_MAGIC_64", 14), fmt::hex(u64::from(macho.header.magic)))
        );
        assert!(rows[5].1.starts_with("x86_64"), "CPU Type: {}", rows[5].1);
        // 64-bit headers end with the `Reserved` row of `UpdateBasicInfo`.
        assert!(fields.contains(&"Reserved"), "{fields:?}");
        // Every flag row is caption-less and names its bit.
        for (index, (caption, value)) in rows.iter().enumerate().skip(11) {
            if caption.is_empty() {
                assert!(value.contains("(0x"), "flag row {index}: {value}");
            }
        }
        assert!(plugin.panel_content(Panel::Segments.panel_id()).is_none());
    }

    /// A fat binary renders `UpdateFatInfo` instead of the header rows.
    #[test]
    fn information_panel_of_a_fat_binary_matches_update_fat_info() {
        let (x86, _) = typical(true, false);
        let plugin = MachoPlugin::create_instance();
        let image = fat(false, true, &[(CPU_TYPE_X86_64, 3, x86)]);
        let mut win = window_for(&image, "universal");
        plugin.populate_window(&mut win).expect("populate");
        let content = plugin.panel_content(Panel::Information.panel_id()).expect("panel");
        assert_eq!(
            content,
            PanelContent::KeyValue(vec![
                (String::from("Fat Binary Info"), String::new()),
                (String::from("File"), String::from("universal")),
                (
                    String::from("Size"),
                    format!("{} bytes", fmt::dec(image.len() as u64))
                ),
                (String::from("Arch"), String::from("x86")),
                (String::from("Objects"), String::from("1")),
            ])
        );
    }

    /// `00_APP §5.3.3`: both hooks are `None` before
    /// `populate_window`; afterwards the boxed colorizer colours the
    /// same ranges the plugin's own colorizer does, and the boxed
    /// enumerator lists the same fat members the plugin does.
    #[test]
    fn viewer_service_hooks_snapshot_the_plugin() {
        let plugin = MachoPlugin::create_instance();
        assert!(plugin.position_to_color().is_none(), "before populate_window");
        assert!(plugin.container_enumerator().is_none());
        assert!(plugin.container_opener().is_none(), "Mach-O has no open hook");
        assert!(plugin.panel_content("macho.information").is_none());

        let (x86, _) = typical(true, false);
        let arm = thin(true, false, CPU_TYPE_ARM64, &[], &[]);
        let image = fat(false, true, &[(CPU_TYPE_X86_64, 3, x86), (CPU_TYPE_ARM64, 0, arm)]);
        let mut win = window_for(&image, "universal");
        plugin.populate_window(&mut win).expect("populate");
        plugin.set_show_opcodes_mask(opcodes::ALL);

        let mut hook = plugin.position_to_color().expect("colour hook");
        let mut direct = plugin.colorizer().expect("colorizer");
        for (offset, bytes) in [
            (0_u64, [0xCA, 0xFE, 0xBA, 0xBE].as_slice()),
            (0x1000, &[0xCC, 0x00]),
            (0x1000, &[0x55, 0x8B, 0xEC]),
            (0x1000, &[0x90, 0x90]),
        ] {
            let boxed = hook.color_for_buffer(offset, bytes).map(|b| (b.start, b.end, b.color));
            assert_eq!(
                boxed,
                cb(&mut direct, offset, bytes),
                "hook and colorizer disagree at {offset:#x}"
            );
        }

        // The enumerator snapshot walks the same two members, and has
        // its own cursor: the plugin's own iteration is unaffected.
        let mut enumerator = plugin.container_enumerator().expect("enumerate hook");
        assert!(enumerator.begin_iteration("", 0));
        let mut first = TreeNode::default();
        assert!(enumerator.populate_item(&mut first), "one member follows");
        assert_eq!(first.texts[0], "x86_64 (0x1000007)");
        assert_eq!(first.data, 0);
        let mut second = TreeNode::default();
        assert!(!enumerator.populate_item(&mut second), "last member");
        assert_eq!(second.texts[0], "arm64 (0x100000c)");
        assert_eq!(second.data, 1);
        assert!(!enumerator.populate_item(&mut TreeNode::default()), "exhausted");
        // Restartable.
        assert!(enumerator.begin_iteration("", 0));
        assert!(enumerator.populate_item(&mut TreeNode::default()));

        // A thin file has no members: the hook exists, it lists nothing.
        let (thin_image, _) = typical(true, false);
        let mut win = window_for(&thin_image, "thin");
        plugin.populate_window(&mut win).expect("populate");
        let mut enumerator = plugin.container_enumerator().expect("enumerate hook");
        assert!(!enumerator.begin_iteration("", 0));
        assert!(!enumerator.populate_item(&mut TreeNode::default()));
    }

    #[test]
    fn enumerate_without_archs_or_file_reports_nothing() {
        let mut plugin = MachoPlugin::create_instance();
        assert!(!plugin.begin_iteration("", 0));
        let mut node = TreeNode::default();
        assert!(!plugin.populate_item(&mut node));
        assert!(plugin.open_arch(0).is_none());
        let (image, _) = typical(true, false);
        let mut win = window_for(&image, "thin");
        plugin.populate_window(&mut win).expect("populate");
        assert!(!plugin.begin_iteration("", 0), "thin files have no members");
    }

    #[test]
    fn errors_from_update_fail_populate_without_viewers() {
        let dup = command_dup();
        let plugin = MachoPlugin::create_instance();
        let mut win = window_for(&dup, "dup");
        let err = plugin.populate_window(&mut win).expect_err("duplicate LC_MAIN");
        assert!(matches!(err, PluginError::Window(_)));
        assert!(err.to_string().contains("MAIN"));
        assert!(win.viewers.is_empty());
        assert!(plugin.file().is_none());
        assert!(format!("{plugin:?}").contains("parsed: false"));
        // A non-Mach-O buffer still populates (empty buffer viewer,
        // Information panel), as the C++ does.
        let mut win = window_for(b"MZ\x90\x00", "notmacho");
        plugin.populate_window(&mut win).expect("populate");
        assert_eq!(win.viewers.len(), 1);
        assert_eq!(win.viewers[0].buffer.as_ref().map(|b| b.zones.count()), Some(0));
        assert_eq!(win.panels, [(String::from("Informa&Tion"), true)]);
    }

    fn command_dup() -> Vec<u8> {
        let main = crate::parse::tests::command(false, lc::MAIN, &[], &[0, 0], &[]);
        thin(true, false, CPU_TYPE_X86_64, &[main.clone(), main], &[])
    }

    #[test]
    fn opcode_colorizer_matches_cpp_heuristics() {
        let (image, _) = typical(true, false);
        let plugin = MachoPlugin::create_instance();
        let mut win = window_for(&image, "ops");
        plugin.populate_window(&mut win).expect("populate");
        let m = plugin.file().expect("parsed");
        let text = &m.segments[1].sections[0];
        let colors = OpcodeColors::default();

        let mut off = plugin.colorizer().expect("colorizer");
        assert_eq!(cb(&mut off, u64::from(text.offset), &[0xCC]), None, "mask 0");
        plugin.set_show_opcodes_mask(opcodes::ALL);
        assert_eq!(plugin.show_opcodes_mask(), opcodes::ALL);
        let mut c = plugin.colorizer().expect("colorizer");
        assert_eq!(c.cputype, CPU_TYPE_X86_64);
        // Header marker: MH_MAGIC / MH_CIGAM little-endian dwords.
        assert_eq!(cb(&mut c, 0, &MH_MAGIC.to_le_bytes()), Some((0, 3, colors.exe_marker)));
        assert_eq!(cb(&mut c, 0, &MH_CIGAM.to_le_bytes()), Some((0, 3, colors.exe_marker)));
        // MH_MAGIC_64 starts with 0xCF: not one of the C++ `case 0xFE / 0xCE` bytes.
        assert_eq!(cb(&mut c, 0, &MH_MAGIC_64.to_le_bytes()), None);
        let at = u64::from(text.offset) + 8;
        let expect = |end: u64, color: CharAttribute| Some((at, end, color));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x15, 1, 2, 3, 4]), expect(at + 5, colors.call));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x25, 1, 2, 3, 4]), expect(at + 5, colors.jump));
        assert_eq!(cb(&mut c, at, &[0xFF, 0x15, 1, 2, 3]), None);
        assert_eq!(cb(&mut c, at, &[0xCC]), expect(at, colors.breakpoint));
        assert_eq!(cb(&mut c, at, &[0x55, 0x8B, 0xEC]), expect(at + 2, colors.function_start));
        assert_eq!(cb(&mut c, at, &[0x8B, 0xE5, 0x5D, 0xC3]), expect(at + 3, colors.function_end));
        assert_eq!(cb(&mut c, at, &[0x8B, 0xE5, 0x5D, 0xC2]), None);
        assert_eq!(cb(&mut c, at, &[0x90]), None);
        assert_eq!(cb(&mut c, at, &[]), None);
        // Outside executable zones: nothing (the __LINKEDIT segment).
        let linkedit = m.segments[2].fileoff;
        assert_eq!(cb(&mut c, linkedit, &[0xCC]), None);
        // Header bit off: no marker.
        c.show_opcodes_mask = opcodes::CALL;
        assert_eq!(cb(&mut c, 0, &MH_MAGIC.to_le_bytes()), None);
        assert_eq!(cb(&mut c, at, &[0xCC]), expect(at, colors.breakpoint), "Intel bits not consulted");
        // Non-Intel CPU: nothing at all, even the header marker.
        c.show_opcodes_mask = opcodes::ALL;
        c.cputype = CPU_TYPE_ARM64;
        assert_eq!(cb(&mut c, 0, &MH_MAGIC.to_le_bytes()), None);
        assert_eq!(cb(&mut c, at, &[0xCC]), None);
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
        let meta = MachoPlugin::metadata();
        let inis: Vec<String> = meta.pattern.iter().map(Pattern::to_ini_string).collect();
        assert_eq!(
            inis,
            [
                "magic:CE FA ED FE",
                "magic:FE ED FA CE",
                "magic:CF FA ED FE",
                "magic:FE ED FA CF",
                "magic:BE BA FE CA",
                "magic:CA FE BA BE",
                "magic:BF BA FE CA",
                "magic:CA FE BA BF",
            ]
        );
        assert_eq!(meta.priority, 1);
        assert_eq!(meta.description, DESCRIPTION);
        assert_eq!(meta.opcodes_mask, Some(0xFFFF_FFFF));
        assert_eq!(meta.commands.len(), 1);
        assert_eq!(meta.commands[0].name, "DigitalSignature");
        assert_eq!(meta.commands[0].key, Key::new(KeyCode::F8, KeyModifier::Alt));
        assert_eq!(meta.commands[0].command_id, CMD_DIGITAL_SIGNATURE);
        assert!(MachoPlugin::validate(b"\xCA\xFE\xBA\xBE\0\0\0\x02", ""));

        let mut plugin = MachoPlugin::create_instance();
        assert_eq!(plugin.name(), "Mach-O");
        assert!(plugin.smart_assistant_context("", "").is_err());
        plugin.run_command("DigitalSignature");
        assert_eq!(plugin.last_command().as_deref(), Some("DigitalSignature"));
        let mut keys = Keys(Vec::new());
        plugin.register_keys(&mut keys);
        assert_eq!(keys.0, ["DigitalSignature"]);

        let (image, _) = typical(false, false);
        let mut win = window_for(&image, "ctx.macho");
        plugin.populate_window(&mut win).expect("populate");
        let ctx = plugin.smart_assistant_context("what", "what").expect("ctx");
        assert_eq!(ctx["Name"], "ctx.macho");
        assert_eq!(ctx["ContentSize"], image.len() as u64);
        assert_eq!(ctx.as_object().map(serde_json::Map::len), Some(2));
        assert!(format!("{plugin:?}").contains("parsed: true"));
    }

    #[test]
    fn tables_colors_and_columns() {
        assert_eq!(file_type_name(0x2), "EXECUTE");
        assert_eq!(file_type_name(0xB), "KEXT_BUNDLE");
        assert_eq!(file_type_name(0x7), "");
        assert_eq!(file_type_description(0x6), "Dynamically bound shared library.");
        assert_eq!(file_type_description(0x99), "");
        let colors = MachoColors::default();
        assert_eq!(colors.header, attr(Color::Olive, Color::Transparent));
        assert_eq!(colors.load_command, attr(Color::Magenta, Color::Transparent));
        assert_eq!(colors.section, attr(Color::Silver, Color::Transparent));
        assert_eq!(colors.link_edit, attr(Color::Teal, Color::Transparent));
        assert_eq!(colors.arch, attr(Color::Magenta, Color::Transparent));
        assert_eq!(colors.object_name, attr(Color::DarkRed, Color::Transparent));
        assert_eq!(colors.object, attr(Color::Silver, Color::Transparent));
        assert_eq!(FAT_ICON.len(), 256);
        assert_eq!(CONTAINER_COLUMNS[6], "n:Real Align,a:r,w:12");
        assert_eq!(THIN_PANEL_ORDER.len(), 10);
        assert_eq!(Panel::SymTab.gate(), PanelId::DySymTab);
        assert_eq!(Panel::GoFiles.gate(), PanelId::GoInformation);
        assert_eq!(Panel::OpCodes.panel_id(), "macho.opcodes");
        let arch = Arch {
            info: crate::parse::arch_info(CPU_TYPE_ARM64, 2),
            cputype: CPU_TYPE_ARM64,
            cpusubtype: 2,
            offset: 0x4000,
            size: 0x10,
            align: 14,
            reserved: 0,
            filetype: 6,
        };
        let cols = arch_columns(&arch);
        assert_eq!(cols[0], "arm64 (0x100000c)");
        assert_eq!(cols[1], "ARM64 (0x2)");
        assert_eq!(cols[2], "DYLIB (0x6) Dynamically bound shared library.");
        assert_eq!(cols[3], "0x4000");
        assert_eq!(cols[5], "0xe");
        assert_eq!(cols[6], "0x4000");
        let huge = Arch { align: 40, ..arch };
        assert_eq!(arch_columns(&huge)[6], "0x0", "(uint32)(1 << 40) truncates to 0");
    }
}
