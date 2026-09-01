//! `DissasmViewer` zone model (spec `02_VIEWER_DISSASM` §3).
//!
//! C++ anchors: `ParseZone` hierarchy + `DissasmParseZoneType`
//! (`DissasmViewer.hpp:94-125`), `DisassemblyZone`
//! (`DissasmViewer.hpp:55-62`), `AsmOffsetLine`
//! (`DissasmViewer.hpp:127-130`), `DissasmCodeInternalType`
//! (`DissasmViewer.hpp:310-367`), `DissasmCodeZone`
//! (`DissasmCodeZone.hpp:7-47`), `DissasmComments` /
//! `AnnotationContainer` (`DissasmDataTypes.hpp:42-89`,
//! `DissasmDataTypes.cpp:7-50`), `UpdateLayoutTotalLines`
//! (`Instance.cpp:1169-1173`).
//!
//! The struct layout mirrors the C++ types field-for-field so later
//! tasks (offset table, pre-cache, collapse) can port their
//! algorithms without re-mapping names. C++ raw pointers
//! (`asmData`, capstone buffers) are not carried here — data flows
//! through `DataCache` reads instead.

use std::collections::{BTreeMap, HashMap};

/// C++ `DisassemblyLanguage` (`GView.hpp:1766`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DisassemblyLanguage {
    /// Resolved to a concrete language at zone creation.
    #[default]
    Default,
    /// 32-bit x86.
    X86,
    /// 64-bit x86.
    X64,
    /// Java `.class` bytecode (§12A path).
    JavaByteCode,
}

/// C++ `DissasmParseZoneType` (`DissasmViewer.hpp:94`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DissasmParseZoneType {
    /// Typed data fields (`DrawStructureZone`).
    StructureParseZone,
    /// Capstone instructions (`DrawDissasmZone`).
    DissasmCodeParseZone,
    /// Raw text blocks (`DrawCollapsibleAndTextZone`).
    CollapsibleAndTextZone,
}

/// C++ `CollapseExpandType` (`DissasmCodeZone.hpp:8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollapseExpandType {
    /// Force collapsed.
    Collapse,
    /// Force expanded.
    Expand,
    /// Toggle.
    NegateCurrentState,
}

/// Common zone header (C++ `ParseZone`, `DissasmViewer.hpp:96-105`).
#[derive(Clone, Debug)]
pub struct ParseZone {
    /// First document line of the zone.
    pub start_line_index: u32,
    /// One past the zone's last document line.
    pub ending_line_index: u32,
    /// Lines revealed by expanding (C++ `extendedSize`; collapse math
    /// uses this, **not** `ending - start`, spec §3.2).
    pub extended_size: u32,
    /// C++ `zoneID`.
    pub zone_id: u16,
    /// Collapse state (structures start collapsed:
    /// `structuresInitialCollapsedState = true`, `Instance.cpp:192`).
    pub is_collapsed: bool,
    /// Discriminator (C++ `zoneType`).
    pub zone_type: DissasmParseZoneType,
}

impl ParseZone {
    /// Fresh zone header of `zone_type`.
    #[must_use]
    pub const fn new(zone_type: DissasmParseZoneType) -> Self {
        Self {
            start_line_index: 0,
            ending_line_index: 0,
            extended_size: 0,
            zone_id: 0,
            is_collapsed: false,
            zone_type,
        }
    }
}

/// C++ `DisassemblyZone` (`DissasmViewer.hpp:55-62`) — the region a
/// type plugin marks for disassembly.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisassemblyZone {
    /// File offset where the zone starts.
    pub starting_zone_point: u64,
    /// Zone size in bytes.
    pub size: u64,
    /// Entry point (file offset).
    pub entry_point: u64,
    /// Architecture/language.
    pub language: DisassemblyLanguage,
}

/// C++ `AsmOffsetLine` (`DissasmViewer.hpp:127-130`) — one offset
/// table anchor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AsmOffsetLine {
    /// File offset of the instruction.
    pub offset: u64,
    /// Zone-relative asm line.
    pub line: u32,
}

/// Per-line user comments (C++ `DissasmComments`,
/// `DissasmDataTypes.cpp:7-50`).
///
/// C++ quirk preserved: entries are stored keyed by `line - 1`
/// (`AddOrUpdateComment` writes `comments[line - 1]`), and
/// `AdjustCommentsOffsets` shifts the **stored** keys.
#[derive(Clone, Debug, Default)]
pub struct DissasmComments {
    comments: BTreeMap<u32, String>,
}

impl DissasmComments {
    /// C++ `AddOrUpdateComment` — stores at `line - 1`.
    pub fn add_or_update_comment(&mut self, line: u32, comment: String) {
        self.comments.insert(line.saturating_sub(1), comment);
    }

    /// C++ `GetComment` — reads at `line - 1`.
    #[must_use]
    pub fn get_comment(&self, line: u32) -> Option<&str> {
        self.comments
            .get(&line.saturating_sub(1))
            .map(String::as_str)
    }

    /// C++ `HasComment`.
    #[must_use]
    pub fn has_comment(&self, line: u32) -> bool {
        self.comments.contains_key(&line.saturating_sub(1))
    }

    /// C++ `RemoveComment`; `false` when nothing was stored (C++
    /// shows an error box).
    pub fn remove_comment(&mut self, line: u32) -> bool {
        self.comments.remove(&line.saturating_sub(1)).is_some()
    }

    /// Number of comments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.comments.len()
    }

    /// `true` when no comments exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.comments.is_empty()
    }

    /// C++ `AdjustCommentsOffsets` (`DissasmDataTypes.cpp:37-50`):
    /// re-keys every stored entry at/after `changed_line` by ±1;
    /// entries **below** it are dropped by the C++ rebuild loop —
    /// intentional parity (the C++ `commentsAjusted` map only
    /// receives shifted entries).
    pub fn adjust_comments_offsets(&mut self, changed_line: u32, is_added_line: bool) {
        let old = std::mem::take(&mut self.comments);
        for (line, text) in old {
            if line >= changed_line {
                let new_line = if is_added_line {
                    line.saturating_add(1)
                } else {
                    line.saturating_sub(1)
                };
                self.comments.insert(new_line, text);
            }
        }
    }

    /// Iterates `(stored_key, text)` in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &String)> {
        self.comments.iter()
    }
}

/// Line annotations — function names discovered by the pre-pass
/// (C++ `AnnotationContainer`, `DissasmDataTypes.hpp:57-89`):
/// `line → (name, file offset)` plus the rename link maps.
#[derive(Clone, Debug, Default)]
pub struct AnnotationContainer {
    /// C++ `mappings`: line → (call name, value).
    pub mappings: BTreeMap<u32, (String, u64)>,
    /// C++ `initial_name_to_current_name` (user renames).
    pub initial_name_to_current_name: HashMap<String, String>,
    /// C++ `current_name_to_initial_name`.
    pub current_name_to_initial_name: HashMap<String, String>,
}

impl AnnotationContainer {
    /// C++ `size()` — mapping count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// `true` when no annotations exist.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// Nested collapsible code region (C++ `DissasmCodeInternalType`,
/// `DissasmViewer.hpp:310-367`).
#[derive(Clone, Debug, Default)]
pub struct DissasmCodeInternalType {
    /// Region name (empty for the unnamed root spans).
    pub name: String,
    /// Current document span start (moves as siblings collapse).
    pub index_zone_start: u32,
    /// Current document span end.
    pub index_zone_end: u32,
    /// Expanded ("working") span start.
    pub working_index_zone_start: u32,
    /// Expanded span end.
    pub working_index_zone_end: u32,
    /// Text (annotation) lines before this region.
    pub before_text_lines: u32,
    /// Asm lines before this region.
    pub before_asm_lines: u32,
    /// Text lines consumed inside the region while drawing.
    pub text_lines_passed: u32,
    /// Asm lines consumed inside the region while drawing.
    pub asm_lines_passed: u32,
    /// Function-name annotations inside the region.
    pub annotations: AnnotationContainer,
    /// User comments inside the region.
    pub comments_data: DissasmComments,
    /// Collapse state.
    pub is_collapsed: bool,
    /// Nested regions.
    pub internal_types: Vec<Self>,
}

impl DissasmCodeInternalType {
    /// C++ `GetCurrentAsmLine`.
    #[must_use]
    pub const fn current_asm_line(&self) -> u32 {
        self.before_asm_lines.saturating_add(self.asm_lines_passed)
    }

    /// C++ `GetCurrentTextLine`.
    #[must_use]
    pub const fn current_text_line(&self) -> u32 {
        self.before_text_lines.saturating_add(self.text_lines_passed)
    }

    /// C++ `GetCurrentActualLine`.
    #[must_use]
    pub const fn current_actual_line(&self) -> u32 {
        self.current_asm_line().saturating_add(self.current_text_line())
    }

    /// C++ `GetSize` (`DissasmViewer.hpp:342-347`): the **working**
    /// span when collapsed, the current span otherwise.
    #[must_use]
    pub const fn size(&self) -> u32 {
        if self.is_collapsed {
            self.working_index_zone_end
                .saturating_sub(self.working_index_zone_start)
        } else {
            self.index_zone_end.saturating_sub(self.index_zone_start)
        }
    }

    /// C++ `GetNewAsmBeforeLines`.
    #[must_use]
    pub fn new_asm_before_lines(&self) -> u32 {
        self.size().saturating_sub(self.annotations.len() as u32)
    }

    /// C++ `UpdateDataLineFromPrevious` (`DissasmViewer.hpp:354-358`).
    pub fn update_data_line_from_previous(&mut self, prev: &Self) {
        self.before_text_lines = prev
            .before_text_lines
            .saturating_add(prev.annotations.len() as u32);
        self.before_asm_lines = prev
            .before_asm_lines
            .saturating_add(prev.new_asm_before_lines());
    }

    /// C++ `IsValidDataLine`.
    #[must_use]
    pub const fn is_valid_data_line(&self) -> bool {
        self.before_text_lines.saturating_add(self.before_asm_lines) == self.working_index_zone_start
    }
}

/// Structure zone (C++ `DissasmParseStructureZone`,
/// `DissasmViewer.hpp:107-114`; the recursive `types`/`levels`
/// iteration stacks are rebuilt by the structure drawer task).
#[derive(Clone, Debug)]
pub struct DissasmParseStructureZone {
    /// Common header (`zone_type` = `StructureParseZone`).
    pub zone: ParseZone,
    /// C++ `structureIndex` — iteration cursor.
    pub structure_index: i16,
    /// C++ `levels` — per-depth field indices.
    pub levels: Vec<i32>,
    /// C++ `textFileOffset` — current field file offset.
    pub text_file_offset: u64,
    /// C++ `initialTextFileOffset`.
    pub initial_text_file_offset: u64,
}

impl Default for DissasmParseStructureZone {
    fn default() -> Self {
        Self {
            zone: ParseZone::new(DissasmParseZoneType::StructureParseZone),
            structure_index: 0,
            levels: Vec::new(),
            text_file_offset: 0,
            initial_text_file_offset: 0,
        }
    }
}

/// C++ `CollapsibleAndTextData` (`DissasmViewer.hpp:116-121`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CollapsibleAndTextData {
    /// File offset of the text block.
    pub starting_offset: u64,
    /// Block size in bytes.
    pub size: u64,
    /// Whether Ctrl+E may collapse it.
    pub can_be_collapsed: bool,
}

/// Raw text zone (C++ `CollapsibleAndTextZone`,
/// `DissasmViewer.hpp:123-125`).
#[derive(Clone, Debug)]
pub struct CollapsibleAndTextZone {
    /// Common header (`zone_type` = `CollapsibleAndTextZone`).
    pub zone: ParseZone,
    /// Block descriptor.
    pub data: CollapsibleAndTextData,
}

impl Default for CollapsibleAndTextZone {
    fn default() -> Self {
        Self {
            zone: ParseZone::new(DissasmParseZoneType::CollapsibleAndTextZone),
            data: CollapsibleAndTextData::default(),
        }
    }
}

/// Disassembly zone (C++ `DissasmCodeZone`,
/// `DissasmCodeZone.hpp:7-47`; the pre-cache and offset table fields
/// are filled by their own tasks).
#[derive(Clone, Debug)]
pub struct DissasmCodeZone {
    /// Common header (`zone_type` = `DissasmCodeParseZone`).
    pub zone: ParseZone,
    /// Draw-loop optimization cursor (C++ `lastDrawnLine`).
    pub last_drawn_line: u32,
    /// C++ `lastClosestLine`.
    pub last_closest_line: u32,
    /// C++ `offsetCacheMaxLine`.
    pub offset_cache_max_line: u32,
    /// C++ `lastReachedLine` (starts `UINT32_MAX`).
    pub last_reached_line: u32,
    /// C++ `asmAddress` — current decode address (zone-relative).
    pub asm_address: u64,
    /// C++ `asmSize` — bytes remaining from `asm_address`.
    pub asm_size: u64,
    /// C++ `structureIndex`.
    pub structure_index: u32,
    /// C++ `levels` — nested-type iteration stack.
    pub levels: Vec<u32>,
    /// Root nested-region tree (C++ `dissasmType`).
    pub dissasm_type: DissasmCodeInternalType,
    /// Offset table anchors (C++ `cachedCodeOffsets`).
    pub cached_code_offsets: Vec<AsmOffsetLine>,
    /// The plugin-declared region (C++ `zoneDetails`).
    pub zone_details: DisassemblyZone,
    /// Capstone mode value (C++ `internalArchitecture`).
    pub internal_architecture: i32,
    /// C++ `isInit`.
    pub is_init: bool,
    /// C++ `changedLevel`.
    pub changed_level: bool,
}

impl Default for DissasmCodeZone {
    fn default() -> Self {
        Self {
            zone: ParseZone::new(DissasmParseZoneType::DissasmCodeParseZone),
            last_drawn_line: 0,
            last_closest_line: 0,
            offset_cache_max_line: 0,
            last_reached_line: u32::MAX,
            asm_address: 0,
            asm_size: 0,
            structure_index: 0,
            levels: Vec::new(),
            dissasm_type: DissasmCodeInternalType::default(),
            cached_code_offsets: Vec::new(),
            zone_details: DisassemblyZone::default(),
            internal_architecture: 0,
            is_init: false,
            changed_level: false,
        }
    }
}

/// One entry of `settings->parseZones` (C++ holds
/// `unique_ptr<ParseZone>` + the `zoneType` discriminator; Rust uses
/// a sum type).
#[derive(Clone, Debug)]
pub enum ZoneEntry {
    /// Typed data fields.
    Structure(DissasmParseStructureZone),
    /// Capstone instructions.
    Code(Box<DissasmCodeZone>),
    /// Raw text block.
    CollapsibleAndText(CollapsibleAndTextZone),
}

impl ZoneEntry {
    /// The common `ParseZone` header.
    #[must_use]
    pub const fn header(&self) -> &ParseZone {
        match self {
            Self::Structure(z) => &z.zone,
            Self::Code(z) => &z.zone,
            Self::CollapsibleAndText(z) => &z.zone,
        }
    }

    /// Mutable common header.
    pub const fn header_mut(&mut self) -> &mut ParseZone {
        match self {
            Self::Structure(z) => &mut z.zone,
            Self::Code(z) => &mut z.zone,
            Self::CollapsibleAndText(z) => &mut z.zone,
        }
    }
}

/// C++ `Instance::UpdateLayoutTotalLines` (`Instance.cpp:1169-1173`),
/// spec §3.1: `parseZones[last].endingLineIndex - 1`; zero when no
/// zones exist (`Layout.totalLinesSize` stays 0, `Instance.cpp:193`).
#[must_use]
pub fn total_lines(parse_zones: &[ZoneEntry]) -> u32 {
    parse_zones
        .last()
        .map_or(0, |z| z.header().ending_line_index.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_lines_formula_uses_last_zone() {
        let mut structure = DissasmParseStructureZone::default();
        structure.zone.start_line_index = 0;
        structure.zone.ending_line_index = 10;
        let mut code = DissasmCodeZone::default();
        code.zone.start_line_index = 10;
        code.zone.ending_line_index = 55;
        let zones = vec![
            ZoneEntry::Structure(structure),
            ZoneEntry::Code(Box::new(code)),
        ];
        // parseZones[last].endingLineIndex - 1.
        assert_eq!(total_lines(&zones), 54);
        // No zones → 0 (Layout.totalLinesSize initial value).
        assert_eq!(total_lines(&[]), 0);
    }

    #[test]
    fn zone_headers_carry_their_type_tags() {
        let zones = [
            ZoneEntry::Structure(DissasmParseStructureZone::default()),
            ZoneEntry::Code(Box::default()),
            ZoneEntry::CollapsibleAndText(CollapsibleAndTextZone::default()),
        ];
        assert_eq!(
            zones[0].header().zone_type,
            DissasmParseZoneType::StructureParseZone
        );
        assert_eq!(
            zones[1].header().zone_type,
            DissasmParseZoneType::DissasmCodeParseZone
        );
        assert_eq!(
            zones[2].header().zone_type,
            DissasmParseZoneType::CollapsibleAndTextZone
        );
    }

    #[test]
    fn code_zone_defaults_mirror_cpp() {
        let zone = DissasmCodeZone::default();
        assert_eq!(zone.last_reached_line, u32::MAX); // UINT32_MAX
        assert!(!zone.is_init);
        assert!(zone.cached_code_offsets.is_empty());
    }

    #[test]
    fn internal_type_size_depends_on_collapse_state() {
        let mut t = DissasmCodeInternalType {
            index_zone_start: 10,
            index_zone_end: 30,
            working_index_zone_start: 10,
            working_index_zone_end: 50,
            ..DissasmCodeInternalType::default()
        };
        // Expanded: current span.
        assert_eq!(t.size(), 20);
        // Collapsed: working span (GetSize, DissasmViewer.hpp:342).
        t.is_collapsed = true;
        assert_eq!(t.size(), 40);
    }

    #[test]
    fn internal_type_line_accounting_chains() {
        let mut prev = DissasmCodeInternalType {
            before_text_lines: 2,
            before_asm_lines: 5,
            index_zone_start: 7,
            index_zone_end: 17, // size 10
            ..DissasmCodeInternalType::default()
        };
        prev.annotations
            .mappings
            .insert(8, ("fn_one".to_owned(), 0x100));
        // new_asm_before_lines = size - annotations = 10 - 1 = 9.
        assert_eq!(prev.new_asm_before_lines(), 9);

        let mut next = DissasmCodeInternalType::default();
        next.update_data_line_from_previous(&prev);
        assert_eq!(next.before_text_lines, 3); // 2 + 1 annotation
        assert_eq!(next.before_asm_lines, 14); // 5 + 9
        next.working_index_zone_start = 17;
        assert!(next.is_valid_data_line()); // 3 + 14 == 17

        next.asm_lines_passed = 4;
        next.text_lines_passed = 1;
        assert_eq!(next.current_asm_line(), 18);
        assert_eq!(next.current_text_line(), 4);
        assert_eq!(next.current_actual_line(), 22);
    }

    #[test]
    fn comments_store_at_line_minus_one() {
        let mut comments = DissasmComments::default();
        comments.add_or_update_comment(5, "check this".to_owned());
        // C++ quirk: stored under 4, retrieved via line 5.
        assert!(comments.has_comment(5));
        assert_eq!(comments.get_comment(5), Some("check this"));
        assert_eq!(comments.iter().next().map(|(k, _)| *k), Some(4));
        assert!(!comments.has_comment(4));
        assert!(comments.remove_comment(5));
        assert!(!comments.remove_comment(5)); // C++ shows an error box
    }

    #[test]
    fn adjust_comments_offsets_shifts_and_drops() {
        let mut comments = DissasmComments::default();
        comments.add_or_update_comment(3, "low".to_owned()); // key 2
        comments.add_or_update_comment(10, "high".to_owned()); // key 9
        // Insert at stored line 5: keys >= 5 shift +1; keys below are
        // DROPPED by the C++ rebuild loop (intentional parity).
        comments.adjust_comments_offsets(5, true);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments.get_comment(11), Some("high"));
        // Removal shifts back down.
        comments.adjust_comments_offsets(5, false);
        assert_eq!(comments.get_comment(10), Some("high"));
    }
}
