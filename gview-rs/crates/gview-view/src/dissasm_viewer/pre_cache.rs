//! `DissasmViewer` asm line pre-cache — **not** an LRU
//! (spec `02_VIEWER_DISSASM` §5.1–§5.3).
//!
//! C++ anchors: `DissasmAsmPreCacheLine` / `DissasmAsmPreCacheData`
//! (`DissasmViewer.hpp:146-303`), paint lifecycle
//! (`DissasmX86.cpp:819-843`), Clear-vs-Reset dispatch
//! (`Instance.cpp:1340-1346`), mnemonic flag classification
//! (`DissasmX86.cpp:464-481`).
//!
//! The cache is a plain sequential buffer: one paint pass fills up to
//! `visibleRows` lines, then consumes them through `get_line`
//! (`cachedAsmLines[index++]`). When the viewport scrolled
//! (`Cursor.hasMovedView`) the next paint calls [`
//! DissasmAsmPreCacheData::clear`] and refills; otherwise
//! [`DissasmAsmPreCacheData::reset`] just rewinds `index` and the
//! lines are reused verbatim. `instruction_flags` survives `clear` —
//! only the line buffer is wiped (C++ `Clear`,
//! `DissasmViewer.hpp:278-287`).

use std::collections::HashMap;

/// C++ `CS_MNEMONIC_SIZE` (capstone) — mnemonic buffer cap.
pub const CS_MNEMONIC_SIZE: usize = 32;

/// C++ `DissasmAsmPreCacheLine::InstructionFlag`
/// (`DissasmViewer.hpp:147`).
pub mod instruction_flag {
    /// No classification.
    pub const NONE: u8 = 0x00;
    /// `call*` mnemonics.
    pub const CALL: u8 = 0x01;
    /// `push*` mnemonics.
    pub const PUSH: u8 = 0x02;
    /// `j*` mnemonics.
    pub const JMP: u8 = 0x04;
}

/// C++ `DissasmAsmPreCacheLine::LineArrowToDrawFlag`
/// (`DissasmViewer.hpp:149-159`) — jump arrow lanes.
pub mod line_arrow_flag {
    /// No arrows on this line.
    pub const NO_LINES: u8 = 0x00;
    /// Lane 1 vertical.
    pub const DRAW_LINE1: u8 = 0x01;
    /// Lane 2 vertical.
    pub const DRAW_LINE2: u8 = 0x02;
    /// Lane 3 vertical.
    pub const DRAW_LINE3: u8 = 0x04;
    /// Lane 4 vertical.
    pub const DRAW_LINE4: u8 = 0x08;
    /// Lane 5 vertical.
    pub const DRAW_LINE5: u8 = 0x10;
    /// Arrow start marker.
    pub const DRAW_STARTING_LINE: u8 = 0x20;
    /// Arrow end marker.
    pub const DRAW_ENDING_LINE: u8 = 0x40;
}

/// C++ mnemonic classification (`DissasmX86.cpp:464-481`).
///
/// The C++ switch compares the mnemonic's **first four bytes** to the
/// `pushOP`/`callOP` constants, so `pushf`/`pusha` classify as pushes
/// too (preserved); any other mnemonic starting with `j` is a jump;
/// everything else carries no flag.
#[must_use]
pub fn instruction_flag_for_mnemonic(mnemonic: &str) -> u8 {
    let bytes = mnemonic.as_bytes();
    match bytes.get(0..4) {
        Some(b"push") => instruction_flag::PUSH,
        Some(b"call") => instruction_flag::CALL,
        _ => {
            if bytes.first() == Some(&b'j') {
                instruction_flag::JMP
            } else {
                instruction_flag::NONE
            }
        }
    }
}

/// One cached, ready-to-paint asm line (C++ `DissasmAsmPreCacheLine`,
/// `DissasmViewer.hpp:146-225`).
///
/// The raw `op_str` pointer becomes an owned `String`, and the
/// `parent` internal-type pointer is resolved through the zone at
/// draw time instead of being stored.
#[derive(Clone, Debug, Default)]
pub struct DissasmAsmPreCacheLine {
    /// Instruction address.
    pub address: u64,
    /// Raw instruction bytes (capstone caps at 24).
    pub bytes: [u8; 24],
    /// Instruction byte length.
    pub size: u16,
    /// Document line this entry paints.
    pub current_line: u32,
    /// Capstone mnemonic.
    pub mnemonic: String,
    /// Capstone operand string.
    pub op_str: String,
    /// Extracted immediate operand (C++ `std::optional<uint64>`).
    pub hex_value: Option<u64>,
    /// [`instruction_flag`] bits.
    pub flags: u8,
    /// [`line_arrow_flag`] bits (filled by `PrepareLabelArrows`).
    pub line_arrow_to_draw: u8,
    /// Collapse toggle button marker.
    pub should_add_button: bool,
    /// Whether the owning zone region is collapsed.
    pub is_zone_collapsed: bool,
}

impl DissasmAsmPreCacheLine {
    /// C++ `GetLineSize` (`DissasmViewer.hpp:177-180`):
    /// `size * 2 + op_str_size`.
    #[must_use]
    pub fn line_size(&self) -> u32 {
        u32::from(self.size)
            .saturating_mul(2)
            .saturating_add(self.op_str.len() as u32)
    }
}

/// The sequential paint cache (C++ `DissasmAsmPreCacheData`,
/// `DissasmViewer.hpp:237-303`) — explicitly **not** an LRU: it holds
/// exactly the lines of the current viewport fill.
#[derive(Clone, Debug, Default)]
pub struct DissasmAsmPreCacheData {
    /// The cached lines in paint order.
    pub cached_asm_lines: Vec<DissasmAsmPreCacheLine>,
    /// Per-document-line [`instruction_flag`] bits — survives
    /// [`Self::clear`].
    pub instruction_flags: HashMap<u32, u8>,
    /// Sequential consume cursor (C++ `index`).
    pub index: u16,
    /// Max [`DissasmAsmPreCacheLine::line_size`] of the fill
    /// (comment column alignment).
    pub max_line_size: u32,
}

impl DissasmAsmPreCacheData {
    /// C++ `CheckInstructionHasFlag`.
    #[must_use]
    pub fn check_instruction_has_flag(&self, line: u32, flag: u8) -> bool {
        self.instruction_flags
            .get(&line)
            .is_some_and(|&bits| bits & flag > 0)
    }

    /// C++ `AddInstructionFlag` — ORs into the line's bits.
    pub fn add_instruction_flag(&mut self, line: u32, flag: u8) {
        *self.instruction_flags.entry(line).or_insert(0) |= flag;
    }

    /// C++ `HasAnyFlag`.
    #[must_use]
    pub fn has_any_flag(&self, line: u32) -> bool {
        self.instruction_flags
            .get(&line)
            .is_some_and(|&bits| bits > 0)
    }

    /// C++ `GetLine` (`DissasmViewer.hpp:261-266`): sequential
    /// consume — `cachedAsmLines[index++]`, `None` past the end.
    pub fn get_line(&mut self) -> Option<&mut DissasmAsmPreCacheLine> {
        let idx = usize::from(self.index);
        if idx >= self.cached_asm_lines.len() {
            return None;
        }
        self.index = self.index.saturating_add(1);
        self.cached_asm_lines.get_mut(idx)
    }

    /// C++ `ComputeMaxLine`.
    pub fn compute_max_line(&mut self) {
        self.max_line_size = self
            .cached_asm_lines
            .iter()
            .map(DissasmAsmPreCacheLine::line_size)
            .max()
            .unwrap_or(0);
    }

    /// C++ `Clear` (`DissasmViewer.hpp:278-287`): wipes the line
    /// buffer and counters; `instruction_flags` is deliberately kept.
    pub fn clear(&mut self) {
        self.cached_asm_lines.clear();
        self.index = 0;
        self.max_line_size = 0;
    }

    /// C++ `Reset` (`DissasmViewer.hpp:288-291`): rewinds the consume
    /// cursor only — the cached lines are reused.
    pub const fn reset(&mut self) {
        self.index = 0;
    }

    /// The paint-start dispatch (C++ `Instance::Paint`,
    /// `Instance.cpp:1340-1346`): a scrolled viewport invalidates the
    /// fill, an unmoved one merely rewinds.
    pub fn on_paint_start(&mut self, has_moved_view: bool) {
        if has_moved_view {
            self.clear();
        } else {
            self.reset();
        }
    }
}

/// The viewport fill plan (C++ `DissasmX86.cpp:820-824`).
///
/// Number of lines to prepare starting at `current_line`, clamped to
/// the viewport and to the zone's remaining lines
/// (`remaining = extendedSize - currentLine + 1`).
#[must_use]
pub fn lines_to_prepare(visible_rows: u32, extended_size: u32, current_line: u32) -> u32 {
    let mut lines = u32::min(visible_rows, extended_size);
    let remaining = extended_size.saturating_sub(current_line).saturating_add(1);
    lines = u32::min(lines, remaining);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(current_line: u32, size: u16, op_str: &str) -> DissasmAsmPreCacheLine {
        DissasmAsmPreCacheLine {
            current_line,
            size,
            op_str: op_str.to_owned(),
            ..DissasmAsmPreCacheLine::default()
        }
    }

    #[test]
    fn mnemonic_flags_call_push_j_prefix() {
        assert_eq!(instruction_flag_for_mnemonic("call"), instruction_flag::CALL);
        assert_eq!(instruction_flag_for_mnemonic("push"), instruction_flag::PUSH);
        // C++ compares only the first 4 bytes: pushf/pusha classify
        // as pushes too.
        assert_eq!(instruction_flag_for_mnemonic("pushf"), instruction_flag::PUSH);
        assert_eq!(instruction_flag_for_mnemonic("pushal"), instruction_flag::PUSH);
        // Any j* mnemonic is a jump.
        for jmp in ["jmp", "je", "jne", "jz", "jbe", "ja"] {
            assert_eq!(instruction_flag_for_mnemonic(jmp), instruction_flag::JMP);
        }
        // Everything else carries no flag.
        for other in ["mov", "add", "ret", "nop", "cal", "pus", ""] {
            assert_eq!(instruction_flag_for_mnemonic(other), instruction_flag::NONE);
        }
    }

    #[test]
    fn get_line_consumes_sequentially() {
        let mut cache = DissasmAsmPreCacheData::default();
        cache.cached_asm_lines.push(line(10, 2, "eax"));
        cache.cached_asm_lines.push(line(11, 3, "ebx"));
        assert_eq!(cache.get_line().map(|l| l.current_line), Some(10));
        assert_eq!(cache.get_line().map(|l| l.current_line), Some(11));
        // Past the end: None (C++ nullptr).
        assert!(cache.get_line().is_none());
    }

    #[test]
    fn clear_on_moved_view_reset_otherwise() {
        let mut cache = DissasmAsmPreCacheData::default();
        cache.cached_asm_lines.push(line(0, 2, "eax, ebx"));
        cache.add_instruction_flag(0, instruction_flag::CALL);
        cache.compute_max_line();
        assert!(cache.get_line().is_some());
        assert_eq!(cache.index, 1);

        // Unmoved view → Reset: lines kept, cursor rewound.
        cache.on_paint_start(false);
        assert_eq!(cache.index, 0);
        assert_eq!(cache.cached_asm_lines.len(), 1);
        assert_eq!(cache.max_line_size, 12); // 2*2 + 8

        // Moved view → Clear: lines and counters wiped...
        cache.get_line();
        cache.on_paint_start(true);
        assert!(cache.cached_asm_lines.is_empty());
        assert_eq!(cache.index, 0);
        assert_eq!(cache.max_line_size, 0);
        // ...but instruction flags survive (C++ Clear keeps them).
        assert!(cache.check_instruction_has_flag(0, instruction_flag::CALL));
    }

    #[test]
    fn instruction_flags_or_and_query() {
        let mut cache = DissasmAsmPreCacheData::default();
        assert!(!cache.has_any_flag(7));
        cache.add_instruction_flag(7, instruction_flag::PUSH);
        cache.add_instruction_flag(7, instruction_flag::JMP);
        assert!(cache.check_instruction_has_flag(7, instruction_flag::PUSH));
        assert!(cache.check_instruction_has_flag(7, instruction_flag::JMP));
        assert!(!cache.check_instruction_has_flag(7, instruction_flag::CALL));
        assert!(cache.has_any_flag(7));
        assert!(!cache.has_any_flag(8));
    }

    #[test]
    fn compute_max_line_uses_size_and_op_str() {
        let mut cache = DissasmAsmPreCacheData::default();
        cache.cached_asm_lines.push(line(0, 2, "eax")); // 4 + 3 = 7
        cache.cached_asm_lines.push(line(1, 5, "dword ptr [eax]")); // 10 + 15
        cache.compute_max_line();
        assert_eq!(cache.max_line_size, 25);
        cache.clear();
        cache.compute_max_line();
        assert_eq!(cache.max_line_size, 0);
    }

    #[test]
    fn fill_plan_clamps_to_viewport_and_remaining() {
        // Viewport smaller than the zone.
        assert_eq!(lines_to_prepare(25, 100, 0), 25);
        // Zone smaller than the viewport.
        assert_eq!(lines_to_prepare(25, 10, 0), 10);
        // Near the zone end: remaining = extended - current + 1.
        assert_eq!(lines_to_prepare(25, 100, 95), 6);
        assert_eq!(lines_to_prepare(25, 100, 100), 1);
    }
}
