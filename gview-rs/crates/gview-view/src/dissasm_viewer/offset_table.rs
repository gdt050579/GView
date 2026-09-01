//! `DissasmViewer` offset table construction
//! (spec `02_VIEWER_DISSASM` §4.1).
//!
//! C++ anchor: `populateOffsetsVector`
//! (`DissasmCodeZone.cpp:161-306`).
//!
//! Two phases:
//!
//! - **Phase A** scans forward from the entry point collecting the
//!   minimal in-zone jump/call target below it, repeatedly widening
//!   the window backwards until no lower target appears.
//! - **Phase B** disassembles forward from that minimal offset,
//!   pushing an [`AsmOffsetLine`] anchor whenever the decode address
//!   advances [`DISSASM_INSTRUCTION_OFFSET_MARGIN`] (500) bytes past
//!   the last anchor, and stopping after
//!   [`ADD_INSTRUCTIONS_STOP`] (30) consecutive `add byte ptr [...],
//!   al` padding instructions (their lines are subtracted back).
//!
//! Disassembly is abstracted behind [`AsmDecoder`], which mirrors the
//! `cs_disasm_iter` contract (advancing `address` and `size`); the
//! `dissasembler-capstone-init` task supplies the real adapter.
//! Operand parsing preserves the C++ quirks: hex digits accept
//! lowercase only, a decimal target below the zone start is rebased
//! by adding `startingZonePoint`, and any invalid digit resets the
//! parsed value to zero.

use super::zone::{AsmOffsetLine, DisassemblyZone};

/// C++ `DISSASM_INSTRUCTION_OFFSET_MARGIN` (spec §1.1).
pub const DISSASM_INSTRUCTION_OFFSET_MARGIN: u64 = 500;
/// C++ `addInstructionsStop` (`DissasmCodeZone.cpp:183`).
pub const ADD_INSTRUCTIONS_STOP: u32 = 30;

/// One decoded instruction (the `cs_insn` subset the offset table
/// needs).
#[derive(Clone, Debug)]
pub struct DecodedInsn {
    /// Instruction start (zone-relative), i.e. `insn->address`.
    pub address: u64,
    /// Instruction byte length.
    pub size: u16,
    /// Capstone mnemonic (e.g. `"call"`, `"jmp"`, `"add"`).
    pub mnemonic: String,
    /// Capstone operand string.
    pub op_str: String,
}

/// `cs_disasm_iter` contract (`DissasmCodeZone.cpp:212`).
///
/// Decodes one instruction at zone-relative `*address` while `*size`
/// bytes remain; on success both advance past the instruction.
/// `None` mirrors a decode failure or exhausted data.
pub trait AsmDecoder {
    /// Decodes the next instruction, advancing the cursor.
    fn disasm_iter(&mut self, address: &mut u64, size: &mut u64) -> Option<DecodedInsn>;
}

/// C++ jump/call detection (`DissasmCodeZone.cpp:215`): `j*` prefix or
/// the exact `call` mnemonic.
fn is_branch(mnemonic: &str) -> bool {
    mnemonic.starts_with('j') || mnemonic == "call"
}

/// Operand → branch target (`DissasmCodeZone.cpp:217-245`).
///
/// `op_str[1] == 'x'` selects hex parsing from index 2 (lowercase
/// `a-f` only — the C++ range check rejects uppercase); otherwise
/// decimal from index 0, rebased by `starting_zone_point` when below
/// it. An invalid digit zeroes the value and stops (C++ `break` after
/// `computedValue = 0`).
fn parse_branch_target(op_str: &str, starting_zone_point: u64) -> u64 {
    let bytes = op_str.as_bytes();
    let mut value: u64 = 0;
    if bytes.get(1) == Some(&b'x') {
        for &b in bytes.iter().skip(2) {
            if b == b' ' || b == b',' {
                break;
            }
            let digit = match b {
                b'0'..=b'9' => u64::from(b.saturating_sub(b'0')),
                b'a'..=b'f' => u64::from(b.saturating_sub(b'a')).saturating_add(10),
                _ => return 0,
            };
            value = value.saturating_mul(16).saturating_add(digit);
        }
    } else {
        for &b in bytes {
            if b == b' ' || b == b',' {
                break;
            }
            if !b.is_ascii_digit() {
                return 0;
            }
            value = value
                .saturating_mul(10)
                .saturating_add(u64::from(b.saturating_sub(b'0')));
        }
        if value < starting_zone_point {
            value = value.saturating_add(starting_zone_point);
        }
    }
    value
}

/// The `add byte ptr [...], al` padding detector
/// (`DissasmCodeZone.cpp:293`): mnemonic `add`, `op_str[0] == 'b'`
/// and the four bytes at `op_str[15]` equal `" al\0"` — i.e. the
/// operand string is exactly 18 chars ending in `" al"`.
fn is_padding_add(insn: &DecodedInsn) -> bool {
    insn.mnemonic == "add"
        && insn.op_str.as_bytes().first() == Some(&b'b')
        && insn.op_str.len() == 18
        && insn.op_str.ends_with(" al")
}

/// C++ `populateOffsetsVector` (`DissasmCodeZone.cpp:161-306`).
///
/// Fills `offsets` with `{file offset, zone line}` anchors spaced at
/// least [`DISSASM_INSTRUCTION_OFFSET_MARGIN`] bytes apart and sets
/// `total_lines` to the decoded line count. Returns `false` when the
/// entry point lies outside the zone (C++ `address >= endAddress`).
///
/// The decoder is restarted for each phase via `AsmDecoder` cursor
/// resets — the C++ code re-points `data`/`address` the same way.
#[allow(clippy::similar_names)] // address/end_address mirror the C++ names
pub fn populate_offsets_vector(
    offsets: &mut Vec<AsmOffsetLine>,
    zone_details: &DisassemblyZone,
    decoder: &mut dyn AsmDecoder,
    total_lines: &mut u32,
) -> bool {
    if offsets.is_empty() {
        offsets.push(AsmOffsetLine {
            offset: zone_details.entry_point,
            line: 0,
        });
    }

    let start_point = zone_details.starting_zone_point;
    let first_offset = offsets.first().map_or(zone_details.entry_point, |o| o.offset);
    let mut minimal_value = first_offset;
    let mut last_offset = first_offset;

    let Some(mut address) = zone_details.entry_point.checked_sub(start_point) else {
        return false;
    };
    let mut end_address = zone_details.size;
    if address >= end_address {
        return false;
    }
    // C++ `size` starts as startingZonePoint + size (absolute end) —
    // an over-generous byte budget; preserved.
    let mut size = start_point.saturating_add(zone_details.size);
    let mut starting_offset = first_offset;

    // Phase A — find the minimal backward jump/call target.
    loop {
        while address < end_address {
            let Some(insn) = decoder.disasm_iter(&mut address, &mut size) else {
                break;
            };
            if is_branch(&insn.mnemonic) {
                let computed = parse_branch_target(&insn.op_str, start_point);
                if computed < minimal_value && computed >= start_point {
                    minimal_value = computed;
                }
            }
            let adjusted = address.saturating_add(start_point);
            if adjusted.saturating_sub(last_offset) >= DISSASM_INSTRUCTION_OFFSET_MARGIN {
                last_offset = adjusted;
            }
        }
        if minimal_value >= starting_offset {
            break;
        }
        let zone_size_to_analyze = starting_offset.saturating_sub(minimal_value);
        address = minimal_value.saturating_sub(start_point);
        end_address = zone_size_to_analyze.saturating_add(address);
        size = address.saturating_add(zone_size_to_analyze);
        last_offset = minimal_value;
        starting_offset = minimal_value;
    }

    // Phase B — forward disassembly from the minimal offset.
    size = zone_details.size;
    address = minimal_value.saturating_sub(start_point);
    let mut last_offset = address; // zone-relative here (C++ L276)
    let mut line_index: u32 = 0;
    offsets.clear();
    offsets.push(AsmOffsetLine {
        offset: minimal_value,
        line: 0,
    });
    let mut continuous_add_instructions: u32 = 0;

    while let Some(insn) = decoder.disasm_iter(&mut address, &mut size) {
        line_index = line_index.saturating_add(1);
        if address.saturating_sub(last_offset) >= DISSASM_INSTRUCTION_OFFSET_MARGIN {
            last_offset = address;
            offsets.push(AsmOffsetLine {
                offset: address.saturating_add(start_point),
                line: line_index,
            });
        }
        if is_padding_add(&insn) {
            continuous_add_instructions = continuous_add_instructions.saturating_add(1);
            if continuous_add_instructions == ADD_INSTRUCTIONS_STOP {
                line_index = line_index.saturating_sub(continuous_add_instructions);
                break;
            }
        } else {
            continuous_add_instructions = 0;
        }
    }

    *total_lines = line_index;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Mock decoder over an instruction table keyed by zone-relative
    /// address; honours the `cs_disasm_iter` advance contract.
    struct MockDecoder {
        insns: BTreeMap<u64, DecodedInsn>,
    }

    impl MockDecoder {
        fn new(insns: Vec<DecodedInsn>) -> Self {
            Self {
                insns: insns.into_iter().map(|i| (i.address, i)).collect(),
            }
        }
    }

    impl AsmDecoder for MockDecoder {
        fn disasm_iter(&mut self, address: &mut u64, size: &mut u64) -> Option<DecodedInsn> {
            let insn = self.insns.get(address)?.clone();
            let len = u64::from(insn.size);
            if *size < len {
                return None;
            }
            *address = address.saturating_add(len);
            *size = size.saturating_sub(len);
            Some(insn)
        }
    }

    fn nop(address: u64, size: u16) -> DecodedInsn {
        DecodedInsn {
            address,
            size,
            mnemonic: "nop".to_owned(),
            op_str: String::new(),
        }
    }

    fn pad_add(address: u64) -> DecodedInsn {
        DecodedInsn {
            address,
            size: 2,
            // 18-char op_str ending in " al" (C++ byte-15 check).
            mnemonic: "add".to_owned(),
            op_str: "byte ptr [eax], al".to_owned(),
        }
    }

    /// `count` nops of `step` bytes from `start`.
    fn linear_nops(start: u64, step: u16, count: u64) -> Vec<DecodedInsn> {
        (0..count)
            .map(|i| nop(start.saturating_add(i.saturating_mul(u64::from(step))), step))
            .collect()
    }

    #[test]
    fn margin_500_anchors_every_500_bytes() {
        // Zone at file offset 1000, 1100 bytes, entry at start.
        // 110 nops x 10 bytes: anchors when the advanced address
        // crosses 500-byte steps → lines 50 and 100.
        let zone = DisassemblyZone {
            starting_zone_point: 1000,
            size: 1100,
            entry_point: 1000,
            ..DisassemblyZone::default()
        };
        let mut decoder = MockDecoder::new(linear_nops(0, 10, 110));
        let mut offsets = Vec::new();
        let mut total = 0;
        assert!(populate_offsets_vector(
            &mut offsets,
            &zone,
            &mut decoder,
            &mut total
        ));
        assert_eq!(total, 110);
        assert_eq!(
            offsets,
            vec![
                AsmOffsetLine {
                    offset: 1000,
                    line: 0
                },
                AsmOffsetLine {
                    offset: 1500,
                    line: 50
                },
                AsmOffsetLine {
                    offset: 2000,
                    line: 100
                },
            ]
        );
    }

    #[test]
    fn thirty_consecutive_pad_adds_stop_decoding() {
        // 5 nops then 35 padding adds: decoding stops at the 30th
        // pad and subtracts those lines (spec §4.1 Phase B).
        let mut insns = linear_nops(0, 2, 5);
        for i in 0..35_u64 {
            insns.push(pad_add(10 + i * 2));
        }
        let zone = DisassemblyZone {
            starting_zone_point: 0,
            size: 200,
            entry_point: 0,
            ..DisassemblyZone::default()
        };
        let mut decoder = MockDecoder::new(insns);
        let mut offsets = Vec::new();
        let mut total = 0;
        assert!(populate_offsets_vector(
            &mut offsets,
            &zone,
            &mut decoder,
            &mut total
        ));
        // 5 nops + 30 pads decoded, minus the 30 pads.
        assert_eq!(total, 5);
    }

    #[test]
    fn pad_run_broken_by_other_instruction_resets_counter() {
        // 29 pads, one nop, 29 pads → never hits 30, all lines kept.
        let mut insns = Vec::new();
        let mut addr = 0_u64;
        for _ in 0..29 {
            insns.push(pad_add(addr));
            addr += 2;
        }
        insns.push(nop(addr, 2));
        addr += 2;
        for _ in 0..29 {
            insns.push(pad_add(addr));
            addr += 2;
        }
        let zone = DisassemblyZone {
            starting_zone_point: 0,
            size: 200,
            entry_point: 0,
            ..DisassemblyZone::default()
        };
        let mut decoder = MockDecoder::new(insns);
        let mut offsets = Vec::new();
        let mut total = 0;
        populate_offsets_vector(&mut offsets, &zone, &mut decoder, &mut total);
        assert_eq!(total, 59);
    }

    #[test]
    fn backward_branch_target_rebases_the_table() {
        // Entry at 1050 (file) with a jmp back to 0x3F2 (=1010):
        // Phase A finds 1010, Phase B rebuilds the table from there.
        let zone = DisassemblyZone {
            starting_zone_point: 1000,
            size: 100,
            entry_point: 1050,
            ..DisassemblyZone::default()
        };
        let mut insns = linear_nops(10, 5, 8); // 1010..1050 zone-rel 10..50
        insns.push(DecodedInsn {
            address: 50,
            size: 2,
            mnemonic: "jmp".to_owned(),
            op_str: "0x3f2".to_owned(), // 1010
        });
        insns.push(nop(52, 2));
        let mut decoder = MockDecoder::new(insns);
        let mut offsets = Vec::new();
        let mut total = 0;
        assert!(populate_offsets_vector(
            &mut offsets,
            &zone,
            &mut decoder,
            &mut total
        ));
        assert_eq!(offsets.first(), Some(&AsmOffsetLine { offset: 1010, line: 0 }));
        // 8 nops + jmp + trailing nop from 1010.
        assert_eq!(total, 10);
    }

    #[test]
    fn decimal_target_below_zone_start_is_rebased() {
        // C++ decimal parse: value < startingZonePoint → += it.
        assert_eq!(parse_branch_target("16", 1000), 1016);
        assert_eq!(parse_branch_target("2000", 1000), 2000);
        // Hex parse is not rebased and rejects uppercase digits.
        assert_eq!(parse_branch_target("0x3f2", 0), 0x3f2);
        assert_eq!(parse_branch_target("0x3F2", 0), 0);
        // Invalid decimal digit zeroes the value.
        assert_eq!(parse_branch_target("eax", 1000), 0);
        // Parsing stops at ',' and ' '.
        assert_eq!(parse_branch_target("0x10, eax", 0), 0x10);
    }

    #[test]
    fn entry_point_outside_zone_fails() {
        let zone = DisassemblyZone {
            starting_zone_point: 1000,
            size: 50,
            entry_point: 1050, // == end → address >= endAddress
            ..DisassemblyZone::default()
        };
        let mut decoder = MockDecoder::new(Vec::new());
        let mut offsets = Vec::new();
        let mut total = 0;
        assert!(!populate_offsets_vector(
            &mut offsets,
            &zone,
            &mut decoder,
            &mut total
        ));
        // Entry below the zone start also fails (checked_sub guard).
        let zone = DisassemblyZone {
            starting_zone_point: 1000,
            size: 50,
            entry_point: 500,
            ..DisassemblyZone::default()
        };
        assert!(!populate_offsets_vector(
            &mut offsets,
            &zone,
            &mut decoder,
            &mut total
        ));
    }
}
