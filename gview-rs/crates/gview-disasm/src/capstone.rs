//! `DissasemblerIntel` wrapper (spec `04_SERVICES` §6.1).
//!
//! C++ anchor: `DissasemblerIntel::Init` / `DissasembleInstruction` /
//! `DissasembleInstructions` / `GetInstructionGroupName`
//! (`Dissasembly.cpp:20-142`).
//!
//! The C++ code opens a capstone handle for the design/architecture
//! pair, ORs the endianness into the mode and always enables
//! `CS_OPT_DETAIL`. The Rust wrapper keeps that surface: `init`
//! records the target and resolves a backend — `iced-x86` for the
//! Intel x86/x64 pair under the default `disasm-iced` feature —
//! while ARM targets (capstone-only in C++) report
//! [`DisasmError::Unsupported`] until the capstone backend lands.
//! Decoded instructions are rendered capstone-style (lowercase,
//! `0x` hex prefix, `, ` operand separator) and classified into
//! [`X86Insn`] by mnemonic, with detail groups derived from the flow
//! control kind.

use crate::{
    Architecture, Design, DisasmError, Endianess, GroupType, Instruction, X86Insn, BYTES_SIZE,
    MNEMONIC_SIZE, OP_STR_SIZE,
};

/// `CS_OPT_DETAIL` value the C++ init always applies (`CS_OPT_ON`).
pub const CS_OPT_DETAIL_ON: bool = true;

/// C++ `DissasemblerIntel`.
#[derive(Debug, Default)]
pub struct DissasemblerIntel {
    design: Design,
    architecture: Architecture,
    endianess: Endianess,
    /// Decoder bitness once initialized (C++ `handle != 0`).
    bitness: Option<u32>,
    /// C++ `cs_option(CS_OPT_DETAIL, CS_OPT_ON)` — always on.
    detail: bool,
}

impl DissasemblerIntel {
    /// A closed disassembler (C++ default-constructed `handle = 0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            design: Design::Invalid,
            architecture: Architecture::Invalid,
            endianess: Endianess::Invalid,
            bitness: None,
            detail: false,
        }
    }

    /// C++ `Init(design, architecture, endianess)`
    /// (`Dissasembly.cpp:20-94`): re-initializing closes the previous
    /// handle first. Big-endian x86 is accepted (capstone ORs the
    /// flag in and ignores it for x86).
    ///
    /// # Errors
    ///
    /// [`DisasmError::Unsupported`] for `Invalid` values or targets
    /// without a backend (ARM under `disasm-iced`).
    pub const fn init(
        &mut self,
        design: Design,
        architecture: Architecture,
        endianess: Endianess,
    ) -> Result<(), DisasmError> {
        self.design = design;
        self.architecture = architecture;
        self.endianess = endianess;
        self.bitness = None;
        self.detail = false;
        let bitness = match (design, architecture) {
            (Design::Intel, Architecture::X86) if cfg!(feature = "disasm-iced") => 32,
            (Design::Intel, Architecture::X64) if cfg!(feature = "disasm-iced") => 64,
            _ => {
                return Err(DisasmError::Unsupported {
                    design,
                    architecture,
                })
            }
        };
        self.bitness = Some(bitness);
        self.detail = CS_OPT_DETAIL_ON;
        Ok(())
    }

    /// `true` once [`Self::init`] succeeded (C++ `handle != 0`).
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.bitness.is_some()
    }

    /// Whether detail (groups) is enabled — always after a successful
    /// init (C++ `CS_OPT_DETAIL = CS_OPT_ON`).
    #[must_use]
    pub const fn detail_enabled(&self) -> bool {
        self.detail
    }

    /// Configured design.
    #[must_use]
    pub const fn design(&self) -> Design {
        self.design
    }

    /// Configured architecture.
    #[must_use]
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Configured endianness.
    #[must_use]
    pub const fn endianess(&self) -> Endianess {
        self.endianess
    }

    /// C++ `DissasembleInstruction(buf, va, out)`
    /// (`Dissasembly.cpp:96-111`): decodes the single instruction at
    /// the buffer start.
    ///
    /// # Errors
    ///
    /// [`DisasmError::NotInitialized`], [`DisasmError::EmptyInput`],
    /// or [`DisasmError::InvalidInstruction`] when nothing decodes.
    pub fn disassemble_instruction(&self, buf: &[u8], va: u64) -> Result<Instruction, DisasmError> {
        let bitness = self.bitness.ok_or(DisasmError::NotInitialized)?;
        if buf.is_empty() {
            return Err(DisasmError::EmptyInput);
        }
        backend::decode_one(bitness, buf, va).ok_or(DisasmError::InvalidInstruction { address: va })
    }

    /// C++ `DissasembleInstructions(buf, va, out)`
    /// (`Dissasembly.cpp:113-129`): decodes until the first failure
    /// or the end of the buffer (a decode failure just stops, as
    /// `cs_disasm_iter` does).
    ///
    /// # Errors
    ///
    /// [`DisasmError::NotInitialized`] only.
    pub fn disassemble_instructions(&self, buf: &[u8], va: u64) -> Result<Vec<Instruction>, DisasmError> {
        let bitness = self.bitness.ok_or(DisasmError::NotInitialized)?;
        let mut out = Vec::new();
        let mut offset = 0_usize;
        let mut address = va;
        while let Some(rest) = buf.get(offset..) {
            if rest.is_empty() {
                break;
            }
            let Some(insn) = backend::decode_one(bitness, rest, address) else {
                break;
            };
            let size = usize::from(insn.size);
            if size == 0 {
                break;
            }
            offset = offset.saturating_add(size);
            address = address.saturating_add(u64::from(insn.size));
            out.push(insn);
        }
        Ok(out)
    }

    /// C++ `GetInstructionGroupName(groupID)` → `cs_group_name`
    /// (empty for unknown IDs).
    #[must_use]
    pub const fn instruction_group_name(group_id: u8) -> &'static str {
        match group_id {
            1 => GroupType::Jump.name(),
            2 => GroupType::Call.name(),
            3 => GroupType::Ret.name(),
            4 => GroupType::Int.name(),
            5 => GroupType::Iret.name(),
            6 => GroupType::Pivilege.name(),
            7 => GroupType::BranchRelative.name(),
            _ => "",
        }
    }
}

/// Builds the C++ `Instruction` image from decoded parts (shared by
/// backends): bytes are zero-padded to [`BYTES_SIZE`], strings are
/// truncated to the C++ buffer capacities.
fn build_instruction(
    address: u64,
    raw: &[u8],
    mnemonic: &str,
    op_str: &str,
    far: bool,
    groups: &[GroupType],
) -> Instruction {
    let mut bytes = [0_u8; BYTES_SIZE];
    let n = raw.len().min(BYTES_SIZE);
    if let (Some(dst), Some(src)) = (bytes.get_mut(..n), raw.get(..n)) {
        dst.copy_from_slice(src);
    }
    let mut group_slots = [GroupType::Invalid; 8];
    let count = groups.len().min(8);
    for (slot, group) in group_slots.iter_mut().zip(groups.iter()) {
        *slot = *group;
    }
    Instruction {
        id: X86Insn::from_mnemonic(mnemonic, far),
        address,
        size: raw.len() as u16,
        bytes,
        mnemonic: mnemonic.chars().take(MNEMONIC_SIZE.saturating_sub(1)).collect(),
        op_str: op_str.chars().take(OP_STR_SIZE.saturating_sub(1)).collect(),
        groups: group_slots,
        groups_count: count as u8,
    }
}

#[cfg(feature = "disasm-iced")]
mod backend {
    use super::build_instruction;
    use crate::{GroupType, Instruction};
    use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};

    fn capstone_style_formatter() -> IntelFormatter {
        let mut formatter = IntelFormatter::new();
        let options = formatter.options_mut();
        options.set_hex_prefix("0x");
        options.set_hex_suffix("");
        options.set_uppercase_hex(false);
        options.set_uppercase_mnemonics(false);
        options.set_uppercase_registers(false);
        options.set_space_after_operand_separator(true);
        options.set_branch_leading_zeros(false);
        options.set_leading_zeros(false);
        options.set_small_hex_numbers_in_decimal(false);
        options.set_add_leading_zero_to_hex_numbers(false);
        options.set_rip_relative_addresses(true);
        formatter
    }

    fn groups_for(instr: &iced_x86::Instruction) -> Vec<GroupType> {
        let mut groups = Vec::with_capacity(3);
        let near_branch = matches!(
            instr.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
        match instr.flow_control() {
            FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::ConditionalBranch => {
                groups.push(GroupType::Jump);
                if near_branch {
                    groups.push(GroupType::BranchRelative);
                }
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                groups.push(GroupType::Call);
                if near_branch {
                    groups.push(GroupType::BranchRelative);
                }
            }
            FlowControl::Return => groups.push(GroupType::Ret),
            FlowControl::Interrupt => groups.push(GroupType::Int),
            _ => {}
        }
        groups
    }

    /// Decodes one instruction at the buffer start; `None` when
    /// iced reports an invalid encoding.
    pub(super) fn decode_one(bitness: u32, buf: &[u8], va: u64) -> Option<Instruction> {
        let mut decoder = Decoder::with_ip(bitness, buf, va, DecoderOptions::NONE);
        let instr = decoder.decode();
        if instr.is_invalid() {
            return None;
        }
        let len = instr.len();
        let raw = buf.get(..len)?;
        let mut formatter = capstone_style_formatter();
        let mut mnemonic = String::new();
        formatter.format_mnemonic(&instr, &mut mnemonic);
        let mut op_str = String::new();
        formatter.format_all_operands(&instr, &mut op_str);
        let far = matches!(instr.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32);
        let mut groups = groups_for(&instr);
        let mnemonic_lower = mnemonic.trim().to_ascii_lowercase();
        if mnemonic_lower.starts_with("iret") {
            groups.push(GroupType::Iret);
        }
        Some(build_instruction(
            va,
            raw,
            &mnemonic_lower,
            op_str.trim(),
            far,
            &groups,
        ))
    }
}

#[cfg(not(feature = "disasm-iced"))]
mod backend {
    use crate::Instruction;

    /// No backend compiled in: nothing decodes.
    pub(super) fn decode_one(_bitness: u32, _buf: &[u8], _va: u64) -> Option<Instruction> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x64() -> DissasemblerIntel {
        let mut d = DissasemblerIntel::new();
        d.init(Design::Intel, Architecture::X64, Endianess::Little)
            .expect("x64 backend");
        d
    }

    #[test]
    fn init_records_target_and_enables_detail() {
        let d = x64();
        assert!(d.is_initialized());
        assert!(d.detail_enabled());
        assert_eq!(d.design(), Design::Intel);
        assert_eq!(d.architecture(), Architecture::X64);
        assert_eq!(d.endianess(), Endianess::Little);
        // Uninitialized: every decode fails.
        let closed = DissasemblerIntel::new();
        assert_eq!(
            closed.disassemble_instruction(&[0x90], 0),
            Err(DisasmError::NotInitialized)
        );
        assert!(!closed.detail_enabled());
    }

    #[test]
    fn unsupported_targets_are_rejected() {
        let mut d = DissasemblerIntel::new();
        assert!(matches!(
            d.init(Design::Arm, Architecture::X64, Endianess::Little),
            Err(DisasmError::Unsupported { .. })
        ));
        assert!(!d.is_initialized());
        assert!(matches!(
            d.init(Design::Invalid, Architecture::X86, Endianess::Little),
            Err(DisasmError::Unsupported { .. })
        ));
        assert!(matches!(
            d.init(Design::Intel, Architecture::Invalid, Endianess::Little),
            Err(DisasmError::Unsupported { .. })
        ));
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn nop_nop_decodes_and_invalid_errors() {
        let d = x64();
        let insns = d.disassemble_instructions(&[0x90, 0x90], 0x1000).unwrap();
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].mnemonic, "nop");
        assert_eq!(insns[0].size, 1);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].address, 0x1001);
        assert_eq!(insns[0].bytes[0], 0x90);
        // 0x06 (push es) is invalid in 64-bit mode.
        assert_eq!(
            d.disassemble_instruction(&[0x06], 0x2000),
            Err(DisasmError::InvalidInstruction { address: 0x2000 })
        );
        assert_eq!(d.disassemble_instruction(&[], 0), Err(DisasmError::EmptyInput));
        // A stream stops at the first invalid encoding.
        let insns = d.disassemble_instructions(&[0x90, 0x06, 0x90], 0).unwrap();
        assert_eq!(insns.len(), 1);
    }

    #[cfg(feature = "disasm-iced")]
    #[test]
    fn capstone_style_text_ids_and_groups() {
        let d = x64();
        // push rbp; mov rbp, rsp; sub rsp, 0x20; call +0; ret
        let code = [
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3,
        ];
        let insns = d.disassemble_instructions(&code, 0x0040_1000).unwrap();
        assert_eq!(insns.len(), 5);
        assert_eq!((insns[0].id, insns[0].op_str.as_str()), (X86Insn::Push, "rbp"));
        assert_eq!((insns[1].id, insns[1].op_str.as_str()), (X86Insn::Mov, "rbp, rsp"));
        assert_eq!((insns[2].id, insns[2].op_str.as_str()), (X86Insn::Sub, "rsp, 0x20"));
        assert_eq!(insns[3].id, X86Insn::Call);
        assert_eq!(insns[3].op_str, "0x40100d");
        assert!(insns[3].groups().contains(&GroupType::Call));
        assert!(insns[3].groups().contains(&GroupType::BranchRelative));
        assert_eq!(insns[4].id, X86Insn::Ret);
        assert_eq!(insns[4].groups(), &[GroupType::Ret]);
        // jmp short and int3
        let insns = d.disassemble_instructions(&[0xEB, 0xFE, 0xCC], 0).unwrap();
        assert_eq!(insns[0].id, X86Insn::Jmp);
        assert!(insns[0].groups().contains(&GroupType::Jump));
        assert_eq!(insns[1].id, X86Insn::Int3);
        assert_eq!(insns[1].groups(), &[GroupType::Int]);
        // 32-bit mode decodes push es.
        let mut d32 = DissasemblerIntel::new();
        d32.init(Design::Intel, Architecture::X86, Endianess::Little).unwrap();
        assert_eq!(d32.disassemble_instruction(&[0x06], 0).unwrap().mnemonic, "push");
    }

    #[test]
    fn group_names_match_capstone() {
        assert_eq!(DissasemblerIntel::instruction_group_name(1), "jump");
        assert_eq!(DissasemblerIntel::instruction_group_name(2), "call");
        assert_eq!(DissasemblerIntel::instruction_group_name(3), "ret");
        assert_eq!(DissasemblerIntel::instruction_group_name(7), "branch_relative");
        assert_eq!(DissasemblerIntel::instruction_group_name(0), "");
        assert_eq!(DissasemblerIntel::instruction_group_name(99), "");
    }
}
