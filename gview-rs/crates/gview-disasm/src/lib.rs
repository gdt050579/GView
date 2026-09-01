//! `GView` disassembly engine (spec `04_SERVICES_CRYPTO_AND_DISASM`
//! §6).
//!
//! Port of `GViewCore/src/Dissasembly/Dissasembly.cpp`: the
//! `DissasemblerIntel` wrapper ([`capstone`], backed by `iced-x86`
//! under the default `disasm-iced` feature) and the instruction
//! heuristics ([`heuristics`]) used by the `BufferViewer` dissasm
//! dialog. Instruction identities are expressed as [`X86Insn`], a
//! backend-neutral subset of the capstone `X86_INS_*` IDs the
//! heuristics switch on.

#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]

pub mod capstone;
pub mod heuristics;

pub use heuristics::X86Insn;

/// C++ `Dissasembly::Opcodes` bitmask (`GView.hpp:816`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Opcodes {
    /// Function header.
    Header = 1,
    /// `call`.
    Call = 2,
    /// `jmp`.
    Jmp = 8,
    /// `int*`.
    Breakpoint = 32,
    /// Prologue pattern.
    FunctionStart = 64,
    /// `ret*`.
    FunctionEnd = 128,
    /// Everything.
    All = 0xFFFF_FFFF,
}

/// C++ `Dissasembly::GroupType` (mirrors capstone `cs_group_type`;
/// the `Pivilege` typo is preserved).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum GroupType {
    /// No group.
    #[default]
    Invalid = 0,
    /// Jump.
    Jump = 1,
    /// Call.
    Call = 2,
    /// Return.
    Ret = 3,
    /// Interrupt.
    Int = 4,
    /// Interrupt return.
    Iret = 5,
    /// Privileged (C++ `Pivilege`).
    Pivilege = 6,
    /// Relative branch.
    BranchRelative = 7,
}

impl GroupType {
    /// C++ `GetInstructionGroupName` → capstone `cs_group_name`
    /// (empty for `Invalid`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Invalid => "",
            Self::Jump => "jump",
            Self::Call => "call",
            Self::Ret => "ret",
            Self::Int => "int",
            Self::Iret => "iret",
            Self::Pivilege => "privilege",
            Self::BranchRelative => "branch_relative",
        }
    }
}

/// C++ `Dissasembly::Architecture`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Architecture {
    /// Not set.
    #[default]
    Invalid = 0,
    /// 32-bit.
    X86 = 1,
    /// 64-bit.
    X64 = 2,
}

/// C++ `Dissasembly::Design`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Design {
    /// Not set.
    #[default]
    Invalid = 0,
    /// Intel / AMD.
    Intel = 1,
    /// ARM (`CS_ARCH_ARM` / `CS_ARCH_ARM64`).
    Arm = 2,
}

/// C++ `Dissasembly::Endianess`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Endianess {
    /// Not set.
    #[default]
    Invalid = 0,
    /// Little-endian.
    Little = 1,
    /// Big-endian.
    Big = 2,
}

/// C++ `BYTES_SIZE`.
pub const BYTES_SIZE: usize = 24;
/// C++ `MNEMONIC_SIZE`.
pub const MNEMONIC_SIZE: usize = 32;
/// C++ `OP_STR_SIZE`.
pub const OP_STR_SIZE: usize = 160;

/// C++ `Dissasembly::Instruction` ("inspired" by `cs_insn` +
/// `cs_detail`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    /// Backend-neutral instruction identity (C++ `id`).
    pub id: X86Insn,
    /// Virtual address.
    pub address: u64,
    /// Length in bytes.
    pub size: u16,
    /// Raw bytes (zero-padded to [`BYTES_SIZE`]).
    pub bytes: [u8; BYTES_SIZE],
    /// Mnemonic (capped at [`MNEMONIC_SIZE`] - 1 chars like the C++
    /// buffer).
    pub mnemonic: String,
    /// Operand string (capped at [`OP_STR_SIZE`] - 1 chars).
    pub op_str: String,
    /// Detail groups (up to 8).
    pub groups: [GroupType; 8],
    /// Valid entries in `groups`.
    pub groups_count: u8,
}

impl Default for Instruction {
    fn default() -> Self {
        Self {
            id: X86Insn::Other,
            address: 0,
            size: 0,
            bytes: [0; BYTES_SIZE],
            mnemonic: String::new(),
            op_str: String::new(),
            groups: [GroupType::Invalid; 8],
            groups_count: 0,
        }
    }
}

impl Instruction {
    /// The populated group slice.
    #[must_use]
    pub fn groups(&self) -> &[GroupType] {
        let n = usize::from(self.groups_count).min(self.groups.len());
        self.groups.get(..n).unwrap_or(&[])
    }
}

/// Disassembler errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisasmError {
    /// `Init` was not called (C++ `CHECK(handle != 0)`).
    NotInitialized,
    /// The design/architecture pair has no backend (ARM without the
    /// capstone feature, or `Invalid` values).
    Unsupported {
        /// Requested design.
        design: Design,
        /// Requested architecture.
        architecture: Architecture,
    },
    /// No instruction could be decoded at the buffer start
    /// (`cs_disasm_iter` returned `false`).
    InvalidInstruction {
        /// Address of the failed decode.
        address: u64,
    },
    /// The input buffer is empty.
    EmptyInput,
}

impl core::fmt::Display for DisasmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotInitialized => write!(f, "disassembler not initialized"),
            Self::Unsupported {
                design,
                architecture,
            } => write!(f, "unsupported target {design:?}/{architecture:?}"),
            Self::InvalidInstruction { address } => {
                write!(f, "invalid instruction at {address:#x}")
            }
            Self::EmptyInput => write!(f, "empty input buffer"),
        }
    }
}

impl std::error::Error for DisasmError {}
