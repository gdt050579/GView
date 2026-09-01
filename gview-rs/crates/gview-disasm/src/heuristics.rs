//! Intel instruction heuristics (spec `04_SERVICES` §6.2,
//! `02_VIEWER_DISSASM` §2.1).
//!
//! C++ anchor: `DissasemblerIntel::Is*Instruction` /
//! `AreFunctionStartInstructions` / `IsFunctionEndInstruction`
//! (`Dissasembly.cpp:143-288`).
//!
//! The predicates switch on capstone `X86_INS_*` IDs; [`X86Insn`]
//! names exactly the IDs those switches mention (everything else is
//! [`X86Insn::Other`]), so the heuristics stay independent of the
//! decoder backend. Note the C++ function-start rule checks the
//! **stack pointer** operand (`rsp`/`esp`), not `rbp`: `push rbp; mov
//! rbp, rsp` is *not* a function start for this API (the viewer's own
//! deep-scan uses the `push ebp` pattern instead — §2.2).

use crate::{Architecture, Instruction};

/// Backend-neutral instruction identities — the capstone
/// `X86_INS_*` values referenced by `Dissasembly.cpp`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // 1:1 capstone ID names
pub enum X86Insn {
    #[default]
    Other,
    Call,
    Lcall,
    Jmp,
    Ljmp,
    Int,
    Int1,
    Int3,
    Into,
    Ret,
    Retf,
    Retfq,
    Sysret,
    Sysretq,
    Push,
    Pushaw,
    Pushal,
    Pushf,
    Pushfd,
    Pushfq,
    Sub,
    Subpd,
    Subps,
    Fsubr,
    Fisubr,
    Fsubrp,
    Subsd,
    Subss,
    Fsub,
    Fisub,
    Fsubp,
    Endbr64,
    Endbr32,
    Mov,
    Movabs,
    Movapd,
    Movaps,
    Movbe,
    Movddup,
    Movdir64b,
    Movdiri,
    Movdqa,
    Movdqu,
    Movhlps,
    Movhpd,
    Movhps,
    Movlhps,
    Movlpd,
    Movlps,
    Movmskpd,
    Movmskps,
    Movntdqa,
    Movntdq,
    Movnti,
    Movntpd,
    Movntps,
    Movntsd,
    Movntss,
    Movsb,
    Movsd,
    Movshdup,
    Movsldup,
    Movsq,
    Movss,
    Movsw,
    Movsx,
    Movsxd,
    Movupd,
    Movups,
    Movzx,
}

impl X86Insn {
    /// Maps a capstone-style mnemonic string to its identity (used by
    /// the decoder adapter; `far` selects `Lcall`/`Ljmp`). Capstone
    /// spellings and the iced-x86 aliases (`pusha`/`pushad`) are both
    /// accepted.
    #[must_use]
    pub fn from_mnemonic(mnemonic: &str, far: bool) -> Self {
        match mnemonic {
            "call" => {
                if far {
                    Self::Lcall
                } else {
                    Self::Call
                }
            }
            "lcall" => Self::Lcall,
            "jmp" => {
                if far {
                    Self::Ljmp
                } else {
                    Self::Jmp
                }
            }
            "ljmp" => Self::Ljmp,
            "int" => Self::Int,
            "int1" | "icebp" => Self::Int1,
            "int3" => Self::Int3,
            "into" => Self::Into,
            "ret" | "retn" => Self::Ret,
            "retf" => Self::Retf,
            "retfq" => Self::Retfq,
            "sysret" => Self::Sysret,
            "sysretq" => Self::Sysretq,
            "push" => Self::Push,
            "pushaw" | "pusha" => Self::Pushaw,
            "pushal" | "pushad" => Self::Pushal,
            "pushf" => Self::Pushf,
            "pushfd" => Self::Pushfd,
            "pushfq" => Self::Pushfq,
            "sub" => Self::Sub,
            "subpd" => Self::Subpd,
            "subps" => Self::Subps,
            "fsubr" => Self::Fsubr,
            "fisubr" => Self::Fisubr,
            "fsubrp" => Self::Fsubrp,
            "subsd" => Self::Subsd,
            "subss" => Self::Subss,
            "fsub" => Self::Fsub,
            "fisub" => Self::Fisub,
            "fsubp" => Self::Fsubp,
            "endbr64" => Self::Endbr64,
            "endbr32" => Self::Endbr32,
            "mov" => Self::Mov,
            "movabs" => Self::Movabs,
            "movapd" => Self::Movapd,
            "movaps" => Self::Movaps,
            "movbe" => Self::Movbe,
            "movddup" => Self::Movddup,
            "movdir64b" => Self::Movdir64b,
            "movdiri" => Self::Movdiri,
            "movdqa" => Self::Movdqa,
            "movdqu" => Self::Movdqu,
            "movhlps" => Self::Movhlps,
            "movhpd" => Self::Movhpd,
            "movhps" => Self::Movhps,
            "movlhps" => Self::Movlhps,
            "movlpd" => Self::Movlpd,
            "movlps" => Self::Movlps,
            "movmskpd" => Self::Movmskpd,
            "movmskps" => Self::Movmskps,
            "movntdqa" => Self::Movntdqa,
            "movntdq" => Self::Movntdq,
            "movnti" => Self::Movnti,
            "movntpd" => Self::Movntpd,
            "movntps" => Self::Movntps,
            "movntsd" => Self::Movntsd,
            "movntss" => Self::Movntss,
            "movsb" => Self::Movsb,
            "movsd" => Self::Movsd,
            "movshdup" => Self::Movshdup,
            "movsldup" => Self::Movsldup,
            "movsq" => Self::Movsq,
            "movss" => Self::Movss,
            "movsw" => Self::Movsw,
            "movsx" => Self::Movsx,
            "movsxd" => Self::Movsxd,
            "movupd" => Self::Movupd,
            "movups" => Self::Movups,
            "movzx" => Self::Movzx,
            _ => Self::Other,
        }
    }
}

/// C++ `IsCallInstruction`: `id == X86_INS_CALL`.
#[must_use]
pub fn is_call_instruction(instruction: &Instruction) -> bool {
    instruction.id == X86Insn::Call
}

/// C++ `IsLCallInstruction`: `id == X86_INS_LCALL`.
#[must_use]
pub fn is_lcall_instruction(instruction: &Instruction) -> bool {
    instruction.id == X86Insn::Lcall
}

/// C++ `IsJmpInstruction`: `id == X86_INS_JMP`.
#[must_use]
pub fn is_jmp_instruction(instruction: &Instruction) -> bool {
    instruction.id == X86Insn::Jmp
}

/// C++ `IsLJmpInstruction`: `id == X86_INS_LJMP`.
#[must_use]
pub fn is_ljmp_instruction(instruction: &Instruction) -> bool {
    instruction.id == X86Insn::Ljmp
}

/// C++ `IsBreakpointInstruction`: `INT`, `INT1`, `INT3`, `INTO`.
#[must_use]
pub const fn is_breakpoint_instruction(instruction: &Instruction) -> bool {
    matches!(
        instruction.id,
        X86Insn::Int | X86Insn::Int1 | X86Insn::Int3 | X86Insn::Into
    )
}

/// C++ `IsFunctionEndInstruction`: `RET`, `RETF`, `RETFQ`, `SYSRET`,
/// `SYSRETQ` (the `IRET*` cases are commented out in C++).
#[must_use]
pub const fn is_function_end_instruction(instruction: &Instruction) -> bool {
    matches!(
        instruction.id,
        X86Insn::Ret | X86Insn::Retf | X86Insn::Retfq | X86Insn::Sysret | X86Insn::Sysretq
    )
}

const fn is_push_family(id: X86Insn) -> bool {
    matches!(
        id,
        X86Insn::Push
            | X86Insn::Pushaw
            | X86Insn::Pushal
            | X86Insn::Pushf
            | X86Insn::Pushfd
            | X86Insn::Pushfq
    )
}

const fn is_sub_family(id: X86Insn) -> bool {
    matches!(
        id,
        X86Insn::Sub
            | X86Insn::Subpd
            | X86Insn::Subps
            | X86Insn::Fsubr
            | X86Insn::Fisubr
            | X86Insn::Fsubrp
            | X86Insn::Subsd
            | X86Insn::Subss
            | X86Insn::Fsub
            | X86Insn::Fisub
            | X86Insn::Fsubp
    )
}

const fn is_mov_family(id: X86Insn) -> bool {
    matches!(
        id,
        X86Insn::Mov
            | X86Insn::Movabs
            | X86Insn::Movapd
            | X86Insn::Movaps
            | X86Insn::Movbe
            | X86Insn::Movddup
            | X86Insn::Movdir64b
            | X86Insn::Movdiri
            | X86Insn::Movdqa
            | X86Insn::Movdqu
            | X86Insn::Movhlps
            | X86Insn::Movhpd
            | X86Insn::Movhps
            | X86Insn::Movlhps
            | X86Insn::Movlpd
            | X86Insn::Movlps
            | X86Insn::Movmskpd
            | X86Insn::Movmskps
            | X86Insn::Movntdqa
            | X86Insn::Movntdq
            | X86Insn::Movnti
            | X86Insn::Movntpd
            | X86Insn::Movntps
            | X86Insn::Movntsd
            | X86Insn::Movntss
            | X86Insn::Movsb
            | X86Insn::Movsd
            | X86Insn::Movshdup
            | X86Insn::Movsldup
            | X86Insn::Movsq
            | X86Insn::Movss
            | X86Insn::Movsw
            | X86Insn::Movsx
            | X86Insn::Movsxd
            | X86Insn::Movupd
            | X86Insn::Movups
            | X86Insn::Movzx
    )
}

/// The stack-pointer operand check shared by the push/sub patterns:
/// `opStr` must start with `rsp` (x64) or `esp` (x86).
fn stack_pointer_operand(architecture: Architecture, op_str: &str) -> bool {
    if architecture == Architecture::X64 {
        op_str.starts_with("rsp")
    } else {
        op_str.starts_with("esp")
    }
}

/// C++ `AreFunctionStartInstructions` (`Dissasembly.cpp:180-269`).
///
/// - `PUSH*` with an `rsp`/`esp` operand followed by any `MOV*`;
/// - `SUB*` (incl. the x87 forms) with an `rsp`/`esp` operand;
/// - `ENDBR64`/`ENDBR32` not followed by `RET`.
#[must_use]
pub fn are_function_start_instructions(
    architecture: Architecture,
    instruction1: &Instruction,
    instruction2: &Instruction,
) -> bool {
    if is_push_family(instruction1.id) {
        return stack_pointer_operand(architecture, &instruction1.op_str)
            && is_mov_family(instruction2.id);
    }
    if is_sub_family(instruction1.id) {
        return stack_pointer_operand(architecture, &instruction1.op_str);
    }
    if matches!(instruction1.id, X86Insn::Endbr64 | X86Insn::Endbr32) {
        return instruction2.id != X86Insn::Ret;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(id: X86Insn, op_str: &str) -> Instruction {
        Instruction {
            id,
            op_str: op_str.to_owned(),
            ..Instruction::default()
        }
    }

    #[test]
    fn endbr_followed_by_ret_is_not_a_start() {
        let endbr = insn(X86Insn::Endbr64, "");
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &endbr,
            &insn(X86Insn::Ret, "")
        ));
        assert!(are_function_start_instructions(
            Architecture::X64,
            &endbr,
            &insn(X86Insn::Other, "")
        ));
        assert!(are_function_start_instructions(
            Architecture::X86,
            &insn(X86Insn::Endbr32, ""),
            &insn(X86Insn::Mov, "eax, ebx")
        ));
    }

    #[test]
    fn push_stack_pointer_then_mov_is_a_start() {
        // The C++ predicate requires the rsp/esp operand on the push.
        assert!(are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Push, "rsp"),
            &insn(X86Insn::Mov, "rbp, rsp")
        ));
        assert!(are_function_start_instructions(
            Architecture::X86,
            &insn(X86Insn::Pushfd, "esp"),
            &insn(X86Insn::Movaps, "xmm0, xmm1")
        ));
        // `push rbp; mov rbp, rsp` does NOT satisfy the C++ rule.
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Push, "rbp"),
            &insn(X86Insn::Mov, "rbp, rsp")
        ));
        // Wrong register width for the architecture.
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Push, "esp"),
            &insn(X86Insn::Mov, "")
        ));
        // Push followed by a non-mov.
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Push, "rsp"),
            &insn(X86Insn::Sub, "rsp, 0x20")
        ));
    }

    #[test]
    fn sub_stack_pointer_is_a_start_regardless_of_second() {
        assert!(are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Sub, "rsp, 0x28"),
            &insn(X86Insn::Other, "")
        ));
        assert!(are_function_start_instructions(
            Architecture::X86,
            &insn(X86Insn::Fsubp, "esp"),
            &insn(X86Insn::Ret, "")
        ));
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Sub, "rax, 1"),
            &insn(X86Insn::Other, "")
        ));
        // Anything else is not a start.
        assert!(!are_function_start_instructions(
            Architecture::X64,
            &insn(X86Insn::Mov, "rsp, rbp"),
            &insn(X86Insn::Mov, "")
        ));
    }

    #[test]
    fn simple_predicates() {
        assert!(is_call_instruction(&insn(X86Insn::Call, "")));
        assert!(!is_call_instruction(&insn(X86Insn::Lcall, "")));
        assert!(is_lcall_instruction(&insn(X86Insn::Lcall, "")));
        assert!(is_jmp_instruction(&insn(X86Insn::Jmp, "")));
        assert!(is_ljmp_instruction(&insn(X86Insn::Ljmp, "")));
        for id in [X86Insn::Int, X86Insn::Int1, X86Insn::Int3, X86Insn::Into] {
            assert!(is_breakpoint_instruction(&insn(id, "")));
        }
        assert!(!is_breakpoint_instruction(&insn(X86Insn::Ret, "")));
        for id in [
            X86Insn::Ret,
            X86Insn::Retf,
            X86Insn::Retfq,
            X86Insn::Sysret,
            X86Insn::Sysretq,
        ] {
            assert!(is_function_end_instruction(&insn(id, "")));
        }
        assert!(!is_function_end_instruction(&insn(X86Insn::Jmp, "")));
    }

    #[test]
    fn mnemonic_mapping_covers_aliases() {
        assert_eq!(X86Insn::from_mnemonic("call", false), X86Insn::Call);
        assert_eq!(X86Insn::from_mnemonic("call", true), X86Insn::Lcall);
        assert_eq!(X86Insn::from_mnemonic("jmp", true), X86Insn::Ljmp);
        assert_eq!(X86Insn::from_mnemonic("pusha", false), X86Insn::Pushaw);
        assert_eq!(X86Insn::from_mnemonic("pushad", false), X86Insn::Pushal);
        assert_eq!(X86Insn::from_mnemonic("movzx", false), X86Insn::Movzx);
        assert_eq!(X86Insn::from_mnemonic("xor", false), X86Insn::Other);
    }
}
