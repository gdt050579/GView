#include "X86InstructionInfo.hpp"

using namespace AppCUI;
using namespace GView::View::DissasmViewer;

// The ARM64 counterparts of GetX86Flow / GetX86OperandsInfo / GetX86InstructionKind: the same results, so the listing, the deep scan, the
// cross references and the graph work on ARM64 code as they do on x86 code

namespace
{
bool HasArm64Group(const cs_detail& detail, uint8 group)
{
    for (uint8 i = 0; i < detail.groups_count; i++)
        if (detail.groups[i] == group)
            return true;
    return false;
}

bool IsArm64ConditionalBranch(unsigned int id, std::string_view mnemonic)
{
    switch (id) {
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
        return true;
    case ARM64_INS_B:
        return mnemonic.size() > 2 && mnemonic[1] == '.' && mnemonic != "b.al"; // b.eq, b.lt, ...
    default:
        return false;
    }
}
} // namespace

X86Flow GView::View::DissasmViewer::GetArm64Flow(const cs_insn& insn)
{
    if (insn.id == ARM64_INS_INVALID || !insn.detail)
        return X86Flow::None;
    if (IsArm64ConditionalBranch(insn.id, insn.mnemonic))
        return X86Flow::ConditionalJump;
    const cs_detail& detail = *insn.detail;
    if (HasArm64Group(detail, CS_GRP_CALL)) // bl, blr, blraa, ...
        return X86Flow::Call;
    if (HasArm64Group(detail, CS_GRP_RET) || insn.id == ARM64_INS_RET || insn.id == ARM64_INS_RETAA || insn.id == ARM64_INS_RETAB ||
        insn.id == ARM64_INS_ERET)
        return X86Flow::Return;
    if (HasArm64Group(detail, CS_GRP_JUMP)) // b, br, braa, ...
        return X86Flow::Jump;
    if (HasArm64Group(detail, CS_GRP_INT) || insn.id == ARM64_INS_SVC || insn.id == ARM64_INS_BRK)
        return X86Flow::Interrupt;
    return X86Flow::None;
}

X86OperandsInfo GView::View::DissasmViewer::GetArm64OperandsInfo(const cs_insn& insn)
{
    X86OperandsInfo info;
    if (insn.id == ARM64_INS_INVALID || !insn.detail)
        return info;
    const cs_arm64& arm64 = insn.detail->arm64;
    const bool isBranch   = IsX86Branch(GetArm64Flow(insn));
    for (uint8 i = 0; i < arm64.op_count; i++) {
        const cs_arm64_op& op = arm64.operands[i];
        if (op.type != ARM64_OP_IMM)
            continue;
        const uint64 value = static_cast<uint64>(op.imm);
        // b / bl / cbz x0, / tbz x0, #3,: the target is the last operand (an absolute address)
        if (isBranch && i + 1 == arm64.op_count) {
            info.directTarget = value;
            continue;
        }
        switch (insn.id) {
        case ARM64_INS_ADR: // adr x0, label: the address is taken
            info.ripTarget = value;
            break;
        case ARM64_INS_LDR: // ldr x0, label (a literal): the address is read
        case ARM64_INS_LDRSW:
            info.ripTarget    = value;
            info.memoryAccess = CS_AC_READ;
            break;
        case ARM64_INS_ADRP: // the page of an address: its offset is added by the next instruction (not known here)
            break;
        default:
            info.immediates.push_back(value);
            break;
        }
    }
    return info;
}

X86InstructionKind GView::View::DissasmViewer::GetArm64InstructionKind(unsigned int id, std::string_view mnemonic)
{
    if (IsArm64ConditionalBranch(id, mnemonic))
        return X86InstructionKind::ConditionalJump;
    switch (id) {
    case ARM64_INS_INVALID: // the lines of DecodeX86Line: .word 0x.. / db 0x.. / align 0x10
        return mnemonic == "align" ? X86InstructionKind::Padding : X86InstructionKind::Data;
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
        return X86InstructionKind::Call;
    case ARM64_INS_B:
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
        return X86InstructionKind::Jump;
    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
    case ARM64_INS_ERET:
        return X86InstructionKind::Return;
    case ARM64_INS_CMP:
    case ARM64_INS_CMN:
    case ARM64_INS_TST:
    case ARM64_INS_FCMP:
    case ARM64_INS_CCMP:
    case ARM64_INS_CCMN:
        return X86InstructionKind::Compare;
    case ARM64_INS_STP: // the saved registers of the prologue / epilogue
    case ARM64_INS_LDP:
        return X86InstructionKind::Stack;
    case ARM64_INS_NOP:
    case ARM64_INS_HINT:
    case ARM64_INS_BTI:
    case ARM64_INS_PACIASP:
    case ARM64_INS_PACIBSP:
    case ARM64_INS_AUTIASP:
        return X86InstructionKind::Padding;
    // system calls, exceptions, system registers (the anti debug / anti VM checks read them)
    case ARM64_INS_SVC:
    case ARM64_INS_HVC:
    case ARM64_INS_SMC:
    case ARM64_INS_BRK:
    case ARM64_INS_HLT:
    case ARM64_INS_UDF:
    case ARM64_INS_MRS:
    case ARM64_INS_MSR:
    case ARM64_INS_SYS:
    case ARM64_INS_DCPS1:
        return X86InstructionKind::System;
    default:
        return X86InstructionKind::Other;
    }
}
