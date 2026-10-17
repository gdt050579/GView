#include "X86InstructionInfo.hpp"

using namespace AppCUI;
using namespace GView::View::DissasmViewer;

namespace
{
bool HasGroup(const cs_detail& detail, uint8 group)
{
    for (uint8 i = 0; i < detail.groups_count; i++)
        if (detail.groups[i] == group)
            return true;
    return false;
}
} // namespace

X86Flow GView::View::DissasmViewer::GetX86Flow(const cs_insn& insn)
{
    if (insn.id == X86_INS_INVALID || !insn.detail)
        return X86Flow::None;
    switch (insn.id) {
    // capstone does not place them in CS_GRP_JUMP (only in the relative branches group)
    case X86_INS_LOOP:
    case X86_INS_LOOPE:
    case X86_INS_LOOPNE:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
        return X86Flow::ConditionalJump;
    default:
        break;
    }
    const cs_detail& detail = *insn.detail;
    if (HasGroup(detail, CS_GRP_CALL))
        return X86Flow::Call;
    if (HasGroup(detail, CS_GRP_RET) || HasGroup(detail, CS_GRP_IRET))
        return X86Flow::Return;
    if (HasGroup(detail, CS_GRP_JUMP))
        return insn.id == X86_INS_JMP || insn.id == X86_INS_LJMP ? X86Flow::Jump : X86Flow::ConditionalJump; // jcc, loop, jcxz
    if (HasGroup(detail, CS_GRP_INT))
        return X86Flow::Interrupt;
    return X86Flow::None;
}

X86OperandsInfo GView::View::DissasmViewer::GetX86OperandsInfo(const cs_insn& insn, bool is64)
{
    X86OperandsInfo info;
    if (insn.id == X86_INS_INVALID || !insn.detail)
        return info;

    // the addresses of 32 bit code wrap around at 4 GB: a negative displacement is a high address
    const uint64 addressMask = is64 ? UINT64_MAX : 0xFFFFFFFFull;
    const bool isBranch      = IsX86Branch(GetX86Flow(insn));
    const cs_x86& x86        = insn.detail->x86;
    for (uint8 i = 0; i < x86.op_count; i++) {
        const cs_x86_op& op = x86.operands[i];
        if (op.type == X86_OP_IMM) {
            const uint64 value = static_cast<uint64>(op.imm) & addressMask;
            // the target of a near branch is its only operand (a far branch has a segment and an offset)
            if (isBranch && x86.op_count == 1)
                info.directTarget = value;
            else
                info.immediates.push_back(value);
        } else if (op.type == X86_OP_MEM) {
            const x86_op_mem& mem = op.mem;
            if (mem.base == X86_REG_RIP && mem.index == X86_REG_INVALID) {
                info.ripTarget    = (insn.address + insn.size + static_cast<uint64>(mem.disp)) & addressMask;
                info.memoryAccess = op.access;
            } else if (mem.base == X86_REG_INVALID && mem.index == X86_REG_INVALID &&
                       (mem.segment == X86_REG_INVALID || mem.segment == X86_REG_DS)) {
                // fs: / gs: point to thread data (TEB / TLS), not to a location of the file
                info.absoluteMemory = static_cast<uint64>(mem.disp) & addressMask;
                info.memoryAccess   = op.access;
            }
        }
    }
    return info;
}
