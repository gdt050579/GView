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

namespace
{
// x0 .. x30 (and their w halves): 0 .. 30; -1 for the other registers (sp, xzr, the vector registers)
int Arm64RegisterIndex(arm64_reg reg)
{
    if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
        return static_cast<int>(reg - ARM64_REG_X0);
    if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
        return static_cast<int>(reg - ARM64_REG_W0);
    if (reg == ARM64_REG_X29)
        return 29;
    if (reg == ARM64_REG_X30)
        return 30;
    return -1;
}

bool IsArm64LoadOrStore(unsigned int id, bool& isStore)
{
    switch (id) {
    case ARM64_INS_LDR:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDRSW:
        isStore = false;
        return true;
    case ARM64_INS_STR:
    case ARM64_INS_STRB:
    case ARM64_INS_STRH:
        isStore = true;
        return true;
    default:
        return false;
    }
}
} // namespace

AppCUI::uint64 GView::View::DissasmViewer::GetArm64AdrpPage(const cs_insn& insn, AppCUI::uint64 addressBase)
{
    if (insn.id != ARM64_INS_ADRP || !insn.detail || insn.detail->arm64.op_count < 2 || insn.detail->arm64.operands[1].type != ARM64_OP_IMM)
        return 0;
    constexpr uint64 PAGE_MASK = ~static_cast<uint64>(0xFFF);
    // the pages from the instruction to the target, as capstone computed them from the relative address
    const uint64 delta = static_cast<uint64>(insn.detail->arm64.operands[1].imm) - (insn.address & PAGE_MASK);
    return ((addressBase + insn.address) & PAGE_MASK) + delta - addressBase;
}

void Arm64AdrpTracker::Reset()
{
    registers.fill({});
}

std::optional<Arm64AdrpTracker::Result> Arm64AdrpTracker::Next(const cs_insn& insn, bool atBlockStart)
{
    if (insn.id == ARM64_INS_INVALID || !insn.detail) {
        Reset(); // a data line: the code before it is another block
        return {};
    }
    const cs_arm64& arm64 = insn.detail->arm64;
    std::optional<Result> result;
    int kept = -1; // the register this instruction sets to a known value
    const auto registerOf = [&arm64](uint8 index) { return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_REG ? Arm64RegisterIndex(arm64.operands[index].reg) : -1; };

    bool isStore = false;
    if (insn.id == ARM64_INS_ADRP) {
        // adrp x0, page: the 4 KB page of an address, the next instructions add its offset
        const int target = registerOf(0);
        if (target >= 0 && arm64.op_count >= 2 && arm64.operands[1].type == ARM64_OP_IMM) {
            registers[target] = { GetArm64AdrpPage(insn, addressBase), {}, insn.address, atBlockStart };
            kept              = target;
        }
    } else if (insn.id == ARM64_INS_ADD && arm64.op_count == 3 && arm64.operands[2].type == ARM64_OP_IMM) {
        // add x1, x0, #off: the address itself (a string, a variable, a table)
        const int base = registerOf(1);
        if (base >= 0 && registers[base].page.has_value()) {
            const auto& offset = arm64.operands[2];
            const uint64 value = static_cast<uint64>(offset.imm) << (offset.shift.type == ARM64_SFT_LSL ? offset.shift.value : 0);
            result             = Result{ registers[base].page.value() + value, false, registers[base].start, registers[base].startAtBlock, 0 };
        }
    } else if (IsArm64LoadOrStore(insn.id, isStore)) {
        // ldr x1, [x0, #off] / str w1, [x0, #off]: the address is read / written
        for (uint8 index = 0; index < arm64.op_count; index++) {
            const cs_arm64_op& op = arm64.operands[index];
            if (op.type != ARM64_OP_MEM || op.mem.index != ARM64_REG_INVALID)
                continue;
            const int base = Arm64RegisterIndex(op.mem.base);
            if (base < 0 || !registers[base].page.has_value())
                break;
            const auto& value = registers[base];
            result            = Result{ value.page.value() + static_cast<uint64>(static_cast<int64>(op.mem.disp)), false, value.start, value.startAtBlock,
                                     static_cast<uint8>(isStore ? CS_AC_WRITE : CS_AC_READ) };
            // ldr x16, [x16, #off]: the register holds the value of the slot (an import: the next br / blr goes through it)
            const int target = registerOf(0);
            if (insn.id == ARM64_INS_LDR && !isStore && target >= 0) {
                const auto start  = value.start;
                const bool atBlock = value.startAtBlock;
                registers[target] = { {}, result->address, start, atBlock };
                kept              = target;
            }
            break;
        }
    } else if (insn.id == ARM64_INS_BR || insn.id == ARM64_INS_BLR) {
        // br x16 / blr x8: through the slot read before
        const int target = registerOf(0);
        if (target >= 0 && registers[target].slot.has_value())
            result = Result{ registers[target].slot.value(), true, registers[target].start, registers[target].startAtBlock, CS_AC_READ };
    }

    // the registers written by the instruction do not hold the page / slot any more
    for (uint8 index = 0; index < arm64.op_count; index++) {
        const cs_arm64_op& op = arm64.operands[index];
        if (op.type == ARM64_OP_REG && (op.access & CS_AC_WRITE) != 0) {
            const int target = Arm64RegisterIndex(op.reg);
            if (target >= 0 && target != kept)
                registers[target] = {};
        } else if (op.type == ARM64_OP_MEM && arm64.writeback) {
            const int base = Arm64RegisterIndex(op.mem.base);
            if (base >= 0)
                registers[base] = {};
        }
    }
    const auto flow = GetArm64Flow(insn);
    if (flow == X86Flow::Call) { // the called function changes the argument / temporary registers (x0 .. x18) and the link register
        for (size_t index = 0; index <= 18; index++)
            registers[index] = {};
        registers[30] = {};
    } else if (flow == X86Flow::Jump || flow == X86Flow::Return)
        Reset(); // the next instruction starts another block
    return result;
}
