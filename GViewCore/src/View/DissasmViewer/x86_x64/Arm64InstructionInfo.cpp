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
        case ARM64_INS_LDR: // ldr x0, label (a literal): the address is read; ldr x0, [sp], #0x10 (post index) is not one
        case ARM64_INS_LDRSW:
            if (arm64.op_count == 2) {
                info.ripTarget    = value;
                info.memoryAccess = CS_AC_READ;
            } else
                info.immediates.push_back(value);
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

bool GView::View::DissasmViewer::IsArm64PrologueStart(const cs_insn& insn)
{
    if (!insn.detail)
        return false;
    const cs_arm64& arm64 = insn.detail->arm64;
    switch (insn.id) {
    case ARM64_INS_PACIBSP:
    case ARM64_INS_PACIASP:
        return true;
    case ARM64_INS_BTI: // bti c: the target of an indirect call (bti j: of an indirect jump)
        return insn.op_str[0] == 'c' || (insn.op_str[0] == 'j' && insn.op_str[1] == 'c');
    case ARM64_INS_STP: // stp x29, x30, [sp, #-0x10]! / stp x20, x19, [sp, #-0x20]!: the registers saved by the prologue
        return arm64.writeback && arm64.op_count >= 3 && arm64.operands[2].type == ARM64_OP_MEM && arm64.operands[2].mem.base == ARM64_REG_SP &&
               arm64.operands[2].mem.disp < 0;
    case ARM64_INS_SUB: // sub sp, sp, #0x40: the local variables
        return arm64.op_count == 3 && arm64.operands[0].type == ARM64_OP_REG && arm64.operands[0].reg == ARM64_REG_SP &&
               arm64.operands[1].type == ARM64_OP_REG && arm64.operands[1].reg == ARM64_REG_SP && arm64.operands[2].type == ARM64_OP_IMM;
    default:
        return false;
    }
}

void Arm64AdrpTracker::Reset()
{
    registers.fill({});
    compared.reset();
    bound.reset();
}

std::optional<Arm64AdrpTracker::Result> Arm64AdrpTracker::Next(const cs_insn& insn, bool atBlockStart)
{
    jumpTable.reset();
    if (insn.id == ARM64_INS_INVALID || !insn.detail) {
        Reset(); // a data line: the code before it is another block
        return {};
    }
    const cs_arm64& arm64 = insn.detail->arm64;
    std::optional<Result> result;
    int kept = -1; // the register this instruction sets to a known value
    const auto registerOf = [&arm64](uint8 index) { return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_REG ? Arm64RegisterIndex(arm64.operands[index].reg) : -1; };
    const auto isImmediate = [&arm64](uint8 index) { return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_IMM; };

    bool isStore = false;
    if (insn.id == ARM64_INS_ADRP) {
        // adrp x0, page: the 4 KB page of an address, the next instructions add its offset
        const int target = registerOf(0);
        if (target >= 0 && isImmediate(1)) {
            registers[target] = { GetArm64AdrpPage(insn, addressBase), {}, {}, {}, {}, insn.address, atBlockStart };
            kept              = target;
        }
    } else if (insn.id == ARM64_INS_ADR) {
        // adr x10, label: the register holds the address (a jump table, the anchor of its cases)
        const int target = registerOf(0);
        if (target >= 0 && isImmediate(1)) {
            registers[target]         = {};
            registers[target].address = static_cast<uint64>(arm64.operands[1].imm);
            kept                      = target;
        }
    } else if (insn.id == ARM64_INS_ADD && arm64.op_count == 3 && isImmediate(2)) {
        // add x1, x0, #off: the address itself (a string, a variable, a table)
        const int base   = registerOf(1);
        const int target = registerOf(0);
        if (base >= 0 && registers[base].page.has_value()) {
            const auto& offset = arm64.operands[2];
            const uint64 value = static_cast<uint64>(offset.imm) << (offset.shift.type == ARM64_SFT_LSL ? offset.shift.value : 0);
            result             = Result{ registers[base].page.value() + value, false, registers[base].start, registers[base].startAtBlock, 0 };
            if (target >= 0) {
                const Value from          = registers[base];
                registers[target]         = {};
                registers[target].address = result->address;
                registers[target].start   = from.start;
                registers[target].startAtBlock = from.startAtBlock;
                kept                      = target;
            }
        }
    } else if (insn.id == ARM64_INS_ADD && arm64.op_count == 3 && arm64.operands[2].type == ARM64_OP_REG) {
        // add x10, x10, x11, lsl #2 / add x0, x1, w0, sxtb #2: an address (the anchor, or the table itself) plus a table entry
        const int first  = registerOf(1);
        const int second = registerOf(2);
        const int target = registerOf(0);
        if (first >= 0 && second >= 0 && target >= 0 && registers[first].address.has_value() && registers[second].entry.has_value()) {
            const auto& operand    = arm64.operands[2];
            const bool signExtends = operand.ext == ARM64_EXT_SXTB || operand.ext == ARM64_EXT_SXTH || operand.ext == ARM64_EXT_SXTW;
            const auto entry       = registers[second].entry.value();
            Arm64JumpTable table{ entry.table, entry.size, entry.isSigned || signExtends, registers[first].address.value(),
                                  static_cast<uint8>(operand.shift.value), 0 };
            registers[target]      = {};
            registers[target].jump = table;
            kept                   = target;
        }
    } else if (IsArm64LoadOrStore(insn.id, isStore)) {
        for (uint8 index = 0; index < arm64.op_count; index++) {
            const cs_arm64_op& op = arm64.operands[index];
            if (op.type != ARM64_OP_MEM)
                continue;
            const int base = Arm64RegisterIndex(op.mem.base);
            if (base < 0)
                break;
            if (op.mem.index != ARM64_REG_INVALID) {
                // ldrb w11, [x9, x8]: an entry of the table that x9 points to
                const int target = registerOf(0);
                if (!isStore && target >= 0 && registers[base].address.has_value()) {
                    const bool isWide = arm64.operands[0].reg >= ARM64_REG_X0 && arm64.operands[0].reg <= ARM64_REG_X28;
                    uint8 size        = 4;
                    if (insn.id == ARM64_INS_LDRB || insn.id == ARM64_INS_LDRSB)
                        size = 1;
                    else if (insn.id == ARM64_INS_LDRH || insn.id == ARM64_INS_LDRSH)
                        size = 2;
                    else if (insn.id == ARM64_INS_LDR && isWide)
                        size = 8;
                    const bool isSigned = insn.id == ARM64_INS_LDRSB || insn.id == ARM64_INS_LDRSH || insn.id == ARM64_INS_LDRSW;
                    const uint64 table  = registers[base].address.value();
                    registers[target]       = {};
                    registers[target].entry = TableEntry{ table, size, isSigned };
                    kept                    = target;
                }
                break;
            }
            if (!registers[base].page.has_value())
                break;
            // ldr x1, [x0, #off] / str w1, [x0, #off]: the address is read / written
            const auto& value = registers[base];
            result            = Result{ value.page.value() + static_cast<uint64>(static_cast<int64>(op.mem.disp)), false, value.start, value.startAtBlock,
                                        static_cast<uint8>(isStore ? CS_AC_WRITE : CS_AC_READ) };
            // ldr x16, [x16, #off]: the register holds the value of the slot (an import: the next br / blr goes through it)
            const int target = registerOf(0);
            if (insn.id == ARM64_INS_LDR && !isStore && target >= 0) {
                const auto start   = value.start;
                const bool atBlock = value.startAtBlock;
                registers[target]  = { {}, result->address, {}, {}, {}, start, atBlock };
                kept               = target;
            }
            break;
        }
    } else if (insn.id == ARM64_INS_BR || insn.id == ARM64_INS_BLR) {
        // br x16 / blr x8: through the slot read before; br x10: the case of a switch
        const int target = registerOf(0);
        if (target >= 0 && registers[target].slot.has_value())
            result = Result{ registers[target].slot.value(), true, registers[target].start, registers[target].startAtBlock, CS_AC_READ };
        if (target >= 0 && insn.id == ARM64_INS_BR && registers[target].jump.has_value() && bound.has_value()) {
            jumpTable        = registers[target].jump;
            jumpTable->count = bound.value();
        }
    } else if (insn.id == ARM64_INS_CMP && arm64.op_count == 2 && isImmediate(1)) {
        compared = static_cast<uint64>(arm64.operands[1].imm); // cmp w0, #11
    } else if (insn.id == ARM64_INS_B && compared.has_value() && (arm64.cc == ARM64_CC_HI || arm64.cc == ARM64_CC_HS)) {
        // b.hi default: the cases are 0 .. N (b.hs: 0 .. N - 1)
        constexpr uint64 MAX_CASES = 4096;
        const uint64 count         = arm64.cc == ARM64_CC_HI ? compared.value() + 1 : compared.value();
        if (count > 0 && count <= MAX_CASES)
            bound = static_cast<uint32>(count);
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
        compared.reset();
        bound.reset();
    } else if (flow == X86Flow::Jump || flow == X86Flow::Return)
        Reset(); // the next instruction starts another block
    return result;
}
