#include "X86InstructionInfo.hpp"

using namespace AppCUI;
using namespace GView::View::DissasmViewer;

// The 32 bit ARM counterparts of GetX86Flow / GetX86OperandsInfo / GetX86InstructionKind (ARM and Thumb modes): the same results, so the
// listing, the deep scan, the cross references and the graph work on 32 bit ARM code as they do on x86 code

namespace
{
bool IsConditional(const cs_arm& arm)
{
    return arm.cc != ARM_CC_AL && arm.cc != ARM_CC_INVALID;
}

bool HasRegister(const cs_arm& arm, arm_reg reg)
{
    for (uint8 index = 0; index < arm.op_count; index++)
        if (arm.operands[index].type == ARM_OP_REG && arm.operands[index].reg == reg)
            return true;
    return false;
}

// r0 .. r12: 0 .. 12, sp: 13, lr: 14; -1 for pc and the other registers
int RegisterIndex(int reg) // capstone keeps the registers of the operands as int
{
    if (reg >= ARM_REG_R0 && reg <= ARM_REG_R12)
        return reg - ARM_REG_R0;
    if (reg == ARM_REG_SP)
        return 13;
    if (reg == ARM_REG_LR)
        return 14;
    return -1;
}

// an immediate operand and its rotation (add r12, pc, #0, #12: the value is rotated right by the second immediate)
std::optional<uint32> ImmediateAt(const cs_arm& arm, uint8 index)
{
    if (index >= arm.op_count || arm.operands[index].type != ARM_OP_IMM)
        return {};
    uint32 value = static_cast<uint32>(arm.operands[index].imm);
    if (index + 1 < arm.op_count && arm.operands[index + 1].type == ARM_OP_IMM) {
        const uint32 rotation = static_cast<uint32>(arm.operands[index + 1].imm) & 31;
        value                 = rotation == 0 ? value : ((value >> rotation) | (value << (32 - rotation)));
    }
    return value;
}

// the value of pc for the instruction (relative address): the address + 8 (ARM) / the 4 bytes aligned address + 4 (Thumb), on the VA
uint64 ProgramCounter(const cs_insn& insn, bool thumb, uint64 addressBase)
{
    if (!thumb)
        return insn.address + 8;
    return ((addressBase + insn.address + 4) & ~static_cast<uint64>(3)) - addressBase;
}

// a relative address of 32 bit code: the VA wraps around at 4 GB (a PIC offset is often negative), the relative address is VA - addressBase
uint64 Wrap(uint64 relative, uint64 addressBase)
{
    return ((addressBase + relative) & 0xFFFFFFFFull) - addressBase;
}

bool IsLoad(unsigned int id)
{
    switch (id) {
    case ARM_INS_LDR:
    case ARM_INS_LDRB:
    case ARM_INS_LDRH:
    case ARM_INS_LDRSB:
    case ARM_INS_LDRSH:
    case ARM_INS_LDRD:
        return true;
    default:
        return false;
    }
}

bool IsStore(unsigned int id)
{
    return id == ARM_INS_STR || id == ARM_INS_STRB || id == ARM_INS_STRH || id == ARM_INS_STRD;
}
} // namespace

X86Flow GView::View::DissasmViewer::GetArm32Flow(const cs_insn& insn)
{
    if (insn.id == ARM_INS_INVALID || !insn.detail)
        return X86Flow::None;
    const cs_arm& arm      = insn.detail->arm;
    const bool conditional = IsConditional(arm);
    switch (insn.id) {
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        return X86Flow::ConditionalJump;
    case ARM_INS_B:
        return conditional ? X86Flow::ConditionalJump : X86Flow::Jump;
    case ARM_INS_BL:
    case ARM_INS_BLX:
        return X86Flow::Call;
    case ARM_INS_BX: // bx lr: a return; bx r12: an indirect jump (an import thunk)
        if (conditional)
            return X86Flow::None;
        return HasRegister(arm, ARM_REG_LR) ? X86Flow::Return : X86Flow::Jump;
    case ARM_INS_POP: // pop {r4, pc} / ldm sp!, {r4, pc}: a return
    case ARM_INS_LDM:
        return !conditional && HasRegister(arm, ARM_REG_PC) ? X86Flow::Return : X86Flow::None;
    case ARM_INS_LDR: // ldr pc, [ip, #off]!: through a slot (a PLT stub, a jump table; ldrls pc, [pc, r0, lsl #2]: a switch)
    case ARM_INS_ADD: // add pc, r1, r0 / addls pc, pc, r0, lsl #2: a switch
        if (arm.op_count == 0 || arm.operands[0].type != ARM_OP_REG || arm.operands[0].reg != ARM_REG_PC)
            return X86Flow::None;
        return conditional ? X86Flow::ConditionalJump : X86Flow::Jump;
    case ARM_INS_MOV: // mov pc, lr
        if (conditional || arm.op_count < 2 || arm.operands[0].type != ARM_OP_REG || arm.operands[0].reg != ARM_REG_PC)
            return X86Flow::None;
        return arm.operands[1].type == ARM_OP_REG && arm.operands[1].reg == ARM_REG_LR ? X86Flow::Return : X86Flow::Jump;
    case ARM_INS_TBB: // the jump tables of Thumb
    case ARM_INS_TBH:
        return X86Flow::Jump;
    case ARM_INS_SVC:
    case ARM_INS_BKPT:
    case ARM_INS_UDF:
        return X86Flow::Interrupt;
    default:
        return X86Flow::None;
    }
}

X86OperandsInfo GView::View::DissasmViewer::GetArm32OperandsInfo(const cs_insn& insn, bool thumb, uint64 addressBase)
{
    X86OperandsInfo info;
    if (insn.id == ARM_INS_INVALID || !insn.detail)
        return info;
    const cs_arm& arm     = insn.detail->arm;
    const uint64 pc       = ProgramCounter(insn, thumb, addressBase);
    const auto flow       = GetArm32Flow(insn);
    // b / bl / blx / cbz r0,: the target is the last operand (an absolute address)
    if (IsX86Branch(flow) && arm.op_count > 0 && arm.operands[arm.op_count - 1].type == ARM_OP_IMM) {
        info.directTarget = Wrap(static_cast<uint64>(arm.operands[arm.op_count - 1].imm), addressBase);
        return info;
    }
    if (insn.id == ARM_INS_ADR) { // adr r0, #off (Thumb): the address is taken
        if (const auto offset = ImmediateAt(arm, 1); offset.has_value())
            info.ripTarget = Wrap(pc + offset.value(), addressBase);
        return info;
    }
    // add r0, pc, #imm / sub r0, pc, #imm (the adr of ARM mode)
    if ((insn.id == ARM_INS_ADD || insn.id == ARM_INS_SUB) && arm.op_count >= 3 && arm.operands[1].type == ARM_OP_REG &&
        arm.operands[1].reg == ARM_REG_PC) {
        if (const auto value = ImmediateAt(arm, 2); value.has_value()) {
            info.ripTarget = Wrap(insn.id == ARM_INS_ADD ? pc + value.value() : pc - value.value(), addressBase);
            return info;
        }
    }
    for (uint8 index = 0; index < arm.op_count; index++) {
        const cs_arm_op& op = arm.operands[index];
        if (op.type == ARM_OP_MEM && op.mem.base == ARM_REG_PC && op.mem.index == ARM_REG_INVALID) {
            // ldr r0, [pc, #off]: a literal of the pool
            info.ripTarget    = Wrap(pc + static_cast<uint64>(static_cast<int64>(op.mem.disp)), addressBase);
            info.memoryAccess = static_cast<uint8>(IsStore(insn.id) ? CS_AC_WRITE : CS_AC_READ);
        } else if (op.type == ARM_OP_IMM)
            info.immediates.push_back(static_cast<uint64>(static_cast<uint32>(op.imm)));
    }
    return info;
}

X86InstructionKind GView::View::DissasmViewer::GetArm32InstructionKind(unsigned int id, std::string_view mnemonic)
{
    switch (id) {
    case ARM_INS_INVALID: // the data lines of DecodeX86Line: .word / .short / db
        return X86InstructionKind::Data;
    case ARM_INS_B: // b / beq / bne.w ...: the conditional ones have a condition after the b
        return mnemonic == "b" || mnemonic == "b.w" ? X86InstructionKind::Jump : X86InstructionKind::ConditionalJump;
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
        return X86InstructionKind::ConditionalJump;
    case ARM_INS_BL:
    case ARM_INS_BLX:
        return X86InstructionKind::Call;
    case ARM_INS_BX: // bx lr, mostly
        return X86InstructionKind::Return;
    case ARM_INS_TBB:
    case ARM_INS_TBH:
        return X86InstructionKind::Jump;
    case ARM_INS_CMP:
    case ARM_INS_CMN:
    case ARM_INS_TST:
    case ARM_INS_TEQ:
        return X86InstructionKind::Compare;
    case ARM_INS_PUSH:
    case ARM_INS_POP:
    case ARM_INS_STMDB:
    case ARM_INS_LDM:
        return X86InstructionKind::Stack;
    case ARM_INS_NOP:
        return X86InstructionKind::Padding;
    case ARM_INS_SVC:
    case ARM_INS_BKPT:
    case ARM_INS_UDF:
    case ARM_INS_MRS:
    case ARM_INS_MSR:
    case ARM_INS_CPS:
        return X86InstructionKind::System;
    default:
        return X86InstructionKind::Other;
    }
}

bool GView::View::DissasmViewer::IsArm32PrologueStart(const cs_insn& insn)
{
    if (!insn.detail)
        return false;
    const cs_arm& arm = insn.detail->arm;
    // push {r4, lr} / stmdb sp!, {r4, r11, lr}: the return address is saved
    if (insn.id == ARM_INS_PUSH)
        return HasRegister(arm, ARM_REG_LR);
    if (insn.id == ARM_INS_STMDB)
        return arm.writeback && arm.op_count > 0 && arm.operands[0].type == ARM_OP_REG && arm.operands[0].reg == ARM_REG_SP && HasRegister(arm, ARM_REG_LR);
    return false;
}

void Arm32Tracker::Reset()
{
    registers.fill({});
    compared.reset();
    bound.reset();
}

std::optional<Arm32Tracker::Result> Arm32Tracker::Next(const cs_insn& insn, bool thumb, bool atBlockStart)
{
    jumpTable.reset();
    if (insn.id == ARM_INS_INVALID || !insn.detail) {
        Reset(); // a data line (a literal pool): the code before it is another block
        return {};
    }
    const cs_arm& arm = insn.detail->arm;
    const uint64 pc   = ProgramCounter(insn, thumb, addressBase);
    std::optional<Result> result;
    int kept = -1; // the register this instruction sets to a known value
    const auto registerOf = [&arm](uint8 index) { return index < arm.op_count && arm.operands[index].type == ARM_OP_REG ? RegisterIndex(arm.operands[index].reg) : -1; };
    const auto isPc       = [&arm](uint8 index) { return index < arm.op_count && arm.operands[index].type == ARM_OP_REG && arm.operands[index].reg == ARM_REG_PC; };
    const auto setAddress = [&](int target, uint64 value, uint64 start, bool startAtBlock) {
        registers[target]              = {};
        registers[target].address      = Wrap(value, addressBase);
        registers[target].start        = start;
        registers[target].startAtBlock = startAtBlock;
        kept                           = target;
    };

    // the bound of a switch: cmp r0, #N, then an instruction executed above it (bhi default / bxhi lr / movhi) or the jump itself, executed
    // below or same (addls pc, ... / ldrls pc, ...)
    std::optional<uint32> ownBound;
    if (insn.id == ARM_INS_CMP) {
        compared.reset();
        bound.reset();
        if (arm.op_count == 2 && ImmediateAt(arm, 1).has_value())
            compared = ImmediateAt(arm, 1).value();
    } else if (compared.has_value()) {
        if (arm.cc == ARM_CC_HI || arm.cc == ARM_CC_HS)
            bound = static_cast<uint32>(arm.cc == ARM_CC_HI ? compared.value() + 1 : compared.value());
        else if (arm.cc == ARM_CC_LS || arm.cc == ARM_CC_LO)
            ownBound = static_cast<uint32>(arm.cc == ARM_CC_LS ? compared.value() + 1 : compared.value());
    }
    constexpr uint32 MAX_CASES = 4096;
    const auto cases           = ownBound.has_value() ? ownBound : bound;
    const bool hasCases        = cases.has_value() && cases.value() > 0 && cases.value() <= MAX_CASES;
    const auto setJumpTable    = [&](Arm64JumpTable table) {
        if (!hasCases)
            return;
        table.count = cases.value();
        jumpTable   = table;
    };

    const int target = registerOf(0);
    switch (insn.id) {
    case ARM_INS_TBB: // tbb [pc, r0] / tbh [pc, r0, lsl #1]: the table follows the instruction, the case i is at pc + 2 * entry i
    case ARM_INS_TBH: {
        const uint64 base = Wrap(insn.address + 4, addressBase);
        setJumpTable({ base, static_cast<uint8>(insn.id == ARM_INS_TBB ? 1 : 2), false, base, 1, 0 });
        break;
    }
    case ARM_INS_MOVW: // movw r12, #:lower16:address (capstone names the movw of Thumb-2 mov)
    case ARM_INS_MOV:
        if (target >= 0 && ImmediateAt(arm, 1).has_value() && ImmediateAt(arm, 1).value() <= 0xFFFF) {
            registers[target]              = {};
            registers[target].low16        = ImmediateAt(arm, 1).value() & 0xFFFF;
            registers[target].start        = insn.address;
            registers[target].startAtBlock = atBlockStart;
            kept                           = target;
        }
        break;
    case ARM_INS_MOVT: // movt r12, #:upper16:address: an absolute address (a VA)
        if (target >= 0 && registers[target].low16.has_value() && ImmediateAt(arm, 1).has_value()) {
            const uint64 va = (static_cast<uint64>(ImmediateAt(arm, 1).value() & 0xFFFF) << 16) | registers[target].low16.value();
            const auto from = registers[target];
            if (va >= addressBase) { // the address is taken (a string, a variable, a slot)
                setAddress(target, va - addressBase, from.start, from.startAtBlock);
                result = Result{ va - addressBase, false, from.start, from.startAtBlock, 0 };
            }
        }
        break;
    case ARM_INS_ADR: // adr r0, #off (Thumb)
        if (target >= 0 && ImmediateAt(arm, 1).has_value()) {
            result = Result{ Wrap(pc + ImmediateAt(arm, 1).value(), addressBase), false, insn.address, atBlockStart, 0 };
            setAddress(target, result->address, insn.address, atBlockStart);
        }
        break;
    case ARM_INS_ADD:
    case ARM_INS_SUB: {
        const bool isAdd = insn.id == ARM_INS_ADD;
        if (isAdd && arm.op_count == 3 && arm.operands[1].type == ARM_OP_REG && arm.operands[2].type == ARM_OP_REG) {
            const auto& indexOperand = arm.operands[2];
            const uint8 shift        = static_cast<uint8>(indexOperand.shift.type == ARM_SFT_LSL ? indexOperand.shift.value : 0);
            if (isPc(0) && isPc(1)) {
                // addls pc, pc, r0, lsl #2: a table of branches, the case i is at pc + (i << 2)
                setJumpTable({ 0, 0, false, pc, shift, 0 });
                break;
            }
            // add pc, r1, r0 / add r2, r1, r0: an address (the table, an anchor) plus an entry of the table
            const int first  = registerOf(1);
            const int second = registerOf(2);
            const bool firstIsAddress = first >= 0 && registers[first].address.has_value() && second >= 0 && registers[second].entry.has_value();
            const bool secondIsAddress = first >= 0 && registers[first].entry.has_value() && second >= 0 && registers[second].address.has_value();
            if (firstIsAddress || secondIsAddress) {
                const auto entry   = (firstIsAddress ? registers[second] : registers[first]).entry.value();
                const uint64 base  = (firstIsAddress ? registers[first] : registers[second]).address.value();
                const Arm64JumpTable table{ entry.table, entry.size, entry.isSigned, base, firstIsAddress ? shift : static_cast<uint8>(0), 0 };
                if (isPc(0))
                    setJumpTable(table);
                else if (target >= 0) {
                    registers[target]      = {};
                    registers[target].jump = table;
                    kept                   = target;
                }
                break;
            }
        }
        if (target < 0)
            break;
        if (arm.op_count >= 3 && arm.operands[2].type == ARM_OP_IMM) {
            // add r12, pc, #0, #12 (the PLT, the adr of ARM mode) / add r12, r12, #0x20000
            const uint32 value = ImmediateAt(arm, 2).value_or(0);
            if (isPc(1))
                setAddress(target, isAdd ? pc + value : pc - value, insn.address, atBlockStart);
            else if (const int base = registerOf(1); base >= 0 && registers[base].address.has_value()) {
                const auto from = registers[base];
                setAddress(target, isAdd ? from.address.value() + value : from.address.value() - value, from.start, from.startAtBlock);
            }
        } else if (isAdd && arm.op_count == 3) {
            // add r0, pc, r0: a PIC address, the offset was read from the literal pool
            const int other = isPc(1) ? registerOf(2) : (isPc(2) ? registerOf(1) : -1);
            if (other >= 0 && registers[other].literal.has_value()) {
                result = Result{ Wrap(pc + registers[other].literal.value(), addressBase), false, insn.address, atBlockStart, 0 };
                setAddress(target, result->address, insn.address, atBlockStart);
            }
        } else if (isAdd && arm.op_count == 2 && isPc(1) && registers[target].literal.has_value()) {
            // add r0, pc (Thumb): the same
            result = Result{ Wrap(pc + registers[target].literal.value(), addressBase), false, insn.address, atBlockStart, 0 };
            setAddress(target, result->address, insn.address, atBlockStart);
        }
        break;
    }
    case ARM_INS_BX:
    case ARM_INS_BLX: // bx r12 / blx r3: through the slot read before; bx r2: the case of a switch
        if (target >= 0 && arm.operands[0].type == ARM_OP_REG && registers[target].slot.has_value())
            result = Result{ registers[target].slot.value(), true, registers[target].start, registers[target].startAtBlock, CS_AC_READ };
        if (target >= 0 && insn.id == ARM_INS_BX && registers[target].jump.has_value())
            setJumpTable(registers[target].jump.value());
        break;
    default:
        if (!IsLoad(insn.id) && !IsStore(insn.id))
            break;
        for (uint8 index = 0; index < arm.op_count; index++) {
            const cs_arm_op& op = arm.operands[index];
            if (op.type != ARM_OP_MEM)
                continue;
            if (op.mem.index != ARM_REG_INVALID) {
                if (!IsLoad(insn.id))
                    break;
                if (op.mem.base == ARM_REG_PC && insn.id == ARM_INS_LDR && isPc(0)) {
                    // ldrls pc, [pc, r0, lsl #2]: a table of the addresses (VA) of the cases, at pc
                    setJumpTable({ pc, 4, false, 0, 0, 0, true });
                    break;
                }
                // ldr r0, [r1, r0, lsl #2] / ldrb r0, [r1, r0]: an entry of the table that r1 points to
                const int base = RegisterIndex(op.mem.base);
                if (target >= 0 && base >= 0 && registers[base].address.has_value()) {
                    uint8 size = 4;
                    if (insn.id == ARM_INS_LDRB || insn.id == ARM_INS_LDRSB)
                        size = 1;
                    else if (insn.id == ARM_INS_LDRH || insn.id == ARM_INS_LDRSH)
                        size = 2;
                    const uint64 table      = registers[base].address.value();
                    registers[target]       = {};
                    registers[target].entry = TableEntry{ table, size, insn.id == ARM_INS_LDRSB || insn.id == ARM_INS_LDRSH };
                    kept                    = target;
                }
                break;
            }
            if (op.mem.base == ARM_REG_PC) {
                // ldr r0, [pc, #off]: the word of the literal pool (a PIC offset, an address)
                if (insn.id == ARM_INS_LDR && target >= 0 && readWord) {
                    if (const auto word = readWord(Wrap(pc + static_cast<uint64>(static_cast<int64>(op.mem.disp)), addressBase)); word.has_value()) {
                        registers[target]         = {};
                        registers[target].literal = word.value();
                        kept                      = target;
                    }
                }
                break;
            }
            const int base = RegisterIndex(op.mem.base);
            if (base < 0 || !registers[base].address.has_value())
                break;
            // ldr r0, [r12, #off]( !): a slot (post index: the base itself)
            const auto from   = registers[base];
            const uint64 slot = Wrap(arm.post_index ? from.address.value() : from.address.value() + static_cast<uint64>(static_cast<int64>(op.mem.disp)), addressBase);
            const bool isJump = insn.id == ARM_INS_LDR && isPc(0); // ldr pc, [ip, #off]!: the PLT stub
            result            = Result{ slot, isJump, from.start, from.startAtBlock, static_cast<uint8>(IsStore(insn.id) ? CS_AC_WRITE : CS_AC_READ) };
            if (insn.id == ARM_INS_LDR && target >= 0) {
                registers[target]              = {};
                registers[target].slot         = slot;
                registers[target].start        = from.start;
                registers[target].startAtBlock = from.startAtBlock;
                kept                           = target;
            }
            break;
        }
        break;
    }

    // the registers written by the instruction (and the base of a writeback) do not hold their values any more
    for (uint8 index = 0; index < arm.op_count; index++) {
        const cs_arm_op& op = arm.operands[index];
        if (op.type == ARM_OP_REG && (op.access & CS_AC_WRITE) != 0) {
            const int written = RegisterIndex(op.reg);
            if (written >= 0 && written != kept)
                registers[written] = {};
        } else if (op.type == ARM_OP_MEM && arm.writeback) {
            const int base = RegisterIndex(op.mem.base);
            if (base >= 0 && base != kept)
                registers[base] = {};
        }
    }
    const auto flow = GetArm32Flow(insn);
    if (flow == X86Flow::Call) { // the called function changes r0 .. r3, r12 and lr
        for (size_t index = 0; index <= 3; index++)
            registers[index] = {};
        registers[12] = {};
        registers[14] = {};
    } else if (flow == X86Flow::Jump || flow == X86Flow::Return)
        Reset(); // the next instruction starts another block
    return result;
}
