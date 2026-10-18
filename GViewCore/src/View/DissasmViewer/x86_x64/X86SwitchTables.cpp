#include "X86SwitchTables.hpp"

#include <algorithm>
#include <unordered_map>

using namespace AppCUI;
using namespace GView::View::DissasmViewer;

namespace
{
constexpr uint32 MAX_CASES           = 1024; // a bounds check above it is not a switch
constexpr uint32 MAX_UNBOUNDED_CASES = 256;  // a table without a bounds check: the cases end at the first entry that is not code
constexpr size_t MAX_ADD_DISTANCE    = 3;    // add rcx, rdx is right before jmp rcx
constexpr size_t MAX_LOAD_DISTANCE   = 6;    // the load of the entry is a few instructions before the add
constexpr size_t MAX_INDEX_DISTANCE  = 6;    // the byte index table is read a few instructions before the entry

// the general purpose register (0-15) of any of its sizes; -1 for the other registers
int RegisterFamily(x86_reg reg)
{
    switch (reg) {
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: return 0;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: return 1;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: return 2;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: return 3;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return 4;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return 5;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return 6;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return 7;
    case X86_REG_R8: case X86_REG_R8D: case X86_REG_R8W: case X86_REG_R8B: return 8;
    case X86_REG_R9: case X86_REG_R9D: case X86_REG_R9W: case X86_REG_R9B: return 9;
    case X86_REG_R10: case X86_REG_R10D: case X86_REG_R10W: case X86_REG_R10B: return 10;
    case X86_REG_R11: case X86_REG_R11D: case X86_REG_R11W: case X86_REG_R11B: return 11;
    case X86_REG_R12: case X86_REG_R12D: case X86_REG_R12W: case X86_REG_R12B: return 12;
    case X86_REG_R13: case X86_REG_R13D: case X86_REG_R13W: case X86_REG_R13B: return 13;
    case X86_REG_R14: case X86_REG_R14D: case X86_REG_R14W: case X86_REG_R14B: return 14;
    case X86_REG_R15: case X86_REG_R15D: case X86_REG_R15W: case X86_REG_R15B: return 15;
    default: return -1;
    }
}

bool IsRegister(const cs_x86_op& op, int family)
{
    return op.type == X86_OP_REG && family >= 0 && RegisterFamily(op.reg) == family;
}
} // namespace

X86SwitchDetector::X86SwitchDetector(bool is64, uint64 labelBase, std::optional<uint64> imageBase)
    : is64(is64), labelBase(labelBase), addressMask(is64 ? UINT64_MAX : 0xFFFFFFFFull), imageBase(imageBase)
{
}

const cs_insn* X86SwitchDetector::Previous(size_t index) const
{
    if (index >= recentCount)
        return nullptr;
    return &recent[(recentHead + HISTORY - 1 - index) % HISTORY].insn;
}

std::optional<X86JumpTable> X86SwitchDetector::Next(const cs_insn& insn)
{
    std::optional<X86JumpTable> table;
    if (insn.id == X86_INS_JMP && insn.detail && insn.detail->x86.op_count == 1) {
        const cs_x86_op& op = insn.detail->x86.operands[0];
        const uint8 pointerSize = is64 ? 8 : 4;
        if (op.type == X86_OP_MEM && op.mem.index != X86_REG_INVALID && op.mem.base == X86_REG_INVALID && op.mem.scale == pointerSize &&
            (op.mem.segment == X86_REG_INVALID || op.mem.segment == X86_REG_DS)) {
            // jmp dword ptr [eax * 4 + table]: a table of addresses
            X86JumpTable absolute;
            absolute.tableAddress = static_cast<uint64>(op.mem.disp) & addressMask;
            absolute.entrySize    = pointerSize;
            absolute.kind         = X86JumpTable::EntryKind::Absolute;
            table                 = absolute;
        } else if (op.type == X86_OP_REG) {
            table = FindRegisterJumpTable(op.reg);
        }
        if (table.has_value())
            table->casesCount = FindCasesCount();
    }

    // the instructions of the patterns are kept with their details (the other ones are not copied: the scan decodes every instruction of
    // the code); the distances are counted in kept instructions
    switch (insn.id) {
    case X86_INS_ADD:
    case X86_INS_MOV:
    case X86_INS_MOVSXD:
    case X86_INS_MOVZX:
    case X86_INS_LEA:
    case X86_INS_CMP:
    case X86_INS_JA:
    case X86_INS_JAE:
    case X86_INS_JMP:
    case X86_INS_RET:
    case X86_INS_CALL:
        break;
    default:
        return table;
    }
    auto& slot = recent[recentHead];
    slot.insn  = insn;
    if (insn.detail) {
        slot.detail      = *insn.detail;
        slot.insn.detail = &slot.detail;
    } else {
        slot.insn.detail = nullptr;
    }
    recentHead  = (recentHead + 1) % HISTORY;
    recentCount = std::min(recentCount + 1, HISTORY);
    return table;
}

std::optional<X86JumpTable> X86SwitchDetector::FindRegisterJumpTable(x86_reg target) const
{
    // add rcx, rdx: the entry (rcx) plus a base (rdx)
    const int targetFamily = RegisterFamily(target);
    size_t index           = 0;
    int baseFamily         = -1;
    for (; index < MAX_ADD_DISTANCE; index++) {
        const cs_insn* previous = Previous(index);
        if (!previous || !previous->detail)
            return {};
        const cs_x86& x86 = previous->detail->x86;
        if (previous->id == X86_INS_ADD && x86.op_count == 2 && IsRegister(x86.operands[0], targetFamily) && x86.operands[1].type == X86_OP_REG) {
            baseFamily = RegisterFamily(x86.operands[1].reg);
            break;
        }
    }
    if (baseFamily < 0)
        return {};

    // mov ecx, dword ptr [rdx + rax * 4 + table_rva] / movsxd rax, dword ptr [rdx + rax * 4]: the entry
    const cs_insn* load = nullptr;
    size_t loadIndex    = 0;
    for (index++; index <= MAX_ADD_DISTANCE + MAX_LOAD_DISTANCE; index++) {
        const cs_insn* previous = Previous(index);
        if (!previous || !previous->detail)
            return {};
        const cs_x86& x86 = previous->detail->x86;
        if ((previous->id == X86_INS_MOV || previous->id == X86_INS_MOVSXD) && x86.op_count == 2 && IsRegister(x86.operands[0], targetFamily) &&
            x86.operands[1].type == X86_OP_MEM && x86.operands[1].size == 4 && RegisterFamily(x86.operands[1].mem.base) == baseFamily &&
            x86.operands[1].mem.index != X86_REG_INVALID && x86.operands[1].mem.scale == 4) {
            load      = previous;
            loadIndex = index;
            break;
        }
    }
    if (!load)
        return {};

    // lea rdx, [rip + ...]: the base, the image base (MSVC) or the table (GCC)
    std::optional<uint64> baseValue;
    for (index++; index < HISTORY; index++) {
        const cs_insn* previous = Previous(index);
        if (!previous || !previous->detail)
            break;
        const cs_x86& x86 = previous->detail->x86;
        if (previous->id == X86_INS_LEA && x86.op_count == 2 && IsRegister(x86.operands[0], baseFamily) && x86.operands[1].type == X86_OP_MEM &&
            x86.operands[1].mem.base == X86_REG_RIP && x86.operands[1].mem.index == X86_REG_INVALID) {
            baseValue = (labelBase + previous->address + previous->size + static_cast<uint64>(x86.operands[1].mem.disp)) & addressMask;
            break;
        }
    }
    if (!baseValue.has_value())
        return {};

    const cs_x86_op& entry = load->detail->x86.operands[1];
    X86JumpTable table;
    table.entrySize = 4;
    if (imageBase.has_value() && baseValue.value() == imageBase.value()) {
        table.kind         = X86JumpTable::EntryKind::ImageBaseRelative;
        table.base         = imageBase.value();
        table.tableAddress = (imageBase.value() + static_cast<uint64>(entry.mem.disp)) & addressMask;
        // movzx eax, byte ptr [rdx + rax + index_rva]: the index of the entry of every case
        const int indexFamily = RegisterFamily(entry.mem.index);
        for (size_t indexTable = loadIndex + 1; indexTable <= loadIndex + MAX_INDEX_DISTANCE; indexTable++) {
            const cs_insn* previous = Previous(indexTable);
            if (!previous || !previous->detail)
                break;
            const cs_x86& x86 = previous->detail->x86;
            if (previous->id == X86_INS_MOVZX && x86.op_count == 2 && IsRegister(x86.operands[0], indexFamily) && x86.operands[1].type == X86_OP_MEM &&
                x86.operands[1].size == 1 && RegisterFamily(x86.operands[1].mem.base) == baseFamily && x86.operands[1].mem.index != X86_REG_INVALID &&
                x86.operands[1].mem.scale == 1) {
                table.indexTableAddress = (imageBase.value() + static_cast<uint64>(x86.operands[1].mem.disp)) & addressMask;
                break;
            }
        }
    } else {
        table.kind         = X86JumpTable::EntryKind::TableRelative;
        table.tableAddress = (baseValue.value() + static_cast<uint64>(entry.mem.disp)) & addressMask;
        table.base         = table.tableAddress;
    }
    return table;
}

std::optional<uint32> X86SwitchDetector::FindCasesCount() const
{
    // cmp eax, N; ja default: N + 1 cases (jae: N cases); the index may be extended after the check (movsxd rax, ecx)
    for (size_t index = 0; index + 1 < HISTORY; index++) {
        const cs_insn* previous = Previous(index);
        if (!previous || !previous->detail)
            return {};
        if (previous->id == X86_INS_JMP || previous->id == X86_INS_RET || previous->id == X86_INS_CALL)
            return {}; // another block
        if (previous->id != X86_INS_JA && previous->id != X86_INS_JAE)
            continue;
        const cs_insn* compare = Previous(index + 1);
        if (!compare || !compare->detail || compare->id != X86_INS_CMP)
            return {};
        const cs_x86& x86 = compare->detail->x86;
        // cmp ecx, 6 / cmp dword ptr [rcx + 0x2f0], 7 (the index is loaded after the check)
        if (x86.op_count != 2 || (x86.operands[0].type != X86_OP_REG && x86.operands[0].type != X86_OP_MEM) || x86.operands[1].type != X86_OP_IMM)
            return {};
        const int64 limit = x86.operands[1].imm;
        const int64 count = previous->id == X86_INS_JA ? limit + 1 : limit;
        if (count <= 0 || count > MAX_CASES)
            return {};
        return static_cast<uint32>(count);
    }
    return {};
}

std::vector<uint64> GView::View::DissasmViewer::ReadX86JumpTableTargets(
      const X86JumpTable& table, const std::function<std::optional<uint64>(uint64, uint8)>& readValue, const std::function<bool(uint64)>& isTarget)
{
    auto readEntry = [&](uint64 entryIndex) -> std::optional<uint64> {
        const auto value = readValue(table.tableAddress + entryIndex * table.entrySize, table.entrySize);
        if (!value.has_value())
            return {};
        switch (table.kind) {
        case X86JumpTable::EntryKind::Absolute:
            return value.value();
        case X86JumpTable::EntryKind::ImageBaseRelative:
            return table.base + static_cast<uint32>(value.value());
        case X86JumpTable::EntryKind::TableRelative:
            return table.base + static_cast<uint64>(static_cast<int64>(static_cast<int32>(static_cast<uint32>(value.value()))));
        }
        return {};
    };

    std::vector<uint64> targets;
    if (table.indexTableAddress.has_value()) {
        // the cases count is the size of the index table; an entry is read once for all the cases that use it
        if (!table.casesCount.has_value())
            return {};
        std::unordered_map<uint64, uint64> entries;
        targets.reserve(table.casesCount.value());
        for (uint32 caseIndex = 0; caseIndex < table.casesCount.value(); caseIndex++) {
            const auto entryIndex = readValue(table.indexTableAddress.value() + caseIndex, 1);
            if (!entryIndex.has_value())
                return {};
            auto entry = entries.find(entryIndex.value());
            if (entry == entries.end()) {
                const auto target = readEntry(entryIndex.value());
                if (!target.has_value() || !isTarget(target.value()))
                    return {}; // not a jump table
                entry = entries.emplace(entryIndex.value(), target.value()).first;
            }
            targets.push_back(entry->second);
        }
        return targets;
    }

    const uint32 count = std::min(table.casesCount.value_or(MAX_UNBOUNDED_CASES), MAX_CASES);
    targets.reserve(count);
    for (uint32 caseIndex = 0; caseIndex < count; caseIndex++) {
        const auto target = readEntry(caseIndex);
        if (!target.has_value() || !isTarget(target.value())) {
            if (table.casesCount.has_value())
                return {}; // a bounded table has only cases: this is not a jump table
            break;
        }
        targets.push_back(target.value());
    }
    return targets;
}
