#include "DissasmX86LocalVariables.hpp"
#include "X86InstructionInfo.hpp"
#include <algorithm>
#include <memory>

using namespace GView::View::DissasmViewer;

namespace
{
constexpr uint32 MAX_PROLOGUE_PADDING_INSTRUCTIONS = 2;        // mov edi, edi (hot patching), endbr32/64, nop before push ebp
constexpr uint32 MAX_FUNCTION_INSTRUCTIONS         = 1u << 20; // hard stop for malformed code
constexpr int64 MAX_FRAME_DISPLACEMENT             = 0x100000; // larger displacements are not stack slots
constexpr size_t ACCESSES_COMPACT_THRESHOLD        = 4096;     // bounds the memory used while scanning huge functions

struct FrameAccess {
    int32 frameOffset;
    uint16 size;
};

struct CsInsnDeleter {
    void operator()(cs_insn* insn) const
    {
        cs_free(insn, 1);
    }
};

bool IsFrameRegister(x86_reg reg, bool is64)
{
    // any write to a part of the frame register breaks the frame (writing ebp also clears the upper half of rbp)
    if (is64)
        return reg == X86_REG_RBP || reg == X86_REG_EBP || reg == X86_REG_BP || reg == X86_REG_BPL;
    return reg == X86_REG_EBP || reg == X86_REG_BP;
}

bool IsRegisterOperand(const cs_x86& x86, uint8 index, x86_reg reg)
{
    return index < x86.op_count && x86.operands[index].type == X86_OP_REG && x86.operands[index].reg == reg;
}

bool IsProloguePadding(const cs_insn* insn)
{
    switch (insn->id) {
    case X86_INS_NOP:
    case X86_INS_ENDBR32:
    case X86_INS_ENDBR64:
        return true;
    case X86_INS_MOV:
        return IsRegisterOperand(insn->detail->x86, 0, X86_REG_EDI) && IsRegisterOperand(insn->detail->x86, 1, X86_REG_EDI);
    default:
        return false;
    }
}

// sorts the accesses by offset keeping one entry per offset (the widest access); false when the frame has too many slots to be trusted
bool CompactAccesses(std::vector<FrameAccess>& accesses)
{
    std::sort(accesses.begin(), accesses.end(), [](const FrameAccess& a, const FrameAccess& b) {
        if (a.frameOffset != b.frameOffset)
            return a.frameOffset < b.frameOffset;
        return a.size > b.size;
    });
    // the first entry of every offset is the widest one
    accesses.erase(
          std::unique(accesses.begin(), accesses.end(), [](const FrameAccess& a, const FrameAccess& b) { return a.frameOffset == b.frameOffset; }),
          accesses.end());
    return accesses.size() <= DISSASM_MAX_LOCAL_VARIABLES_PER_FUNCTION;
}

std::string_view GetOperandSizeName(uint16 size)
{
    switch (size) {
    case 2:
        return "word";
    case 4:
        return "dword";
    case 6:
        return "fword";
    case 8:
        return "qword";
    case 10:
        return "xword";
    case 16:
        return "xmmword";
    case 32:
        return "ymmword";
    case 64:
        return "zmmword";
    default:
        return "byte"; // 1 or only the address was taken (buffers / structures), same as IDA
    }
}

bool IsNameStartCharacter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '@' || c == '$' || c == '?';
}

bool IsNameCharacter(char c)
{
    return IsNameStartCharacter(c) || (c >= '0' && c <= '9') || c == '.';
}
} // namespace

bool GView::View::DissasmViewer::AnalyzeX86FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, bool is64, DissasmFunctionFrame& frame)
{
    frame.startAddress = codeAddress;
    frame.endAddress   = codeAddress;
    frame.variables.clear();
    if (!code || codeSize == 0 || limitAddress <= codeAddress)
        return false;

    const std::unique_ptr<cs_insn, CsInsnDeleter> insn(cs_malloc(detailHandle));
    if (!insn || !insn->detail)
        return false; // the handle must have CS_OPT_DETAIL enabled

    const x86_reg frameRegister                                    = is64 ? X86_REG_RBP : X86_REG_EBP;
    const x86_reg stackRegister                                    = is64 ? X86_REG_RSP : X86_REG_ESP;
    const int64 firstArgumentOffset                                = is64 ? 16 : 8; // saved frame pointer + return address
    const uint8* data                                              = code;
    size_t size                                                    = static_cast<size_t>(std::min<uint64>(codeSize, limitAddress - codeAddress));
    uint64 address                                                 = codeAddress;
    uint64 furthestBranchTarget                                    = 0;
    uint64 endAddress                                              = codeAddress;
    uint32 decodedInstructions                                     = 0;
    enum class State : uint8 { ExpectPush, ExpectMov, Body } state = State::ExpectPush;

    std::vector<FrameAccess> accesses;
    accesses.reserve(32);

    while (decodedInstructions < MAX_FUNCTION_INSTRUCTIONS && cs_disasm_iter(detailHandle, &data, &size, &address, insn.get())) {
        decodedInstructions++;
        const cs_insn* current   = insn.get();
        const cs_x86& x86        = current->detail->x86;
        const uint64 nextAddress = current->address + current->size;
        endAddress               = nextAddress;

        if (state == State::ExpectPush) {
            if (current->id == X86_INS_PUSH && IsRegisterOperand(x86, 0, frameRegister)) {
                state = State::ExpectMov;
                continue;
            }
            if (current->id == X86_INS_ENTER) {
                state = State::Body;
                continue;
            }
            if (decodedInstructions <= MAX_PROLOGUE_PADDING_INSTRUCTIONS && IsProloguePadding(current))
                continue;
            return false;
        }
        if (state == State::ExpectMov) {
            if (current->id == X86_INS_MOV && IsRegisterOperand(x86, 0, frameRegister) && IsRegisterOperand(x86, 1, stackRegister)) {
                state = State::Body;
                continue;
            }
            return false;
        }

        bool writesFrameRegister = false;
        for (uint8 i = 0; i < x86.op_count; i++) {
            const cs_x86_op& op = x86.operands[i];
            if (op.type == X86_OP_MEM) {
                const x86_op_mem& mem = op.mem;
                if (mem.base != frameRegister || mem.index != X86_REG_INVALID)
                    continue;
                if (mem.segment != X86_REG_INVALID && mem.segment != X86_REG_SS)
                    continue;
                const int64 displacement = mem.disp;
                const bool isLocal       = displacement < 0 && displacement >= -MAX_FRAME_DISPLACEMENT;
                const bool isArgument    = displacement >= firstArgumentOffset && displacement <= MAX_FRAME_DISPLACEMENT;
                if (!isLocal && !isArgument)
                    continue;
                // lea only takes the address of the slot (buffers, structures): its size is unknown
                accesses.push_back({ static_cast<int32>(displacement), static_cast<uint16>(current->id == X86_INS_LEA ? 0 : op.size) });
                if (accesses.size() >= ACCESSES_COMPACT_THRESHOLD && !CompactAccesses(accesses))
                    return false;
            } else if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE) && IsFrameRegister(op.reg, is64)) {
                writesFrameRegister = true;
            }
        }
        // the frame register is rebuilt (another frame or optimized code reusing it): the following slots are not this frame's
        if (writesFrameRegister && current->id != X86_INS_POP)
            break;

        if (cs_insn_group(detailHandle, current, CS_GRP_JUMP) && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM) {
            const uint64 target = static_cast<uint64>(x86.operands[0].imm);
            if (target > current->address && target < limitAddress)
                furthestBranchTarget = std::max(furthestBranchTarget, target);
        }

        bool endsFlow = false;
        switch (current->id) {
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_INT3:
        case X86_INS_HLT:
        case X86_INS_UD2:
            endsFlow = true;
            break;
        default:
            break;
        }
        // the code that follows belongs to the function only when one of its branches reaches it
        if (endsFlow && furthestBranchTarget < nextAddress)
            break;
    }

    if (state != State::Body)
        return false;
    if (!CompactAccesses(accesses))
        return false;

    frame.endAddress = endAddress;
    frame.variables.reserve(accesses.size());
    for (const auto& access : accesses) {
        DissasmLocalVariable variable{ access.frameOffset, access.size, {} };
        FormatDefaultLocalVariableName(access.frameOffset, is64, variable.name);
        frame.variables.push_back(std::move(variable));
    }
    return true;
}

void GView::View::DissasmViewer::FormatDefaultLocalVariableName(int32 frameOffset, bool is64, std::string& name)
{
    const int64 offset              = frameOffset;
    const int64 firstArgumentOffset = is64 ? 16 : 8;
    char buffer[32];
    if (offset < 0)
        snprintf(buffer, sizeof(buffer), "var_%llX", static_cast<unsigned long long>(-offset));
    else
        snprintf(buffer, sizeof(buffer), "arg_%llX", static_cast<unsigned long long>(offset >= firstArgumentOffset ? offset - firstArgumentOffset : offset));
    name = buffer;
}

void GView::View::DissasmViewer::FormatLocalVariableDefinition(const DissasmLocalVariable& variable, std::string& text, uint32& nameSize)
{
    text     = variable.name;
    nameSize = static_cast<uint32>(variable.name.size());
    text += " = ";
    text += GetOperandSizeName(variable.size);
    text += " ptr ";

    // same number format as the capstone operands ([ebp - 8], [ebp - 0x44])
    int64 offset = variable.frameOffset;
    if (offset < 0) {
        text += '-';
        offset = -offset;
    }
    char buffer[32];
    if (offset <= 9)
        snprintf(buffer, sizeof(buffer), "%llu", static_cast<unsigned long long>(offset));
    else
        snprintf(buffer, sizeof(buffer), "0x%llx", static_cast<unsigned long long>(offset));
    text += buffer;
}

bool GView::View::DissasmViewer::IsValidLocalVariableName(std::string_view name)
{
    if (name.empty() || name.size() > DISSASM_MAX_LOCAL_VARIABLE_NAME_SIZE || !IsNameStartCharacter(name[0]))
        return false;
    for (const char c : name)
        if (!IsNameCharacter(c))
            return false;
    return true;
}

bool GView::View::DissasmViewer::FindX86FrameOperand(std::string_view operands, bool is64, X86FrameOperand& result)
{
    const std::string_view frameBase = is64 ? "[rbp" : "[ebp";
    const size_t start               = operands.find(frameBase);
    if (start == std::string_view::npos)
        return false;

    const size_t length = operands.size();
    size_t position     = start + frameBase.size();
    // "[ebp]" is the saved frame pointer and "[ebp + eax*4 ...]" is not a single slot
    if (position + 3 > length || operands[position] != ' ' || (operands[position + 1] != '+' && operands[position + 1] != '-') || operands[position + 2] != ' ')
        return false;
    const bool isNegative = operands[position + 1] == '-';
    position += 3;

    constexpr uint64 MAX_VALUE = 0x7FFFFFFF;
    uint64 value               = 0;
    uint32 digits              = 0;
    if (position + 1 < length && operands[position] == '0' && operands[position + 1] == 'x') {
        position += 2;
        for (; position < length; position++, digits++) {
            const char c = operands[position];
            uint32 digit;
            if (c >= '0' && c <= '9')
                digit = c - '0';
            else if (c >= 'a' && c <= 'f')
                digit = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                digit = c - 'A' + 10;
            else
                break;
            value = value * 16 + digit;
            if (value > MAX_VALUE)
                return false;
        }
    } else {
        for (; position < length && operands[position] >= '0' && operands[position] <= '9'; position++, digits++) {
            value = value * 10 + static_cast<uint32>(operands[position] - '0');
            if (value > MAX_VALUE)
                return false;
        }
    }
    if (digits == 0 || position >= length || operands[position] != ']')
        return false;

    result.replaceStart = static_cast<uint32>(start + frameBase.size());
    result.replaceEnd   = static_cast<uint32>(position);
    result.frameOffset  = isNegative ? -static_cast<int32>(value) : static_cast<int32>(value);
    return true;
}

namespace
{
uint16 Arm64RegisterSize(arm64_reg reg)
{
    if ((reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) || reg == ARM64_REG_WZR || reg == ARM64_REG_WSP)
        return 4;
    if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31)
        return 1;
    if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31)
        return 2;
    if (reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31)
        return 4;
    if (reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31)
        return 16;
    return 8; // x0 .. x28, fp, lr, xzr, d0 .. d31
}

// the size of every register moved by a load / store (stp / ldp: two of them); 0 for the other instructions
uint16 Arm64AccessSize(const cs_insn& insn, bool& isPair)
{
    const cs_arm64& arm64 = insn.detail->arm64;
    isPair                = false;
    switch (insn.id) {
    case ARM64_INS_LDRB:
    case ARM64_INS_STRB:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDURB:
    case ARM64_INS_STURB:
    case ARM64_INS_LDURSB:
        return 1;
    case ARM64_INS_LDRH:
    case ARM64_INS_STRH:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDURH:
    case ARM64_INS_STURH:
    case ARM64_INS_LDURSH:
        return 2;
    case ARM64_INS_LDRSW:
    case ARM64_INS_LDURSW:
        return 4;
    case ARM64_INS_LDR:
    case ARM64_INS_STR:
    case ARM64_INS_LDUR:
    case ARM64_INS_STUR:
        return arm64.op_count > 0 && arm64.operands[0].type == ARM64_OP_REG ? Arm64RegisterSize(arm64.operands[0].reg) : 0;
    case ARM64_INS_LDP:
    case ARM64_INS_STP:
    case ARM64_INS_LDNP:
    case ARM64_INS_STNP:
        isPair = true;
        return arm64.op_count > 0 && arm64.operands[0].type == ARM64_OP_REG ? Arm64RegisterSize(arm64.operands[0].reg) : 0;
    default:
        return 0;
    }
}

// x19 .. x30, d8 .. d15: the registers a function saves (stp x20, x19, [sp, #0x10] keeps them, these slots are not variables)
bool IsArm64CalleeSaved(arm64_reg reg)
{
    return (reg >= ARM64_REG_X19 && reg <= ARM64_REG_X28) || reg == ARM64_REG_X29 || reg == ARM64_REG_X30 || (reg >= ARM64_REG_D8 && reg <= ARM64_REG_D15);
}
} // namespace

bool GView::View::DissasmViewer::AnalyzeArm64FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, DissasmFunctionFrame& frame)
{
    frame.startAddress = codeAddress;
    frame.endAddress   = codeAddress;
    frame.stackOffset  = 0;
    frame.variables.clear();
    if (!code || codeSize == 0 || limitAddress <= codeAddress)
        return false;
    const std::unique_ptr<cs_insn, CsInsnDeleter> insn(cs_malloc(detailHandle));
    if (!insn || !insn->detail)
        return false;

    constexpr uint32 MAX_PROLOGUE_INSTRUCTIONS = 12;
    const uint8* data           = code;
    size_t size                 = static_cast<size_t>(std::min<uint64>(codeSize, limitAddress - codeAddress));
    uint64 address              = codeAddress;
    uint64 furthestBranchTarget = 0;
    uint32 decodedInstructions  = 0;
    bool hasFrame               = false;
    bool stackOnly              = false; // no frame register: the slots are relative to the sp of the entry (a leaf function)
    int64 entryDelta            = 0;     // sp - the sp of the entry, during the prologue
    int64 stackPointer          = 0; // sp - x29, once the frame register is set
    std::optional<int64> bodyStackPointer;
    std::vector<FrameAccess> accesses;
    accesses.reserve(32);

    while (decodedInstructions < MAX_FUNCTION_INSTRUCTIONS && size >= 4) {
        size_t left         = 4;
        const uint8* bytes  = data;
        uint64 at           = address;
        if (!cs_disasm_iter(detailHandle, &bytes, &left, &at, insn.get()))
            break; // a data word: not a frame we can follow
        data += 4;
        size -= 4;
        address += 4;
        decodedInstructions++;
        frame.endAddress      = address;
        const cs_insn& current = *insn;
        const cs_arm64& arm64 = current.detail->arm64;
        const auto isRegister = [&arm64](uint8 index, arm64_reg reg) {
            return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_REG && arm64.operands[index].reg == reg;
        };
        const auto immediateAt = [&arm64](uint8 index) -> std::optional<int64> {
            return index < arm64.op_count && arm64.operands[index].type == ARM64_OP_IMM ? std::optional<int64>(arm64.operands[index].imm) : std::nullopt;
        };

        // sub sp, sp, #N / add sp, sp, #N / the writeback of [sp, #-N]! and [sp], #N
        int64 spChange = 0;
        if ((current.id == ARM64_INS_SUB || current.id == ARM64_INS_ADD) && isRegister(0, ARM64_REG_SP) && isRegister(1, ARM64_REG_SP) && immediateAt(2))
            spChange = current.id == ARM64_INS_SUB ? -immediateAt(2).value() : immediateAt(2).value();
        else if (arm64.writeback) {
            for (uint8 index = 0; index < arm64.op_count; index++)
                if (arm64.operands[index].type == ARM64_OP_MEM && arm64.operands[index].mem.base == ARM64_REG_SP)
                    spChange = arm64.post_index ? immediateAt(static_cast<uint8>(arm64.op_count - 1)).value_or(0) : arm64.operands[index].mem.disp;
        }

        if (!hasFrame) {
            // mov x29, sp / add x29, sp, #M: the frame register (the frame record x29, x30 is at x29)
            if (isRegister(0, ARM64_REG_X29) && isRegister(1, ARM64_REG_SP) &&
                (current.id == ARM64_INS_MOV || (current.id == ARM64_INS_ADD && immediateAt(2).has_value()))) {
                const int64 offset = current.id == ARM64_INS_ADD ? immediateAt(2).value() : 0;
                stackPointer       = -offset;
                hasFrame           = true;
                continue;
            }
            // the prologue: sub sp, stp / str of the saved registers, pacibsp, bti
            bool savesOnStack = false;
            if (current.id == ARM64_INS_STP || current.id == ARM64_INS_STR)
                for (uint8 index = 0; index < arm64.op_count; index++)
                    savesOnStack |= arm64.operands[index].type == ARM64_OP_MEM && arm64.operands[index].mem.base == ARM64_REG_SP;
            const bool isPrologue = spChange != 0 || savesOnStack || current.id == ARM64_INS_PACIBSP || current.id == ARM64_INS_PACIASP ||
                                    current.id == ARM64_INS_BTI;
            if (isPrologue && decodedInstructions < MAX_PROLOGUE_INSTRUCTIONS) {
                entryDelta += spChange;
                continue;
            }
            if (entryDelta >= 0)
                return false; // no frame: the locals (if any) are in registers
            // sub sp, sp, #N without a frame register: the slots are relative to the sp of the entry
            hasFrame     = true;
            stackOnly    = true;
            stackPointer = entryDelta;
            spChange     = 0; // counted in the prologue
        }
        stackPointer += spChange;

        bool writesFrameRegister = false;
        bool isPair              = false;
        const uint16 accessSize  = Arm64AccessSize(current, isPair);
        const bool savesRegisters = isPair && arm64.op_count > 1 && arm64.operands[0].type == ARM64_OP_REG && IsArm64CalleeSaved(arm64.operands[0].reg);
        for (uint8 index = 0; index < arm64.op_count; index++) {
            const cs_arm64_op& op = arm64.operands[index];
            if (op.type == ARM64_OP_REG && (op.access & CS_AC_WRITE) && op.reg == ARM64_REG_X29)
                writesFrameRegister = true;
            if (op.type != ARM64_OP_MEM || op.mem.index != ARM64_REG_INVALID || arm64.writeback || savesRegisters || accessSize == 0)
                continue;
            int64 offset = 0;
            if (op.mem.base == ARM64_REG_X29 && !stackOnly)
                offset = op.mem.disp;
            else if (op.mem.base == ARM64_REG_SP) {
                // the slots addressed through sp are kept in x29 offsets: sp stays the same in the body of the function
                if (!bodyStackPointer.has_value())
                    bodyStackPointer = stackPointer;
                if (stackPointer != bodyStackPointer.value())
                    continue;
                offset = op.mem.disp + stackPointer;
            } else
                continue;
            if (offset >= 0 && (stackOnly || offset < 16))
                continue; // the frame record (the saved x29 and x30); a function without a frame register: the slots of its caller
            if (offset < -MAX_FRAME_DISPLACEMENT || offset > MAX_FRAME_DISPLACEMENT)
                continue;
            accesses.push_back({ static_cast<int32>(offset), accessSize });
            if (isPair)
                accesses.push_back({ static_cast<int32>(offset + accessSize), accessSize });
        }
        // add x0, sp, #0x10 / sub x0, x29, #0x10: the address of a slot (a buffer, a structure): its size is unknown
        if ((current.id == ARM64_INS_ADD || current.id == ARM64_INS_SUB) && arm64.op_count == 3 && immediateAt(2) &&
            !isRegister(0, ARM64_REG_SP) && !isRegister(0, ARM64_REG_X29)) {
            const int64 value = current.id == ARM64_INS_SUB ? -immediateAt(2).value() : immediateAt(2).value();
            if (isRegister(1, ARM64_REG_X29) && value < 0 && !stackOnly)
                accesses.push_back({ static_cast<int32>(value), 0 });
            else if (isRegister(1, ARM64_REG_SP) && bodyStackPointer.value_or(stackPointer) == stackPointer && value + stackPointer < 0) {
                if (!bodyStackPointer.has_value())
                    bodyStackPointer = stackPointer;
                accesses.push_back({ static_cast<int32>(value + stackPointer), 0 });
            }
        }
        if (accesses.size() >= ACCESSES_COMPACT_THRESHOLD && !CompactAccesses(accesses))
            return false;
        if (writesFrameRegister && current.id != ARM64_INS_LDP && !stackOnly)
            break; // another frame (the ldp x29, x30 of the epilogue restores it)

        // the branches inside the function: the code after a ret / b belongs to it when one of them reaches it
        const auto flow = GetArm64Flow(current);
        const auto operands = GetArm64OperandsInfo(current);
        if ((flow == X86Flow::ConditionalJump || flow == X86Flow::Jump) && operands.directTarget.has_value()) {
            const uint64 target = operands.directTarget.value();
            if (target > current.address && target < limitAddress)
                furthestBranchTarget = std::max(furthestBranchTarget, target);
        }
        if ((flow == X86Flow::Return || flow == X86Flow::Jump) && furthestBranchTarget < address)
            break;
    }
    if (!hasFrame || !CompactAccesses(accesses))
        return false;
    frame.stackOffset       = static_cast<int32>(bodyStackPointer.value_or(stackPointer));
    frame.usesFrameRegister = !stackOnly;
    frame.variables.reserve(accesses.size());
    for (const auto& access : accesses) {
        DissasmLocalVariable variable{ access.frameOffset, access.size, {} };
        FormatDefaultLocalVariableName(access.frameOffset, true, variable.name);
        frame.variables.push_back(std::move(variable));
    }
    return true;
}

bool GView::View::DissasmViewer::FindArm64FrameOperand(std::string_view operands, Arm64FrameOperand& result)
{
    return FindArmFrameOperand(operands, "x29", result);
}

bool GView::View::DissasmViewer::FindArmFrameOperand(std::string_view operands, std::string_view frameRegister, Arm64FrameOperand& result)
{
    // [x29, #-0x10] / [fp, #-4] / [sp, #0x18] / [sp]: one slot (not the writeback forms [sp, #-0x10]! / [sp], #0x10 of a prologue)
    for (int pass = 0; pass < 2; pass++) {
        const std::string_view base = pass == 0 ? frameRegister : std::string_view("sp");
        if (base.empty())
            continue;
        for (size_t start = operands.find('['); start != std::string_view::npos; start = operands.find('[', start + 1)) {
            if (operands.substr(start + 1, base.size()) != base)
                continue;
            size_t position     = start + 1 + base.size();
            const size_t length = operands.size();
            if (position < length && operands[position] == ']') { // [sp]: the displacement 0, ", #name" is inserted
                if (position + 1 < length && (operands[position + 1] == '!' || operands[position + 1] == ','))
                    return false;
                result.replaceStart        = static_cast<uint32>(position);
                result.replaceEnd          = static_cast<uint32>(position);
                result.displacement        = 0;
                result.isStackPointerBased = pass == 1;
                result.needsSeparator      = true;
                return true;
            }
            if (operands.substr(position, 3) != ", #")
                continue;
            position += 3;
            const size_t replaceStart = position;
            const bool isNegative     = position < length && operands[position] == '-';
            if (isNegative)
                position++;
            uint64 value     = 0;
            uint32 digits    = 0;
            const bool isHex = position + 1 < length && operands[position] == '0' && operands[position + 1] == 'x';
            if (isHex)
                position += 2;
            for (; position < length; position++, digits++) {
                const char c = operands[position];
                uint32 digit = 0;
                if (c >= '0' && c <= '9')
                    digit = static_cast<uint32>(c - '0');
                else if (isHex && c >= 'a' && c <= 'f')
                    digit = static_cast<uint32>(c - 'a' + 10);
                else
                    break;
                value = value * (isHex ? 16 : 10) + digit;
                if (value > 0x7FFFFFFF)
                    return false;
            }
            if (digits == 0 || position >= length || operands[position] != ']' || (position + 1 < length && operands[position + 1] == '!'))
                return false;
            result.replaceStart        = static_cast<uint32>(replaceStart);
            result.replaceEnd          = static_cast<uint32>(position);
            result.displacement        = isNegative ? -static_cast<int32>(value) : static_cast<int32>(value);
            result.isStackPointerBased = pass == 1;
            result.needsSeparator      = false;
            return true;
        }
    }
    return false;
}

namespace
{
// the bytes moved by a 32 bit ARM load / store (ldrd / strd: two words); 0 for the other instructions
uint16 Arm32AccessSize(unsigned int id, bool& isPair)
{
    isPair = false;
    switch (id) {
    case ARM_INS_LDRB:
    case ARM_INS_STRB:
    case ARM_INS_LDRSB:
        return 1;
    case ARM_INS_LDRH:
    case ARM_INS_STRH:
    case ARM_INS_LDRSH:
        return 2;
    case ARM_INS_LDR:
    case ARM_INS_STR:
        return 4;
    case ARM_INS_LDRD:
    case ARM_INS_STRD:
        isPair = true;
        return 4;
    default:
        return 0;
    }
}

// push {r4, r11, lr} / stmdb sp!, {...}: 4 bytes for every register of the list
int64 Arm32PushedBytes(const cs_arm& arm, bool skipFirst)
{
    int64 count = 0;
    for (uint8 index = skipFirst ? 1 : 0; index < arm.op_count; index++)
        if (arm.operands[index].type == ARM_OP_REG)
            count++;
    return count * 4;
}
} // namespace

bool GView::View::DissasmViewer::AnalyzeArm32FunctionFrame(
      csh detailHandle, const uint8* code, size_t codeSize, uint64 codeAddress, uint64 limitAddress, bool thumb, DissasmFunctionFrame& frame)
{
    frame.startAddress  = codeAddress;
    frame.endAddress    = codeAddress;
    frame.stackOffset   = 0;
    frame.frameRegister = 0;
    frame.variables.clear();
    if (!code || codeSize == 0 || limitAddress <= codeAddress)
        return false;
    if (cs_option(detailHandle, CS_OPT_MODE, thumb ? CS_MODE_THUMB : CS_MODE_ARM) != CS_ERR_OK)
        return false;
    const std::unique_ptr<cs_insn, CsInsnDeleter> insn(cs_malloc(detailHandle));
    if (!insn || !insn->detail)
        return false;

    constexpr uint32 MAX_PROLOGUE_INSTRUCTIONS = 8;
    const uint8* data           = code;
    size_t size                 = static_cast<size_t>(std::min<uint64>(codeSize, limitAddress - codeAddress));
    uint64 address              = codeAddress;
    uint64 furthestBranchTarget = 0;
    uint32 decodedInstructions  = 0;
    bool hasFrame               = false;
    bool stackOnly              = false;
    arm_reg frameRegister       = ARM_REG_INVALID;
    int64 entryDelta            = 0; // sp - the sp of the entry, during the prologue
    int64 stackPointer          = 0; // sp - the frame register (sp - the sp of the entry without one)
    std::optional<int64> bodyStackPointer;
    std::vector<FrameAccess> accesses;
    accesses.reserve(32);

    while (decodedInstructions < MAX_FUNCTION_INSTRUCTIONS && size >= 2) {
        const uint8* bytes = data;
        size_t left        = std::min<size_t>(size, 4);
        uint64 at          = address;
        if (!cs_disasm_iter(detailHandle, &bytes, &left, &at, insn.get()))
            break; // a data word (a literal pool): the frame is not followed further
        const size_t length = insn->size;
        data += length;
        size -= length;
        address += length;
        decodedInstructions++;
        frame.endAddress       = address;
        const cs_insn& current = *insn;
        const cs_arm& arm      = current.detail->arm;
        const auto isRegister  = [&arm](uint8 index, arm_reg reg) {
            return index < arm.op_count && arm.operands[index].type == ARM_OP_REG && arm.operands[index].reg == reg;
        };
        const auto immediateAt = [&arm](uint8 index) -> std::optional<int64> {
            return index < arm.op_count && arm.operands[index].type == ARM_OP_IMM ? std::optional<int64>(arm.operands[index].imm) : std::nullopt;
        };
        // sub sp, sp, #N (Thumb: sub sp, #N) / add sp, ... / push / pop / the writeback of [sp, #-4]!
        int64 spChange = 0;
        if ((current.id == ARM_INS_SUB || current.id == ARM_INS_ADD) && isRegister(0, ARM_REG_SP)) {
            const auto value = arm.op_count == 2 ? immediateAt(1) : (isRegister(1, ARM_REG_SP) ? immediateAt(2) : std::nullopt);
            if (value.has_value())
                spChange = current.id == ARM_INS_SUB ? -value.value() : value.value();
        } else if (current.id == ARM_INS_PUSH)
            spChange = -Arm32PushedBytes(arm, false);
        else if (current.id == ARM_INS_POP)
            spChange = Arm32PushedBytes(arm, false);
        else if (current.id == ARM_INS_STMDB && arm.writeback && isRegister(0, ARM_REG_SP))
            spChange = -Arm32PushedBytes(arm, true);
        else if (arm.writeback) {
            for (uint8 index = 0; index < arm.op_count; index++)
                if (arm.operands[index].type == ARM_OP_MEM && arm.operands[index].mem.base == ARM_REG_SP)
                    spChange = arm.post_index ? immediateAt(static_cast<uint8>(arm.op_count - 1)).value_or(0) : arm.operands[index].mem.disp;
        }

        if (!hasFrame) {
            // mov r11, sp / add r11, sp, #M (ARM) / mov r7, sp / add r7, sp, #M (Thumb): the frame register, the saved r11 / r7 and lr at it
            const bool setsR11 = isRegister(0, ARM_REG_R11), setsR7 = isRegister(0, ARM_REG_R7);
            if ((setsR11 || setsR7) && isRegister(1, ARM_REG_SP) && (current.id == ARM_INS_MOV || (current.id == ARM_INS_ADD && immediateAt(2).has_value()))) {
                stackPointer  = current.id == ARM_INS_ADD ? -immediateAt(2).value() : 0;
                frameRegister = setsR11 ? ARM_REG_R11 : ARM_REG_R7;
                hasFrame      = true;
                continue;
            }
            const bool isPrologue = spChange != 0; // push, sub sp, str lr, [sp, #-4]!
            if (isPrologue && decodedInstructions < MAX_PROLOGUE_INSTRUCTIONS) {
                entryDelta += spChange;
                continue;
            }
            if (entryDelta >= 0)
                return false; // no frame: the locals (if any) are in registers
            hasFrame     = true; // sub sp without a frame register: the slots from the sp of the entry
            stackOnly    = true;
            stackPointer = entryDelta;
            spChange     = 0;
        }
        stackPointer += spChange;

        bool isPair             = false;
        const uint16 accessSize = Arm32AccessSize(current.id, isPair);
        bool writesFrameRegister = false;
        for (uint8 index = 0; index < arm.op_count; index++) {
            const cs_arm_op& op = arm.operands[index];
            if (op.type == ARM_OP_REG && (op.access & CS_AC_WRITE) && frameRegister != ARM_REG_INVALID && op.reg == frameRegister)
                writesFrameRegister = true;
            if (op.type != ARM_OP_MEM || op.mem.index != ARM_REG_INVALID || arm.writeback || accessSize == 0)
                continue;
            int64 offset = 0;
            if (!stackOnly && op.mem.base == frameRegister)
                offset = op.mem.disp;
            else if (op.mem.base == ARM_REG_SP) {
                if (!bodyStackPointer.has_value())
                    bodyStackPointer = stackPointer;
                if (stackPointer != bodyStackPointer.value())
                    continue;
                offset = op.mem.disp + stackPointer;
            } else
                continue;
            if (offset >= 0 && (stackOnly || offset < 8))
                continue; // the saved frame register and lr; a function without a frame register: the slots of its caller
            if (offset < -MAX_FRAME_DISPLACEMENT || offset > MAX_FRAME_DISPLACEMENT)
                continue;
            accesses.push_back({ static_cast<int32>(offset), accessSize });
            if (isPair)
                accesses.push_back({ static_cast<int32>(offset + accessSize), accessSize });
        }
        if (accesses.size() >= ACCESSES_COMPACT_THRESHOLD && !CompactAccesses(accesses))
            return false;
        if (writesFrameRegister && current.id != ARM_INS_POP && current.id != ARM_INS_LDM && !stackOnly)
            break; // another frame (the pop of the epilogue restores the register)

        // the branches inside the function: the code after a return / b belongs to it when one of them reaches it
        const auto flow     = GetArm32Flow(current);
        const auto operands = GetArm32OperandsInfo(current, thumb);
        if ((flow == X86Flow::ConditionalJump || flow == X86Flow::Jump) && operands.directTarget.has_value()) {
            const uint64 target = operands.directTarget.value();
            if (target > current.address && target < limitAddress)
                furthestBranchTarget = std::max(furthestBranchTarget, target);
        }
        if ((flow == X86Flow::Return || flow == X86Flow::Jump) && furthestBranchTarget < address)
            break;
    }
    if (!hasFrame || !CompactAccesses(accesses))
        return false;
    frame.stackOffset       = static_cast<int32>(bodyStackPointer.value_or(stackPointer));
    frame.usesFrameRegister = !stackOnly;
    frame.frameRegister     = static_cast<uint8>(frameRegister == ARM_REG_R11 ? 11 : (frameRegister == ARM_REG_R7 ? 7 : 0));
    frame.variables.reserve(accesses.size());
    for (const auto& access : accesses) {
        DissasmLocalVariable variable{ access.frameOffset, access.size, {} };
        FormatDefaultLocalVariableName(access.frameOffset, false, variable.name); // the arguments above the saved register and lr: arg_0
        frame.variables.push_back(std::move(variable));
    }
    return true;
}
