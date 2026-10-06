#include "DissasmX86LocalVariables.hpp"
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

    const x86_reg frameRegister       = is64 ? X86_REG_RBP : X86_REG_EBP;
    const x86_reg stackRegister       = is64 ? X86_REG_RSP : X86_REG_ESP;
    const int64 firstArgumentOffset   = is64 ? 16 : 8; // saved frame pointer + return address
    const uint8* data                 = code;
    size_t size                       = static_cast<size_t>(std::min<uint64>(codeSize, limitAddress - codeAddress));
    uint64 address                    = codeAddress;
    uint64 furthestBranchTarget       = 0;
    uint64 endAddress                 = codeAddress;
    uint32 decodedInstructions        = 0;
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
    if (position + 3 > length || operands[position] != ' ' || (operands[position + 1] != '+' && operands[position + 1] != '-') ||
        operands[position + 2] != ' ')
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
