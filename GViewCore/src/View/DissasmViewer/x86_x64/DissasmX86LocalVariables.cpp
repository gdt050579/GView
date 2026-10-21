#include "DissasmX86LocalVariables.hpp"
#include "X86InstructionInfo.hpp"
#include <algorithm>
#include <array>
#include <map>
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
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      bool is64,
      DissasmFunctionFrame& frame,
      const X86FrameHelperCheck& frameHelper,
      const X86CallNoReturn& callNoReturn)
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
    uint32 helperSetup = 0, helperPushes = 0; // push 0x10; push offset scopetable / mov eax, offset handler before the frame helper
    bool sehRecord     = false;               // __SEH_prolog4: the SEH record (CPPEH_RECORD) is at [ebp - 0x18]

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
            if (decodedInstructions <= MAX_PROLOGUE_PADDING_INSTRUCTIONS && helperSetup == 0 && IsProloguePadding(current))
                continue;
            // MSVC: the frame built by a helper (push 0x10; push offset scopetable; call __SEH_prolog4 / push 8; mov eax, offset handler;
            // call __EH_prolog3 / mov eax, offset handler; call _EH_prolog)
            if (frameHelper && !is64 && helperSetup < 2 &&
                ((current->id == X86_INS_PUSH && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM) ||
                 (current->id == X86_INS_MOV && IsRegisterOperand(x86, 0, X86_REG_EAX) && x86.operands[1].type == X86_OP_IMM))) {
                helperSetup++;
                helperPushes += current->id == X86_INS_PUSH ? 1u : 0u;
                continue;
            }
            if (helperSetup > 0 && current->id == X86_INS_CALL && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM && frameHelper(*current)) {
                sehRecord = helperPushes == 2;
                state     = State::Body;
                continue;
            }
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
        case X86_INS_CALL:
            endsFlow = callNoReturn && callNoReturn(*current); // exit, abort
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

    // the fields of the SEH record of __SEH_prolog4 (IDA: ms_exc = CPPEH_RECORD ptr -0x18)
    static constexpr std::array<std::string_view, 6> SEH_RECORD_FIELDS = {
        "ms_exc.old_esp",       "ms_exc.exc_ptr", "ms_exc.registration.Next", "ms_exc.registration.ExceptionHandler", "ms_exc.registration.ScopeTable",
        "ms_exc.registration.TryLevel",
    };
    frame.endAddress = endAddress;
    frame.variables.reserve(accesses.size());
    for (const auto& access : accesses) {
        DissasmLocalVariable variable{ access.frameOffset, access.size, {} };
        if (sehRecord && access.frameOffset >= -0x18 && access.frameOffset < 0 && access.frameOffset % 4 == 0)
            variable.name = SEH_RECORD_FIELDS[(access.frameOffset + 0x18) / 4];
        else
            FormatDefaultLocalVariableName(access.frameOffset, is64, variable.name);
        frame.variables.push_back(std::move(variable));
    }
    return true;
}

namespace
{
enum class StackFrameResult : uint8 { Accepted, Rejected, Unbalanced };

// the readings of the pushes that are not arguments for sure (AnalyzeStackPointerFrame)
enum StackPushReading : uint8 {
    ENTRY_PUSHES_ARE_ARGUMENTS = 1, // push ecx at the entry: an argument of the first call instead of a local
    LATE_SAVES_ARE_ARGUMENTS   = 2, // push esi after a call (esi not written yet): an argument instead of a saved register (shrink wrapping)
};

// AnalyzeX86StackFrame with a reading of the ambiguous pushes; `ambiguousPushes` receives the readings that the function needs
StackFrameResult AnalyzeStackPointerFrame(
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      bool is64,
      DissasmFunctionFrame& frame,
      const X86CalleeStackPurge& calleePurge,
      const X86CallNoReturn& callNoReturn,
      uint8 reading,
      uint8& ambiguousPushes)
{
    frame.startAddress      = codeAddress;
    frame.endAddress        = codeAddress;
    frame.usesFrameRegister = false;
    frame.stackOffset       = 0;
    frame.variables.clear();
    frame.stackDeltas.clear();
    frame.stackAliases.clear();
    if (!code || codeSize == 0 || limitAddress <= codeAddress)
        return StackFrameResult::Rejected;
    const std::unique_ptr<cs_insn, CsInsnDeleter> insn(cs_malloc(detailHandle));
    if (!insn || !insn->detail)
        return StackFrameResult::Rejected;

    const x86_reg stackRegister = is64 ? X86_REG_RSP : X86_REG_ESP;
    const int64 pointerSize     = is64 ? 8 : 4;
    const uint8* data           = code;
    size_t size                 = static_cast<size_t>(std::min<uint64>(codeSize, limitAddress - codeAddress));
    uint64 address              = codeAddress;
    uint64 furthestBranchTarget = 0;
    uint32 decodedInstructions  = 0;
    int64 delta                 = 0; // the stack pointer - the one of the entry
    int64 deepest               = 0;
    int64 bodyDelta             = 0;     // the depth after the prologue (the saved registers, sub esp)
    bool calledYet              = false; // __chkstk is the first call; push esi after a call may be an argument
    bool leadingPushes          = true;  // the pushes at the entry (push ecx: a local, not an argument)
    uint32 writtenFamilies      = 0;     // the registers written so far (a saved register is pushed before it is written)
    int64 pushedArguments       = 0;     // 32 bit: the bytes pushed since the previous call (the arguments of the next call)
    std::optional<int64> unknownPurge;   // 32 bit: the arguments of a call to an unknown callee, popped unless the caller cleans up
    std::optional<int64> accumulator;    // mov eax, 0x2000: eax keeps it through the call __chkstk that follows
    bool accumulatorAfterCall = false;
    bool flowEnded            = false;
    bool reachedRet           = false; // 32 bit: a function chunk (the cold code of a function, reached by a jcc) has no ret
    // the registers that hold the stack pointer (mov r11, rsp / lea rbp, [rsp - 0x5f]), until they are written (a volatile one: until a call)
    struct ActiveAlias {
        x86_reg reg;
        int64 delta;
        size_t index; // in frame.stackAliases
    };
    std::vector<ActiveAlias> aliases;
    const auto aliasOf = [&aliases](unsigned int reg) -> const ActiveAlias* {
        for (const auto& alias : aliases)
            if (alias.reg == reg)
                return &alias;
        return nullptr;
    };
    std::map<uint64, std::vector<ActiveAlias>> branchAliases; // the aliases at the targets of the forward branches
    constexpr size_t MAX_STACK_ALIASES = 64;                   // a few per function (the reopened ones counted)
    std::map<uint64, int64> branchDeltas; // the depth at the targets of the forward branches
    std::vector<FrameAccess> accesses;
    accesses.reserve(32);
    frame.stackDeltas.emplace_back(codeAddress, 0);
    const auto setDelta = [&](uint64 at, int64 value) {
        delta = value;
        if (frame.stackDeltas.back().first == at)
            frame.stackDeltas.back().second = static_cast<int32>(value);
        else if (frame.stackDeltas.back().second != value)
            frame.stackDeltas.emplace_back(at, static_cast<int32>(value));
    };
    const auto isCalleeSaved = [is64](x86_reg reg) {
        if (is64)
            return reg == X86_REG_RBX || reg == X86_REG_RBP || reg == X86_REG_RSI || reg == X86_REG_RDI || reg == X86_REG_R12 ||
                   reg == X86_REG_R13 || reg == X86_REG_R14 || reg == X86_REG_R15;
        return reg == X86_REG_EBX || reg == X86_REG_EBP || reg == X86_REG_ESI || reg == X86_REG_EDI;
    };

    while (decodedInstructions < MAX_FUNCTION_INSTRUCTIONS && cs_disasm_iter(detailHandle, &data, &size, &address, insn.get())) {
        decodedInstructions++;
        const cs_insn* current   = insn.get();
        const cs_x86& x86        = current->detail->x86;
        const uint64 nextAddress = current->address + current->size;
        frame.endAddress         = nextAddress;
        const auto immediate     = [&x86](uint8 index) -> std::optional<int64> {
            return index < x86.op_count && x86.operands[index].type == X86_OP_IMM ? std::optional<int64>(x86.operands[index].imm) : std::nullopt;
        };
        const bool adjustsStack = (current->id == X86_INS_SUB || current->id == X86_INS_ADD) && IsRegisterOperand(x86, 0, stackRegister);
        const bool noReturnCall = current->id == X86_INS_CALL && callNoReturn && callNoReturn(*current); // exit, abort: the path ends

        // the depth before this instruction: after a ret / jmp the one of a branch to it, after a call to an unknown callee its arguments
        // are popped (stdcall) unless the caller cleans up (cdecl: add esp, 8)
        if (flowEnded) {
            const auto known = branchDeltas.find(current->address);
            setDelta(current->address, known != branchDeltas.end() ? known->second : (is64 ? deepest : bodyDelta));
            // the aliases of the branch to it (the body after an early epilogue: pop rbp; ret ended rbp)
            if (const auto saved = branchAliases.find(current->address); saved != branchAliases.end())
                for (const auto& alias : saved->second)
                    if (!aliasOf(alias.reg) && frame.stackAliases.size() < MAX_STACK_ALIASES) {
                        aliases.push_back({ alias.reg, alias.delta, frame.stackAliases.size() });
                        frame.stackAliases.push_back({ cs_reg_name(detailHandle, alias.reg), static_cast<int32>(alias.delta), current->address, current->address });
                    }
            flowEnded = false;
            unknownPurge.reset();
            pushedArguments = 0;
        }
        const bool pushesRegister = current->id == X86_INS_PUSH && x86.op_count == 1 && x86.operands[0].type == X86_OP_REG;
        const int pushedFamily    = pushesRegister ? GetX64RegisterFamily(x86.operands[0].reg) : -1;
        if (unknownPurge.has_value()) {
            // cdecl: the caller cleans up with the first instruction that uses the stack after the call (add esp, 8 / MSVC: pop ecx, maybe
            // after a mov edi, eax); any other use of the stack (a push, a call, a slot, a branch, a ret): the callee popped its arguments
            const bool callerCleans = (adjustsStack && current->id == X86_INS_ADD && immediate(1).has_value()) ||
                                      (current->id == X86_INS_POP && x86.op_count == 1 &&
                                       (IsRegisterOperand(x86, 0, X86_REG_ECX) || IsRegisterOperand(x86, 0, X86_REG_EDX)));
            bool usesStack = branchDeltas.count(current->address) != 0 || cs_insn_group(detailHandle, current, CS_GRP_JUMP) ||
                             cs_insn_group(detailHandle, current, CS_GRP_CALL) || cs_insn_group(detailHandle, current, CS_GRP_RET);
            for (uint8 index = 0; index < current->detail->regs_read_count && !usesStack; index++)
                usesStack = current->detail->regs_read[index] == X86_REG_ESP; // push / pop / pushfd
            for (uint8 index = 0; index < x86.op_count && !usesStack; index++)
                usesStack = (x86.operands[index].type == X86_OP_MEM && x86.operands[index].mem.base == stackRegister) ||
                            (x86.operands[index].type == X86_OP_REG && x86.operands[index].reg == stackRegister);
            if (callerCleans)
                unknownPurge.reset();
            else if (usesStack) {
                setDelta(current->address, delta + unknownPurge.value());
                unknownPurge.reset();
            }
        }
        // push esi before esi is written: a saved register (also after a call: shrink wrapping); push ecx at the entry: a local
        const bool savesRegister = pushesRegister && isCalleeSaved(x86.operands[0].reg) && pushedFamily >= 0 &&
                                   (writtenFamilies & (1u << pushedFamily)) == 0 && !(calledYet && (reading & LATE_SAVES_ARE_ARGUMENTS));
        const bool allocatesLocal = pushesRegister && leadingPushes && !(reading & ENTRY_PUSHES_ARE_ARGUMENTS) && IsRegisterOperand(x86, 0, X86_REG_ECX);
        if (allocatesLocal)
            ambiguousPushes |= ENTRY_PUSHES_ARE_ARGUMENTS;
        if (savesRegister && calledYet)
            ambiguousPushes |= LATE_SAVES_ARE_ARGUMENTS;
        if (!pushesRegister && !IsProloguePadding(current))
            leadingPushes = false;
        const bool setsAccumulator = current->id == X86_INS_MOV && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG &&
                                     GetX64RegisterFamily(x86.operands[0].reg) == 0 && x86.operands[0].size >= 4 && immediate(1).has_value();

        // the slots: [rsp + n] with the stack pointer before this instruction, [r11 - n] / [rbp + n] with the one of the alias
        for (uint8 index = 0; index < x86.op_count; index++) {
            const cs_x86_op& op = x86.operands[index];
            const auto* viaAlias = op.type == X86_OP_MEM ? aliasOf(op.mem.base) : nullptr;
            if (op.type != X86_OP_MEM || (op.mem.base != stackRegister && !viaAlias) || op.mem.index != X86_REG_INVALID ||
                (op.mem.segment != X86_REG_INVALID && op.mem.segment != X86_REG_SS))
                continue;
            const int64 offset = op.mem.disp + (viaAlias ? viaAlias->delta : delta);
            if ((offset >= 0 && offset < pointerSize) || offset < -MAX_FRAME_DISPLACEMENT || offset > MAX_FRAME_DISPLACEMENT)
                continue; // the return address
            accesses.push_back({ static_cast<int32>(offset), static_cast<uint16>(current->id == X86_INS_LEA ? 0 : op.size) });
            if (accesses.size() >= ACCESSES_COMPACT_THRESHOLD && !CompactAccesses(accesses))
                return StackFrameResult::Rejected;
        }

        // the changes of the stack pointer
        std::optional<int64> change;
        bool writesStack = false;
        switch (current->id) {
        case X86_INS_PUSH:
        case X86_INS_PUSHFD:
        case X86_INS_PUSHFQ:
            change = -pointerSize;
            if (!is64 && !savesRegister && !allocatesLocal)
                pushedArguments += pointerSize;
            break;
        case X86_INS_POP:
        case X86_INS_POPFD:
        case X86_INS_POPFQ:
            if (IsRegisterOperand(x86, 0, stackRegister)) {
                writesStack = true;
                break;
            }
            change          = pointerSize;
            pushedArguments = std::max<int64>(pushedArguments - pointerSize, 0);
            break;
        case X86_INS_PUSHAL:
            change = -32;
            break;
        case X86_INS_POPAL:
            change = 32;
            break;
        case X86_INS_SUB:
        case X86_INS_ADD:
            if (adjustsStack) {
                if (const auto value = immediate(1); value.has_value())
                    change = current->id == X86_INS_SUB ? -value.value() : value.value();
                else if (current->id == X86_INS_SUB && accumulator.has_value() && x86.op_count == 2 && x86.operands[1].type == X86_OP_REG &&
                         GetX64RegisterFamily(x86.operands[1].reg) == 0)
                    change = -accumulator.value(); // mov eax, 0x2000; call __chkstk; sub rsp, rax
                else
                    writesStack = true;
                pushedArguments = current->id == X86_INS_SUB ? 0 : std::max<int64>(pushedArguments - change.value_or(0), 0);
            }
            break;
        case X86_INS_LEA:
            if (IsRegisterOperand(x86, 0, stackRegister)) {
                const bool plain = x86.op_count == 2 && x86.operands[1].type == X86_OP_MEM && x86.operands[1].mem.index == X86_REG_INVALID;
                if (plain && x86.operands[1].mem.base == stackRegister)
                    change = x86.operands[1].mem.disp;
                else if (const auto* restored = plain ? aliasOf(x86.operands[1].mem.base) : nullptr)
                    change = restored->delta + x86.operands[1].mem.disp - delta; // the epilogue: lea rsp, [rbp + 0x50]
                else
                    writesStack = true;
            }
            break;
        case X86_INS_MOV:
            if (IsRegisterOperand(x86, 0, stackRegister)) {
                if (const auto* restored = x86.op_count == 2 && x86.operands[1].type == X86_OP_REG ? aliasOf(x86.operands[1].reg) : nullptr)
                    change = restored->delta - delta; // mov rsp, rbp: the stack pointer of the alias
                else
                    writesStack = true;
            }
            break;
        case X86_INS_CALL:
            if (is64 || noReturnCall)
                break; // the callee returns with the same rsp; a callee that does not return pops nothing
            if (x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM && static_cast<uint64>(x86.operands[0].imm) == nextAddress) {
                change = -pointerSize; // call $+5; pop ebx: the return address stays on the stack
                break;
            }
            if (const auto purge = calleePurge ? calleePurge(*current) : std::nullopt; purge.has_value())
                change = static_cast<int64>(purge.value());
            else if (!calledYet && accumulator.has_value() && !accumulatorAfterCall && accumulator.value() >= 0x1000 && pushedArguments == 0)
                change = -accumulator.value(); // mov eax, 0x2000; call __chkstk: the probe moves esp
            else if (pushedArguments > 0)
                unknownPurge = pushedArguments;
            pushedArguments = 0;
            break;
        default:
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE) &&
                    (x86.operands[index].reg == X86_REG_RSP || x86.operands[index].reg == X86_REG_ESP || x86.operands[index].reg == X86_REG_SP))
                    writesStack = true;
            break;
        }
        if (writesStack)
            return StackFrameResult::Rejected; // mov esp, ebp / and esp, -0x10: the stack pointer is not followed (a frame register function)
        if (!is64 && (current->id == X86_INS_RET || current->id == X86_INS_RETF) && delta != 0)
            return StackFrameResult::Unbalanced; // a ret with an unbalanced stack: a callee that pops something else than what was guessed
        // a ret, or a jmp with the stack of the entry (a tail call: jmp __CxxFrameHandler3); a chunk jumps back with its pushes
        reachedRet |= current->id == X86_INS_RET || current->id == X86_INS_RETF || (current->id == X86_INS_JMP && delta == 0);

        // the aliases of the stack pointer: any write of their register ends them, a call the volatile ones (r11)
        for (auto alias = aliases.begin(); alias != aliases.end();) {
            bool writesAlias = current->id == X86_INS_CALL && !isCalleeSaved(alias->reg);
            for (uint8 index = 0; index < x86.op_count; index++)
                if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE) &&
                    GetX64RegisterFamily(x86.operands[index].reg) == GetX64RegisterFamily(alias->reg))
                    writesAlias = true;
            for (uint8 index = 0; index < current->detail->regs_write_count; index++)
                writesAlias |= GetX64RegisterFamily(current->detail->regs_write[index]) == GetX64RegisterFamily(alias->reg);
            if (writesAlias) {
                frame.stackAliases[alias->index].end = current->address;
                alias                                = aliases.erase(alias);
            } else {
                frame.stackAliases[alias->index].end = nextAddress;
                ++alias;
            }
        }
        // mov rax, rsp (a copy), lea rbp, [rsp - 0x5f] / lea rbp, [rax - 0x5f] (the biased frame pointer of MSVC x64: a callee saved
        // register), lea r11, [rsp + 0x80] (the epilogue of MSVC x64: mov rsp, r11)
        const bool copiesStack = current->id == X86_INS_MOV && x86.op_count == 2 && IsRegisterOperand(x86, 1, stackRegister);
        const auto* biasBase   = current->id == X86_INS_LEA && x86.op_count == 2 && x86.operands[1].type == X86_OP_MEM &&
                                       x86.operands[1].mem.index == X86_REG_INVALID && x86.operands[1].mem.base != stackRegister
                                     ? aliasOf(x86.operands[1].mem.base)
                                     : nullptr;
        const bool biasesStack = current->id == X86_INS_LEA && x86.op_count == 2 && x86.operands[1].type == X86_OP_MEM &&
                                 x86.operands[1].mem.index == X86_REG_INVALID && (x86.operands[1].mem.base == stackRegister || biasBase);
        if ((copiesStack || biasesStack) && x86.operands[0].type == X86_OP_REG && x86.operands[0].size == pointerSize &&
            x86.operands[0].reg != stackRegister && !aliasOf(x86.operands[0].reg) && frame.stackAliases.size() < MAX_STACK_ALIASES &&
            (copiesStack || isCalleeSaved(x86.operands[0].reg) || x86.operands[0].reg == X86_REG_R11)) {
            const int64 aliasDelta = (biasBase ? biasBase->delta : delta) + (biasesStack ? x86.operands[1].mem.disp : 0);
            aliases.push_back({ x86.operands[0].reg, aliasDelta, frame.stackAliases.size() });
            frame.stackAliases.push_back({ cs_reg_name(detailHandle, x86.operands[0].reg), static_cast<int32>(aliasDelta), nextAddress, nextAddress });
        }
        if (change.has_value()) {
            setDelta(nextAddress, delta + change.value());
            deepest = std::min(deepest, delta);
            if (savesRegister || (!calledYet && (allocatesLocal || (adjustsStack && current->id == X86_INS_SUB))))
                bodyDelta = delta;
        }
        if (current->id == X86_INS_CALL)
            calledYet = true;
        for (uint8 index = 0; index < x86.op_count && !IsProloguePadding(current); index++) // mov edi, edi does not change edi
            if (x86.operands[index].type == X86_OP_REG && (x86.operands[index].access & CS_AC_WRITE))
                if (const int family = GetX64RegisterFamily(x86.operands[index].reg); family >= 0)
                    writtenFamilies |= 1u << family;
        // mov eax, 0x2000 (and the call __chkstk right after it): the size of a sub rsp, rax / of the probe
        if (setsAccumulator) {
            accumulator          = immediate(1);
            accumulatorAfterCall = false;
        } else if (current->id == X86_INS_CALL && accumulator.has_value() && !accumulatorAfterCall)
            accumulatorAfterCall = true;
        else
            accumulator.reset();

        if (cs_insn_group(detailHandle, current, CS_GRP_JUMP) && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM) {
            const uint64 target = static_cast<uint64>(x86.operands[0].imm);
            if (target > current->address && target < limitAddress) {
                furthestBranchTarget = std::max(furthestBranchTarget, target);
                branchDeltas.emplace(target, delta);
                if (!aliases.empty())
                    branchAliases.emplace(target, aliases);
            }
        }
        bool endsFlow = false;
        switch (current->id) {
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
        case X86_INS_JMP:
        case X86_INS_INT3:
        case X86_INS_HLT:
        case X86_INS_UD2:
            endsFlow = true;
            break;
        case X86_INS_CALL:
            endsFlow = noReturnCall;
            break;
        default:
            break;
        }
        if (endsFlow) {
            if (furthestBranchTarget < nextAddress)
                break;
            flowEnded = true; // the code after an epilogue: reached through a branch of the body
        }
    }
    if (!is64 && !reachedRet)
        return StackFrameResult::Rejected; // no ret: the depth of the entry is not the one of a function (a chunk of another one)
    if (accesses.empty() || !CompactAccesses(accesses))
        return StackFrameResult::Rejected;
    frame.stackOffset = static_cast<int32>(deepest);
    frame.variables.reserve(accesses.size());
    for (const auto& access : accesses) {
        DissasmLocalVariable variable{ access.frameOffset, access.size, {} };
        // the arguments from the return address: [entry + 8] / [entry + 4] is arg_0 (FormatDefaultLocalVariableName counts them from the
        // saved frame register)
        FormatDefaultLocalVariableName(access.frameOffset >= pointerSize ? access.frameOffset + static_cast<int32>(pointerSize) : access.frameOffset, is64, variable.name);
        frame.variables.push_back(std::move(variable));
    }
    return StackFrameResult::Accepted;
}
} // namespace

bool GView::View::DissasmViewer::AnalyzeX86StackFrame(
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      bool is64,
      DissasmFunctionFrame& frame,
      const X86CalleeStackPurge& calleePurge,
      const X86CallNoReturn& callNoReturn)
{
    // push ecx at the entry: a local (MSVC: sub esp, 4) or the argument of the first call; push esi after a call: a saved register or an
    // argument. The other readings of the pushes the function has, while the stack stays unbalanced
    uint8 ambiguousPushes = 0;
    auto result = AnalyzeStackPointerFrame(detailHandle, code, codeSize, codeAddress, limitAddress, is64, frame, calleePurge, callNoReturn, 0, ambiguousPushes);
    const uint8 firstAmbiguousPushes = ambiguousPushes;
    for (uint8 reading = 1; reading <= (ENTRY_PUSHES_ARE_ARGUMENTS | LATE_SAVES_ARE_ARGUMENTS) && result == StackFrameResult::Unbalanced; reading++)
        if ((reading & ~firstAmbiguousPushes) == 0)
            result = AnalyzeStackPointerFrame(detailHandle, code, codeSize, codeAddress, limitAddress, is64, frame, calleePurge, callNoReturn, reading, ambiguousPushes);
    return result == StackFrameResult::Accepted;
}

bool GView::View::DissasmViewer::FindX86StackOperand(std::string_view operands, X86FrameOperand& result, std::string_view stackRegister)
{
    const std::string base = "[" + std::string(stackRegister);
    const size_t start     = operands.find(base);
    if (start == std::string_view::npos || stackRegister.empty())
        return false;
    const size_t position = start + base.size();
    if (position < operands.size() && operands[position] == ']') { // [rsp]: the displacement 0
        result = { static_cast<uint32>(position), static_cast<uint32>(position), 0 };
        return true;
    }
    // [rsp + 0x20]: the form of [ebp + 8], parsed by FindX86FrameOperand on the text with ebp
    std::string text(operands);
    text.replace(start, base.size(), "[ebp");
    return FindX86FrameOperand(text, false, result);
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
    text += variable.structure ? std::string_view(variable.structure->name) : GetOperandSizeName(variable.size); // StartupInfo = STARTUPINFOW ptr
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

std::string GView::View::DissasmViewer::FormatLocalVariableOrigin(const DissasmLocalVariable& variable)
{
    if (variable.type.empty() || variable.origin.empty() || variable.structure) // a structure: its type is on the line already
        return variable.type.empty() || variable.structure ? variable.origin : variable.type;
    return variable.type + ", " + variable.origin;
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
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      DissasmFunctionFrame& frame,
      const std::function<bool(const cs_insn& call)>& callNoReturn)
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
        const bool noReturnCall = flow == X86Flow::Call && callNoReturn && callNoReturn(current); // bl abort
        if ((flow == X86Flow::Return || flow == X86Flow::Jump || noReturnCall) && furthestBranchTarget < address)
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
      csh detailHandle,
      const uint8* code,
      size_t codeSize,
      uint64 codeAddress,
      uint64 limitAddress,
      bool thumb,
      DissasmFunctionFrame& frame,
      const std::function<bool(const cs_insn& call)>& callNoReturn)
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
        const bool noReturnCall = flow == X86Flow::Call && callNoReturn && callNoReturn(current); // bl abort
        if ((flow == X86Flow::Return || flow == X86Flow::Jump || noReturnCall) && furthestBranchTarget < address)
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
