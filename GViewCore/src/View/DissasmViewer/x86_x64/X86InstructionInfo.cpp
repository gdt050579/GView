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
            } else if (mem.base != X86_REG_RIP && mem.disp != 0 && (mem.segment == X86_REG_INVALID || mem.segment == X86_REG_DS)) {
                info.tableMemory  = static_cast<uint64>(mem.disp) & addressMask;
                info.memoryAccess = op.access;
            }
        }
    }
    return info;
}

int GView::View::DissasmViewer::GetX64RegisterFamily(unsigned int reg)
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

std::optional<uint8> GView::View::DissasmViewer::GetX64ArgumentSlot(const cs_insn& insn, bool systemV)
{
    if (insn.id == X86_INS_INVALID || !insn.detail || insn.detail->x86.op_count == 0)
        return {};
    const cs_x86_op& op = insn.detail->x86.operands[0];
    if ((op.access & CS_AC_WRITE) == 0)
        return {};
    if (systemV) {
        // the integer arguments (the floating point ones go in xmm0.. separately: not counted), the seventh on in the stack
        constexpr int64 MAX_STACK_ARG = 16;
        if (op.type == X86_OP_REG) {
            const int family = GetX64RegisterFamily(op.reg);
            switch (family) {
            case 7: // rdi
                return 0;
            case 6: // rsi
                return 1;
            case 2: // rdx
                return 2;
            case 1: // rcx
                return 3;
            case 8: // r8
                return 4;
            case 9: // r9
                return 5;
            default:
                return {};
            }
        }
        if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RSP && op.mem.index == X86_REG_INVALID && op.mem.disp >= 0 && op.mem.disp % 8 == 0 &&
            op.mem.disp < 8 * MAX_STACK_ARG)
            return static_cast<uint8>(6 + op.mem.disp / 8);
        return {};
    }
    if (op.type == X86_OP_REG) {
        switch (op.reg) {
        case X86_REG_RCX:
        case X86_REG_ECX:
        case X86_REG_CX:
        case X86_REG_CL:
        case X86_REG_XMM0:
            return 0;
        case X86_REG_RDX:
        case X86_REG_EDX:
        case X86_REG_DX:
        case X86_REG_DL:
        case X86_REG_XMM1:
            return 1;
        case X86_REG_R8:
        case X86_REG_R8D:
        case X86_REG_R8W:
        case X86_REG_R8B:
        case X86_REG_XMM2:
            return 2;
        case X86_REG_R9:
        case X86_REG_R9D:
        case X86_REG_R9W:
        case X86_REG_R9B:
        case X86_REG_XMM3:
            return 3;
        default:
            return {};
        }
    }
    // the arguments after the fourth: above the 0x20 bytes of home space of the registers
    constexpr int64 HOME_SPACE    = 0x20;
    constexpr int64 MAX_STACK_ARG = 16;
    if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RSP && op.mem.index == X86_REG_INVALID && op.mem.disp >= HOME_SPACE &&
        op.mem.disp % 8 == 0 && op.mem.disp < HOME_SPACE + 8 * MAX_STACK_ARG)
        return static_cast<uint8>(4 + (op.mem.disp - HOME_SPACE) / 8);
    return {};
}

X86InstructionKind GView::View::DissasmViewer::GetX86InstructionKind(unsigned int id, std::string_view mnemonic)
{
    switch (id) {
    case X86_INS_INVALID: // the lines of DecodeX86Line: db 0x.. / align 0x10
        return mnemonic == "align" ? X86InstructionKind::Padding : X86InstructionKind::Data;
    case X86_INS_CALL:
    case X86_INS_LCALL:
        return X86InstructionKind::Call;
    case X86_INS_JMP:
    case X86_INS_LJMP:
        return X86InstructionKind::Jump;
    case X86_INS_JAE:
    case X86_INS_JA:
    case X86_INS_JBE:
    case X86_INS_JB:
    case X86_INS_JCXZ:
    case X86_INS_JECXZ:
    case X86_INS_JRCXZ:
    case X86_INS_JE:
    case X86_INS_JGE:
    case X86_INS_JG:
    case X86_INS_JLE:
    case X86_INS_JL:
    case X86_INS_JNE:
    case X86_INS_JNO:
    case X86_INS_JNP:
    case X86_INS_JNS:
    case X86_INS_JO:
    case X86_INS_JP:
    case X86_INS_JS:
    case X86_INS_LOOP:
    case X86_INS_LOOPE:
    case X86_INS_LOOPNE:
        return X86InstructionKind::ConditionalJump;
    case X86_INS_RET:
    case X86_INS_RETF:
    case X86_INS_RETFQ:
    case X86_INS_IRET:
    case X86_INS_IRETD:
    case X86_INS_IRETQ:
        return X86InstructionKind::Return;
    case X86_INS_CMP:
    case X86_INS_TEST:
    case X86_INS_BT:
    case X86_INS_COMISS:
    case X86_INS_COMISD:
    case X86_INS_UCOMISS:
    case X86_INS_UCOMISD:
        return X86InstructionKind::Compare;
    case X86_INS_PUSH:
    case X86_INS_POP:
    case X86_INS_PUSHAL:
    case X86_INS_POPAL:
    case X86_INS_PUSHAW:
    case X86_INS_POPAW:
    case X86_INS_PUSHF:
    case X86_INS_POPF:
    case X86_INS_PUSHFD:
    case X86_INS_POPFD:
    case X86_INS_PUSHFQ:
    case X86_INS_POPFQ:
    case X86_INS_ENTER:
    case X86_INS_LEAVE:
        return X86InstructionKind::Stack;
    case X86_INS_NOP:
    case X86_INS_INT3:
    case X86_INS_ENDBR32:
    case X86_INS_ENDBR64:
        return X86InstructionKind::Padding;
    // the instructions an analyst looks for: system calls, interrupts, privileged instructions, the anti debug / anti VM checks
    case X86_INS_INT:
    case X86_INS_INT1:
    case X86_INS_INTO:
    case X86_INS_SYSCALL:
    case X86_INS_SYSENTER:
    case X86_INS_SYSEXIT:
    case X86_INS_SYSRET:
    case X86_INS_HLT:
    case X86_INS_UD0:
    case X86_INS_UD1:
    case X86_INS_UD2:
    case X86_INS_CPUID:
    case X86_INS_RDTSC:
    case X86_INS_RDTSCP:
    case X86_INS_RDPMC:
    case X86_INS_RDMSR:
    case X86_INS_WRMSR:
    case X86_INS_IN:
    case X86_INS_OUT:
    case X86_INS_INSB:
    case X86_INS_INSW:
    case X86_INS_INSD:
    case X86_INS_OUTSB:
    case X86_INS_OUTSW:
    case X86_INS_OUTSD:
    case X86_INS_CLI:
    case X86_INS_STI:
    case X86_INS_LGDT:
    case X86_INS_SGDT:
    case X86_INS_LIDT:
    case X86_INS_SIDT:
    case X86_INS_LLDT:
    case X86_INS_SLDT:
    case X86_INS_LTR:
    case X86_INS_STR:
    case X86_INS_LMSW:
    case X86_INS_SMSW:
    case X86_INS_INVD:
    case X86_INS_WBINVD:
    case X86_INS_VMCALL:
    case X86_INS_VMMCALL:
        return X86InstructionKind::System;
    default:
        return X86InstructionKind::Other;
    }
}

X86RegisterKind GView::View::DissasmViewer::GetX86RegisterKind(std::string_view token)
{
    // the stack, frame, index and instruction pointers (all sizes)
    static constexpr std::string_view pointers[] = { "rsp", "esp", "sp", "spl", "rbp", "ebp", "bp", "bpl", "rsi", "esi", "si",
                                                     "sil", "rdi", "edi", "di",  "dil", "rip", "eip", "ip" };
    static constexpr std::string_view general[]  = { "rax", "eax", "ax", "al", "ah", "rbx", "ebx", "bx", "bl", "bh", "rcx", "ecx", "cx", "cl",
                                                     "ch",  "rdx", "edx", "dx", "dl", "dh", "cs", "ds", "es", "fs", "gs", "ss" };
    for (const auto name : pointers)
        if (token == name)
            return X86RegisterKind::Pointer;
    for (const auto name : general)
        if (token == name)
            return X86RegisterKind::General;

    // a prefix followed by a number: r8 .. r15 (b / w / d), xmm / ymm / zmm 0 .. 31, mm0 .. 7, k0 .. 7, cr0 .. 15, dr0 .. 15
    const auto numbered = [token](std::string_view prefix, uint32 minNumber, uint32 maxNumber, std::string_view suffixes) {
        if (token.size() <= prefix.size() || token.substr(0, prefix.size()) != prefix)
            return false;
        std::string_view rest = token.substr(prefix.size());
        if (!suffixes.empty() && suffixes.find(rest.back()) != std::string_view::npos)
            rest.remove_suffix(1);
        if (rest.empty() || rest.size() > 2 || (rest.size() == 2 && rest[0] == '0'))
            return false;
        uint32 number = 0;
        for (const char c : rest) {
            if (c < '0' || c > '9')
                return false;
            number = number * 10 + static_cast<uint32>(c - '0');
        }
        return number >= minNumber && number <= maxNumber;
    };
    if (numbered("r", 8, 15, "bwd") || numbered("xmm", 0, 31, "") || numbered("ymm", 0, 31, "") || numbered("zmm", 0, 31, "") ||
        numbered("mm", 0, 7, "") || numbered("k", 0, 7, "") || numbered("cr", 0, 15, "") || numbered("dr", 0, 15, ""))
        return X86RegisterKind::General;
    // ARM64: x0 .. x30 / w0 .. w30, the vector and floating point registers; fp (x29) and lr (x30) are pointers, as sp
    if (token == "fp" || token == "lr" || token == "wsp" || token == "pc")
        return X86RegisterKind::Pointer;
    // 32 bit ARM: r0 .. r7 (r8 .. r15 above), sb, sl (ip, fp, sp, lr, pc are pointers)
    if (numbered("r", 0, 7, "") || token == "sb" || token == "sl")
        return X86RegisterKind::General;
    if (token == "xzr" || token == "wzr" || numbered("x", 0, 30, "") || numbered("w", 0, 30, "") || numbered("v", 0, 31, "") ||
        numbered("q", 0, 31, "") || numbered("d", 0, 31, "") || numbered("s", 0, 31, "") || numbered("h", 0, 31, "") || numbered("b", 0, 31, ""))
        return X86RegisterKind::General;
    return X86RegisterKind::None;
}
