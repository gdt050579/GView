#pragma once

#include <AppCUI/include/AppCUI.hpp>
#include <capstone/capstone.h>

#include <optional>
#include <string_view>
#include <vector>

namespace GView::View::DissasmViewer
{
// What an x86/x64 instruction does to the code flow. It is read from the capstone instruction groups: the instruction must be decoded by a
// handle with CS_OPT_DETAIL enabled. The data lines of DecodeX86Line (db 0x.., X86_INS_INVALID) have no flow.
enum class X86Flow : AppCUI::uint8 { None, Call, Jump, ConditionalJump, Return, Interrupt };

// The addresses used by the operands of an instruction, from the capstone operands (CS_OPT_DETAIL), never from the operands text.
// The addresses have the base of the decoded addresses (insn.address); in 32 bit code they are 32 bit values.
struct X86OperandsInfo {
    std::optional<AppCUI::uint64> directTarget;   // call / jmp / jcc / loop 0x...: the target of the branch
    std::optional<AppCUI::uint64> ripTarget;      // [rip + 0x...]: the address that is read / written / taken (x64)
    std::optional<AppCUI::uint64> absoluteMemory; // [0x402010]: a memory operand without base and index registers (x86 globals, imports)
    std::vector<AppCUI::uint64> immediates;       // the immediate operands that are not branch targets (push 0x403000, mov ecx, 0x10)
    AppCUI::uint8 memoryAccess = 0;               // CS_AC_READ / CS_AC_WRITE of the memory operand of ripTarget / absoluteMemory
};

X86Flow GetX86Flow(const cs_insn& insn);
X86OperandsInfo GetX86OperandsInfo(const cs_insn& insn, bool is64);

// The argument of the Windows x64 calling convention written by the instruction (its first operand): 0-3 for rcx / rdx / r8 / r9 (any size)
// or xmm0-3, 4 and more for the stack slots [rsp + 0x20 + 8 * n]; none when it writes no argument.
std::optional<AppCUI::uint8> GetX64ArgumentSlot(const cs_insn& insn);

// What an instruction is, for its color: from its id (no CS_OPT_DETAIL needed); the data lines of DecodeX86Line (X86_INS_INVALID) by their
// mnemonic: db is Data, align is Padding. System: the system calls, interrupts, privileged and anti debug / anti VM instructions (cpuid, rdtsc,
// sidt, in, ...)
enum class X86InstructionKind : AppCUI::uint8 { Other, Call, Jump, ConditionalJump, Return, Compare, Stack, Padding, Data, System };
X86InstructionKind GetX86InstructionKind(unsigned int id, std::string_view mnemonic);

// A register name of the operands text: Pointer for the stack / frame / index / instruction pointers (rsp, ebp, si, rip, ...), General for
// the others (rax, r8d, cl, cs, xmm0, ...); None for anything else (a name, a number, dword, ptr)
enum class X86RegisterKind : AppCUI::uint8 { None, General, Pointer };
X86RegisterKind GetX86RegisterKind(std::string_view token);

inline bool IsX86Branch(X86Flow flow)
{
    return flow == X86Flow::Call || flow == X86Flow::Jump || flow == X86Flow::ConditionalJump;
}
} // namespace GView::View::DissasmViewer
