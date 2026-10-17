#pragma once

#include <AppCUI/include/AppCUI.hpp>
#include <capstone/capstone.h>

#include <optional>
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
};

X86Flow GetX86Flow(const cs_insn& insn);
X86OperandsInfo GetX86OperandsInfo(const cs_insn& insn, bool is64);

inline bool IsX86Branch(X86Flow flow)
{
    return flow == X86Flow::Call || flow == X86Flow::Jump || flow == X86Flow::ConditionalJump;
}
} // namespace GView::View::DissasmViewer
