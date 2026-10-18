#pragma once

#include <AppCUI/include/AppCUI.hpp>
#include <capstone/capstone.h>

#include <array>
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

// A register name of the operands text: Pointer for the stack / frame / index / instruction pointers (rsp, ebp, si, rip, ...; ARM64: sp,
// fp, lr), General for the others (rax, r8d, cl, cs, xmm0, ...; ARM64: x0, w1, v2, d3, xzr); None for anything else (a name, a number,
// dword, ptr)
enum class X86RegisterKind : AppCUI::uint8 { None, General, Pointer };
X86RegisterKind GetX86RegisterKind(std::string_view token);

inline bool IsX86Branch(X86Flow flow)
{
    return flow == X86Flow::Call || flow == X86Flow::Jump || flow == X86Flow::ConditionalJump;
}

// The instruction set of a code zone. The ARM64 versions give the same results as the x86 ones (x86_x64/Arm64InstructionInfo.cpp): the
// branches and their targets (b / bl / cbz / tbz / b.cond: the last operand), the addresses taken by adr and read by ldr literal (ripTarget)
enum class DissasmArch : AppCUI::uint8 { X86, X64, Arm64 };
X86Flow GetArm64Flow(const cs_insn& insn);
X86OperandsInfo GetArm64OperandsInfo(const cs_insn& insn);
X86InstructionKind GetArm64InstructionKind(unsigned int id, std::string_view mnemonic);

// Follows the adrp pairs of the instructions of a linear sweep (ARM64): adrp x0, page then add x1, x0, #off / ldr / str [x0, #off] give
// the address; ldr x16, [x16, #off] then br / blr x16 jump / call through the slot that was read (an import stub / an import call). A pair
// never continues after a jump, a return or a data line; a call changes x0 .. x18 and x30
// adrp x0, page: the page (relative address) of the VA of the instruction. Capstone decodes from the zone start (address 0): its page is
// right only when the zone starts at a 4 KB aligned VA; `addressBase` is the VA of the relative address 0 (labelAddressBase)
AppCUI::uint64 GetArm64AdrpPage(const cs_insn& insn, AppCUI::uint64 addressBase);

// The jump table of an ARM64 switch: br x10 after
//   cmp w0, #N; b.hi default (the bound) / adr (or adrp + add) x9, table / ldrb w11, [x9, x8] / adr x10, anchor /
//   add x10, x10, x11, lsl #2
// the case i is at base + (entry i << shift); the entries are 1, 2, 4 or 8 bytes, signed or not
struct Arm64JumpTable {
    AppCUI::uint64 table; // relative addresses (the base of the decoded addresses)
    AppCUI::uint8 entrySize;
    bool isSigned;
    AppCUI::uint64 base;
    AppCUI::uint8 shift;
    AppCUI::uint32 count;
};

// ARM64: a prologue at a block start (stp x29, x30, [sp, #-N]! / sub sp, sp, #N / pacibsp / paciasp / bti c): a function start
bool IsArm64PrologueStart(const cs_insn& insn);

class Arm64AdrpTracker
{
  public:
    explicit Arm64AdrpTracker(AppCUI::uint64 addressBase = 0) : addressBase(addressBase)
    {
    }
    struct Result {
        AppCUI::uint64 address;       // same base as the decoded addresses
        bool throughSlot;             // br / blr: the address of the slot that was read
        AppCUI::uint64 sequenceStart; // the address of the adrp
        bool sequenceAtBlockStart;
        AppCUI::uint8 memoryAccess; // CS_AC_READ (ldr, br, blr) / CS_AC_WRITE (str); 0: the address is taken (add)
    };
    std::optional<Result> Next(const cs_insn& insn, bool atBlockStart);
    // the jump table of the br given to the last Next (once)
    std::optional<Arm64JumpTable> TakeJumpTable()
    {
        auto table = jumpTable;
        jumpTable.reset();
        return table;
    }
    void Reset();

  private:
    struct TableEntry {
        AppCUI::uint64 table;
        AppCUI::uint8 size;
        bool isSigned;
    };
    struct Value {
        std::optional<AppCUI::uint64> page;    // adrp
        std::optional<AppCUI::uint64> slot;    // ldr from page + offset: the register holds the value of the slot
        std::optional<AppCUI::uint64> address; // adrp + add, adr: the register holds the address
        std::optional<TableEntry> entry;       // ldrb w11, [x9, x8]: an entry of the table at x9
        std::optional<Arm64JumpTable> jump;    // add x10, x10, x11, lsl #2: an anchor plus an entry
        AppCUI::uint64 start = 0;
        bool startAtBlock    = false;
    };
    std::array<Value, 31> registers{};
    AppCUI::uint64 addressBase;
    std::optional<AppCUI::uint64> compared; // cmp w0, #N: N
    std::optional<AppCUI::uint32> bound;    // b.hi after the cmp: the number of cases
    std::optional<Arm64JumpTable> jumpTable;
};

inline X86Flow GetInstructionFlow(const cs_insn& insn, DissasmArch arch)
{
    return arch == DissasmArch::Arm64 ? GetArm64Flow(insn) : GetX86Flow(insn);
}
inline X86OperandsInfo GetInstructionOperands(const cs_insn& insn, DissasmArch arch)
{
    return arch == DissasmArch::Arm64 ? GetArm64OperandsInfo(insn) : GetX86OperandsInfo(insn, arch == DissasmArch::X64);
}
inline X86InstructionKind GetInstructionKind(unsigned int id, std::string_view mnemonic, DissasmArch arch)
{
    return arch == DissasmArch::Arm64 ? GetArm64InstructionKind(id, mnemonic) : GetX86InstructionKind(id, mnemonic);
}
} // namespace GView::View::DissasmViewer
