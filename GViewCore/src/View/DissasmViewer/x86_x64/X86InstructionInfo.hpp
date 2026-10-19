#pragma once

#include <AppCUI/include/AppCUI.hpp>
#include <capstone/capstone.h>

#include <array>
#include <functional>
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
    // [eax*4 + 0x403000] / [ebx + ecx*4 + 0x403000]: the displacement of a memory operand with registers (not rip), the address of a table
    // when it is one of the file (the caller checks it: [ebp - 8] is not)
    std::optional<AppCUI::uint64> tableMemory;
    std::vector<AppCUI::uint64> immediates;       // the immediate operands that are not branch targets (push 0x403000, mov ecx, 0x10)
    AppCUI::uint8 memoryAccess = 0;               // CS_AC_READ / CS_AC_WRITE of the memory operand of ripTarget / absoluteMemory
};

X86Flow GetX86Flow(const cs_insn& insn);
X86OperandsInfo GetX86OperandsInfo(const cs_insn& insn, bool is64);
// x64: the general register of a register and of its parts (rax / eax / ax / al / ah: 0 ... r15: 15), -1 for the others
int GetX64RegisterFamily(unsigned int reg);

// The argument of the Windows x64 calling convention written by the instruction (its first operand): 0-3 for rcx / rdx / r8 / r9 (any size)
// or xmm0-3, 4 and more for the stack slots [rsp + 0x20 + 8 * n]; none when it writes no argument.
// `systemV`: the convention of Linux / macOS (rdi, rsi, rdx, rcx, r8, r9, then the stack from [rsp]); otherwise the one of Windows (rcx,
// rdx, r8, r9, then the stack above the 0x20 bytes of home space)
std::optional<AppCUI::uint8> GetX64ArgumentSlot(const cs_insn& insn, bool systemV = false);

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
enum class DissasmArch : AppCUI::uint8 { X86, X64, Arm64, Arm, Thumb };
inline bool IsArmArch(DissasmArch arch)
{
    return arch == DissasmArch::Arm64 || arch == DissasmArch::Arm || arch == DissasmArch::Thumb;
}

// 32 bit ARM (x86_x64/Arm32InstructionInfo.cpp): b / bl / blx / cbz, bx lr / pop {..., pc} (returns), ldr pc / bx rN (indirect jumps); the
// literal loads (ldr r0, [pc, #off]) and adr / add rd, pc, #imm give the address read / taken: pc is the address + 8 (ARM) or the 4 bytes
// aligned address + 4 (Thumb), computed on the VA (`addressBase`: the VA of the relative address 0)
X86Flow GetArm32Flow(const cs_insn& insn);
X86OperandsInfo GetArm32OperandsInfo(const cs_insn& insn, bool thumb, AppCUI::uint64 addressBase = 0);
X86InstructionKind GetArm32InstructionKind(unsigned int id, std::string_view mnemonic);

// What an instruction does, in a line (the status bar, x86_x64/InstructionHelp.cpp): "move if not equal / not zero (ZF = 0)" for cmovne,
// the prefixes (rep, lock), the condition families (jcc / setcc / cmovcc, ARM b.cond and the condition suffixes), SSE / AVX, the common
// ARM64 / ARM / Thumb instructions; `operands` tells the string movsd from the SSE one. Empty when it is not known
std::string DescribeInstruction(std::string_view mnemonic, std::string_view operands, DissasmArch arch);
X86Flow GetArm64Flow(const cs_insn& insn);
X86OperandsInfo GetArm64OperandsInfo(const cs_insn& insn);
X86InstructionKind GetArm64InstructionKind(unsigned int id, std::string_view mnemonic);
// the size of the data that an ARM load / store reads or writes (ldrb: 1, ldrh: 2, ldr w0 / ldr r0 / ldrsw: 4, ldr x0 / ldrd: 8, ldr q0:
// 16); 0 for the other instructions and the loads of several registers (ldp, ldm)
AppCUI::uint8 GetArm64AccessSize(const cs_insn& insn);
AppCUI::uint8 GetArm32AccessSize(const cs_insn& insn);

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
    bool absolute = false; // 32 bit ARM (ldr pc, [pc, r0, lsl #2]): the entries are the VAs of the cases; entrySize 0 (add pc, pc, r0,
                           // lsl #2): no table, the case i is at base + (i << shift)
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
        // 32 bit ARM: the address is a constant of the code (movw / movt, a word of a literal pool): an address only when it is one of
        // the file (the deep scan checks it), a constant otherwise
        bool absolute = false;
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

// 32 bit ARM: a prologue at a block start (push {..., lr} / stmdb sp!, {..., lr}): a function start
bool IsArm32PrologueStart(const cs_insn& insn);

// Follows the addresses that 32 bit ARM code builds in its registers (the imports, the PIC data): movw / movt (an absolute address),
// add rd, pc, #imm (and add rd, rd, #imm), ldr rd, [pc, #off] then add rd, pc, rd (a PIC address from a literal pool, read through
// `readWord`), ldr rd, [rn, #off] (a slot read), then ldr pc, [..] / bx / blx rn through the slot: the ELF PLT stubs
// (add ip, pc, ...; add ip, ip, ...; ldr pc, [ip, #off]!) and the Windows import thunks (movw r12; movt r12; ldr r12, [r12]; bx r12)
class Arm32Tracker
{
  public:
    using Result   = Arm64AdrpTracker::Result;
    using ReadWord = std::function<std::optional<AppCUI::uint32>(AppCUI::uint64 relativeAddress)>;
    explicit Arm32Tracker(AppCUI::uint64 addressBase = 0, ReadWord readWord = {}) : addressBase(addressBase), readWord(std::move(readWord))
    {
    }
    std::optional<Result> Next(const cs_insn& insn, bool thumb, bool atBlockStart);
    // the jump table of the indirect jump given to the last Next (once): tbb / tbh, ldr pc, [pc, rN, lsl #2], add pc, rA, rE, add pc, pc,
    // rN, lsl #2, bx rN; the bound: cmp rN, #N then an instruction executed above it (bhi, bxhi lr, movhi) or the jump itself (addls pc)
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
        std::optional<AppCUI::uint64> address; // relative
        std::optional<AppCUI::uint32> literal; // ldr rd, [pc, #off]: the word of the literal pool
        std::optional<AppCUI::uint64> slot;    // ldr rd, [rn, #off]: the register holds the value of the slot
        std::optional<AppCUI::uint32> low16;   // movw rd, #imm
        std::optional<TableEntry> entry;       // ldr r0, [r1, r0, lsl #2]: an entry of the table at r1
        std::optional<Arm64JumpTable> jump;    // add r2, r1, r0: an address plus an entry
        AppCUI::uint64 start = 0;
        bool startAtBlock    = false;
        bool absolute        = false; // the address is a constant (movw / movt, ldr r0, =variable): Result::absolute
    };
    std::array<Value, 15> registers{}; // r0 .. r12, sp, lr
    AppCUI::uint64 addressBase;
    ReadWord readWord;
    std::optional<AppCUI::uint64> compared; // cmp rN, #N: N
    std::optional<AppCUI::uint32> bound;    // the number of cases
    std::optional<Arm64JumpTable> jumpTable;
};

inline X86Flow GetInstructionFlow(const cs_insn& insn, DissasmArch arch)
{
    switch (arch) {
    case DissasmArch::Arm64:
        return GetArm64Flow(insn);
    case DissasmArch::Arm:
    case DissasmArch::Thumb:
        return GetArm32Flow(insn);
    default:
        return GetX86Flow(insn);
    }
}
inline X86OperandsInfo GetInstructionOperands(const cs_insn& insn, DissasmArch arch, AppCUI::uint64 addressBase = 0)
{
    switch (arch) {
    case DissasmArch::Arm64:
        return GetArm64OperandsInfo(insn);
    case DissasmArch::Arm:
    case DissasmArch::Thumb:
        return GetArm32OperandsInfo(insn, arch == DissasmArch::Thumb, addressBase);
    default:
        return GetX86OperandsInfo(insn, arch == DissasmArch::X64);
    }
}
inline X86InstructionKind GetInstructionKind(unsigned int id, std::string_view mnemonic, DissasmArch arch)
{
    switch (arch) {
    case DissasmArch::Arm64:
        return GetArm64InstructionKind(id, mnemonic);
    case DissasmArch::Arm:
    case DissasmArch::Thumb:
        return GetArm32InstructionKind(id, mnemonic);
    default:
        return GetX86InstructionKind(id, mnemonic);
    }
}
} // namespace GView::View::DissasmViewer
