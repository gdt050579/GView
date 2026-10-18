#pragma once
#include "AppCUI/include/AppCUI.hpp"
#include "Internal.hpp"
#include "DissasmViewer.hpp"

#include <cstring>
#include <capstone/capstone.h>

AppCUI::Utils::LocalString<64> FormatFunctionName(AppCUI::uint64 functionAddress, const char* prefix);
// a number written in the operands of an instruction (0x... or decimal), positions are inside the operands text
struct OperandNumber {
    AppCUI::uint32 start;
    AppCUI::uint32 length;
    AppCUI::uint64 value;
    bool isHex;
};
// the numbers of the operands text, in order (their index is the bit used by FormatOperandNumbers);
// a number starts the text or follows one of " [,+-*:" so names like var_8, r8d, xmm0 or st(0) are skipped
std::vector<OperandNumber> FindOperandNumbers(std::string_view operands);
// writes the hexadecimal numbers whose index has the bit set in `decimalMask` as (unsigned) decimal numbers;
// `trackedPosition` (a position inside `operands`) is moved to the same character of the result
std::string FormatOperandNumbers(std::string_view operands, AppCUI::uint32 decimalMask, AppCUI::uint32* trackedPosition = nullptr);

// The operands with the name of the data they refer to, as IDA writes them; none when the operands have no such place:
// - x86 / x64: the memory operand at a fixed address ([rip + 0x...] on x64, [0x403000] on x86) becomes cs:name / ds:name, the size
//   ("dword ptr ") is dropped when the name says it (dword_, off_ / __imp_ of a pointer size); lea takes the name itself (lea rcx, aText)
std::optional<std::string> SubstituteX86MemoryOperand(std::string_view operands, std::string_view name, bool isLea, bool is64);
// - x86: an immediate (push 0x403000 / mov ecx, 0x403000) becomes "offset name"
std::optional<std::string> SubstituteX86Immediate(std::string_view operands, AppCUI::uint64 value, std::string_view name);
// - 32 bit ARM: the literal load ldr r0, [pc, #0x28] becomes ldr r0, =literal
std::optional<std::string> SubstituteArmLiteral(std::string_view operands, std::string_view literal);
// - ARM64: the offset in the page of an adrp pair (add x0, x0, #0x5a0 / ldr w8, [x8, #0x248]) becomes #name@PAGEOFF
std::optional<std::string> SubstituteArm64PageOffset(std::string_view operands, AppCUI::uint64 pageOffset, std::string_view name);

// Decodes the next x86/x64 line, as cs_disasm_iter does. A byte that can not be decoded is a 1 byte data line ("db 0xNN", as
// disassemblers show it) and the decoding continues right after it: inline data (jump tables, padding) never ends the code. False only
// when there are no bytes left. Every walk over the lines of a code zone (counting, cached offsets, navigation, drawing, export) decodes
// with it, so a line index maps to the same offset everywhere.
// `boundaries` (sorted, the same base as `address`): the places where an instruction starts (section / function starts); no instruction
// is decoded across one (the bytes before it are data lines), the misaligned bytes of a gap between sections do not hide the next code
// `alignmentBase`: the address of the listing of the relative address 0 (labelAddressBase); the padding (int3, nop) up to the next aligned
// address is one line (align 0x10, a data line: X86_INS_INVALID). DISSASM_NO_PADDING_ALIGNMENT: every padding instruction is a line
bool DecodeX86Line(
      csh handle,
      const uint8_t** code,
      size_t* size,
      uint64_t* address,
      cs_insn* insn,
      const std::vector<AppCUI::uint64>* boundaries = nullptr,
      AppCUI::uint64 alignmentBase                  = GView::View::DissasmViewer::DISSASM_NO_PADDING_ALIGNMENT,
      const GView::View::DissasmViewer::DissasmInstructionSet* instructionSet = nullptr); // null: x86; ARM64 / ARM / Thumb (.word data lines)

// Walks the lines (DecodeX86Line) of the code [codeStart, codeStart + codeSize) of a file from its first byte. The bytes are read from the
// data cache line by line: a zone bigger than the data cache window is decoded entirely, window after window. The addresses of the
// decoded lines are relative to codeStart.
class DissasmCodeLinesWalker
{
    Reference<GView::Object> obj;
    uint64 codeStart;
    uint64 codeSize;
    uint64 address;
    csh handle;
    const std::vector<uint64>* boundaries; // DecodeX86Line
    uint64 alignmentBase;                  // DecodeX86Line
    const GView::View::DissasmViewer::DissasmInstructionSet* instructionSet; // DecodeX86Line

  public:
    // startAddress: the relative address of an instruction of the listing (0: the first one)
    DissasmCodeLinesWalker(
          Reference<GView::Object> obj,
          uint64 codeStart,
          uint64 codeSize,
          csh handle,
          uint64 startAddress               = 0,
          const std::vector<uint64>* boundaries = nullptr,
          uint64 alignmentBase              = GView::View::DissasmViewer::DISSASM_NO_PADDING_ALIGNMENT,
          const GView::View::DissasmViewer::DissasmInstructionSet* instructionSet = nullptr)
        : obj(obj), codeStart(codeStart), codeSize(codeSize), address(startAddress), handle(handle), boundaries(boundaries), alignmentBase(alignmentBase),
          instructionSet(instructionSet)
    {
    }
    // false at the end of the code (or when the file has no more bytes)
    bool Next(cs_insn* insn);
    // relative address of the next line
    uint64 GetAddress() const
    {
        return address;
    }
};

// the characters of a name, a register or a number (mangled names: ?Name@@YAXXZ, $LN5)
bool IsTokenCharacter(char16_t c);
// the occurrences of `token` from `fromColumn` (whole names: the characters around them are not name characters) get `color`
void HighlightTokenOccurrences(AppCUI::Graphics::CharacterBuffer& chars, AppCUI::uint32 fromColumn, std::string_view token, AppCUI::Graphics::ColorPair color);

// the text found at `offset`, quoted: "ascii" or L"utf-16" (printable characters, at least DISSASM_MINIMUM_STRING_PREVIEW of them, until a
// NUL or the first non printable character); none when the bytes do not look like a string
std::optional<std::string> TryExtractStringPreview(Reference<GView::Object> obj, AppCUI::uint64 offset);

// Recognizes the functions that are not reached by a direct call (callbacks, virtual methods, exports) by their prologue. It is fed with
// every decoded line of the code, in order (DecodeX86Line); Next returns the file offset of a function start once a prologue is complete:
//  - push ebp / rbp; mov ebp, esp / rbp, rsp                          anywhere (the frame pointer setup)
//  - at the start of the code or right after a ret / padding (int3, nop, undecodable bytes, zeros):
//      x86: mov edi, edi; push ebp; mov ebp, esp (hot patching)
//      x64: mov qword ptr [rsp + 8..0x20], rcx/rdx/r8/r9/rbx/rsi/rdi/rbp (home space), sub rsp, N, mov rax / r11, rsp
//      push <callee saved register> followed by a push, sub esp / rsp or mov ebp, esp / rbp, rsp
//      push ebp / rbp followed by a push or sub esp / rsp (frame pointer saved, not used)
//  - endbr32 / endbr64 after a ret, a jmp or padding
class X86PrologueDetector
{
    enum class Pending : uint8 { None, FramePush, SavedRegisterPush, HotPatch };
    bool is64;
    bool afterPadding = true; // start of the code, or the previous line ends the code flow (ret) or is padding
    bool afterJump    = false;
    Pending pending   = Pending::None;
    bool pendingAfterPadding = false;
    AppCUI::uint64 pendingOffset = 0;

  public:
    explicit X86PrologueDetector(bool is64) : is64(is64)
    {
    }
    std::optional<AppCUI::uint64> Next(const cs_insn& insn, AppCUI::uint64 fileOffset);
};

cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach,
      GView::View::DissasmViewer::DissasmCodeZone* zone,
      Reference<GView::Object> obj,
      uint32& diffLines,
      GView::View::DissasmViewer::DrawLineInfo* dli = nullptr);

GView::View::DissasmViewer::AsmOffsetLine SearchForClosestAsmOffsetLineByOffset(
      const std::vector<GView::View::DissasmViewer::AsmOffsetLine>& values, uint64 searchedOffset, uint32* index = nullptr);
// end (relative, exclusive) of the bytes needed to decode the lines that start at the cached offset `cachedOffsetIndex`
uint64 GetCachedOffsetWindowEnd(const GView::View::DissasmViewer::DissasmCodeZone* zone, uint32 cachedOffsetIndex);

GView::View::DissasmViewer::AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<GView::View::DissasmViewer::AsmOffsetLine>& values, uint64 searchedLine, uint32* index = nullptr);