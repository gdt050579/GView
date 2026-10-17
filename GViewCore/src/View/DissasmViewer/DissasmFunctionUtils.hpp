#pragma once
#include "AppCUI/include/AppCUI.hpp"
#include "Internal.hpp"

#include <cstring>
#include <capstone/capstone.h>

constexpr uint32 callOP = 1819042147u; //*(uint32*) "call";
constexpr uint32 addOP  = 6579297u;    //*((uint32*) "add");
constexpr uint32 pushOP = 1752397168u; //*((uint32*) "push");
constexpr uint32 movOP  = 7761773u;    //*((uint32*) "mov");
constexpr uint32 retOP  = 7628146u;    //*((uint32*) "ret");

// first 4 bytes of a mnemonic / operands text, to compare with the constants above. cs_insn::mnemonic is not 4-byte aligned
// (it follows bytes[24]), so a *(uint32*) read is undefined behavior; memcpy compiles to the same single load.
inline uint32 TextPrefixAsUInt32(const char* text)
{
    uint32 value;
    std::memcpy(&value, text, sizeof(value));
    return value;
}

// TODO: maybe add also minimum number?
bool CheckExtractInsnHexValue(const char* op_str, AppCUI::uint64& value, AppCUI::uint64 maxSize);
AppCUI::Utils::LocalString<64> FormatFunctionName(AppCUI::uint64 functionAddress, const char* prefix);
// target of a direct jump / call: the operands are only the target address, as capstone prints it ("0x1f4", or "7" below 10);
// none for registers, memory operands, far pointers ("0x10:0x20") or numbers that do not fit in 64 bits
std::optional<AppCUI::uint64> GetDirectBranchTarget(std::string_view operands);

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

// Decodes the next x86/x64 line, as cs_disasm_iter does. A byte that can not be decoded is a 1 byte data line ("db 0xNN", as
// disassemblers show it) and the decoding continues right after it: inline data (jump tables, padding) never ends the code. False only
// when there are no bytes left. Every walk over the lines of a code zone (counting, cached offsets, navigation, drawing, export) decodes
// with it, so a line index maps to the same offset everywhere.
bool DecodeX86Line(csh handle, const uint8_t** code, size_t* size, uint64_t* address, cs_insn* insn);

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

  public:
    DissasmCodeLinesWalker(Reference<GView::Object> obj, uint64 codeStart, uint64 codeSize, csh handle)
        : obj(obj), codeStart(codeStart), codeSize(codeSize), address(0), handle(handle)
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