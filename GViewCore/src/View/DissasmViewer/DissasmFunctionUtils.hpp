#pragma once
#include "AppCUI/include/AppCUI.hpp"
#include "Internal.hpp"

constexpr uint32 callOP = 1819042147u; //*(uint32*) "call";
constexpr uint32 addOP  = 6579297u;    //*((uint32*) "add");
constexpr uint32 pushOP = 1752397168u; //*((uint32*) "push");
constexpr uint32 movOP  = 7761773u;    //*((uint32*) "mov");
constexpr uint32 retOP  = 7628146u;    //*((uint32*) "ret");

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