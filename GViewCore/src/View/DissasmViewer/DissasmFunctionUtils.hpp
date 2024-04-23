#pragma once
#include "AppCUI/include/AppCUI.hpp"
#include "Internal.hpp"

constexpr uint32 callOP = 1819042147u; //*(uint32*) "call";
constexpr uint32 addOP  = 6579297u;    //*((uint32*) "add");
constexpr uint32 pushOP = 1752397168u; //*((uint32*) "push");
constexpr uint32 movOP  = 7761773u;    //*((uint32*) "mov");

// TODO: maybe add also minimum number?
bool CheckExtractInsnHexValue(const char* op_str, AppCUI::uint64& value, AppCUI::uint64 maxSize);
AppCUI::Utils::LocalString<64> FormatFunctionName(AppCUI::uint64 functionAddress, const char* prefix);

cs_insn* GetCurrentInstructionByOffset(
      uint64 offsetToReach,
      GView::View::DissasmViewer::DissasmCodeZone* zone,
      Reference<GView::Object> obj,
      uint32& diffLines,
      GView::View::DissasmViewer::DrawLineInfo* dli = nullptr);

GView::View::DissasmViewer::AsmOffsetLine SearchForClosestAsmOffsetLineByLine(const std::vector<GView::View::DissasmViewer::AsmOffsetLine>& values, uint64 searchedLine, uint32* index = nullptr);