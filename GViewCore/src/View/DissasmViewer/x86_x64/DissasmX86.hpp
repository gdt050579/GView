#pragma once
#include <AppCUI/include/AppCUI.hpp>

bool CheckExtractInsnHexValue(const char* op_str, AppCUI::uint64& value, AppCUI::uint64 maxSize);

namespace GView::View::DissasmViewer
{
struct DissasmCodeInternalType;
DissasmCodeInternalType* GetRecursiveCollpasedZoneByLine(DissasmCodeInternalType& parent, uint32 line);
} // namespace GView::View::DissasmViewer
