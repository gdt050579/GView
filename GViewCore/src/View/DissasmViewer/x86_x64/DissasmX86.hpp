#pragma once
#include <AppCUI/include/AppCUI.hpp>

namespace GView::View::DissasmViewer
{
struct DissasmCodeInternalType;
DissasmCodeInternalType* GetRecursiveCollpasedZoneByLine(DissasmCodeInternalType& parent, uint32 line);
} // namespace GView::View::DissasmViewer
