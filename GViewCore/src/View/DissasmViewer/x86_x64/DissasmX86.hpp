#pragma once
#include <AppCUI/include/AppCUI.hpp>
#include "DissasmViewer.hpp"
#include "X86InstructionInfo.hpp"

namespace GView::View::DissasmViewer
{
// the color of a mnemonic: what the instruction does (GetX86InstructionKind), not its text
AppCUI::Graphics::ColorPair GetX86MnemonicColor(X86InstructionKind kind, const DissasmColors& colors);
// the color of a token of the operands (or of a label): a register (GetX86RegisterKind), a size keyword (dword ptr), an import thunk
AppCUI::Graphics::ColorPair GetX86TokenColor(std::string_view token, const DissasmColors& colors);
} // namespace GView::View::DissasmViewer
