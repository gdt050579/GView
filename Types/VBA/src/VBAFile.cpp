#include "vba.hpp"

namespace GView::Type::VBA
{
using namespace GView::View::LexicalViewer;

VBAFile::VBAFile()
{
}

void VBAFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a VBA format
}
void VBAFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id)
    {
    default:
        str.SetFormat("Unknown: 0x%08X", id);
        break;
    }
}
void VBAFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    syntax.tokens.Add(1, 0, 5, TokenColor::Keyword);
    syntax.tokens.Add(1, 5, 10, TokenColor::String, TokenAlignament::StartsOnNewLine);
}
} // namespace GView::Type::VBA