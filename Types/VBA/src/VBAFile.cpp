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
    CHECKRET(str.SetFormat("Unknown: 0x%08X", id), "");
}

void VBAFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    syntax.tokens.Add(1, 0, 5, TokenColor::Keyword);
    syntax.tokens.Add(1, 5, 10, TokenColor::String, TokenAlignament::StartsOnNewLine);
}

bool VBAFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool VBAFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}
} // namespace GView::Type::VBA
