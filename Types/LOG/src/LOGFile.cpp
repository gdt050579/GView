#include "log.hpp"

namespace GView::Type::Log
{
using namespace GView::View::LexicalViewer;

namespace CharacterType
{
    constexpr uint32 ip_address    = 0;
    constexpr uint32 dash          = 1;
    constexpr uint32 bracket_open  = 2;
    constexpr uint32 bracket_close = 3;
    constexpr uint32 quotes        = 4;
    constexpr uint32 space         = 5;
    constexpr uint32 alphanum      = 6;
    constexpr uint32 invalid       = 7;

    uint32 GetCharacterType(char16 ch)
    {
        if (ch == '.')
            return ip_address; // for parts of IP addresses
        if (ch == '-')
            return dash;
        if (ch == '[')
            return bracket_open;
        if (ch == ']')
            return bracket_close;
        if (ch == '"')
            return quotes;
        if (ch == ' ' || ch == '\t')
            return space;
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_')
            return alphanum;
        return invalid;
    }
} // namespace CharacterType

#define CHAR_CASE(char_type, align)                                                                                                                            \
    case CharacterType::char_type:                                                                                                                             \
        syntax.tokens.Add(TokenType::char_type, pos, pos + 1, TokenColor::Operator, TokenDataType::None, (align), TokenFlags::DisableSimilaritySearch);        \
        pos++;                                                                                                                                                 \
        break;

LogFile::LogFile()
{
}

void LogFile::ParseFile(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    auto len  = syntax.text.Len();
    auto pos  = 0u;
    auto next = 0u;

    while (pos < len) {
        auto char_type = CharacterType::GetCharacterType(syntax.text[pos]);
        switch (char_type) {
            CHAR_CASE(ip_address, TokenAlignament::None);
            CHAR_CASE(dash, TokenAlignament::None);
            CHAR_CASE(bracket_open, TokenAlignament::None);
            CHAR_CASE(bracket_close, TokenAlignament::None);
            CHAR_CASE(quotes, TokenAlignament::None);
            CHAR_CASE(space, TokenAlignament::None);
        case CharacterType::alphanum:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            syntax.tokens.Add(TokenType::value, pos, next, TokenColor::Word, TokenAlignament::AddSpaceBefore);
            pos = next;
            break;
        case CharacterType::invalid:
            next = syntax.text.ParseSameGroupID(pos, CharacterType::GetCharacterType);
            syntax.tokens.Add(TokenType::invalid, pos, next, TokenColor::Error, TokenAlignament::AddSpaceBefore).SetError("Invalid character in log file");
            pos = next;
            break;
        }
    }
}

void LogFile::BuildBlocks(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    // Logs usually don't have complex blocks like JSON, so we'll just handle each entry as a single block.
    auto len = syntax.tokens.Len();
    auto pos = 0u;

    for (; pos < len; pos++) {
        if (syntax.tokens[pos].GetTypeID(TokenType::invalid) == TokenType::value) {
            auto start = pos;
            while (pos < len && syntax.tokens[pos].GetTypeID(TokenType::invalid) != TokenType::invalid)
                pos++;
            syntax.blocks.Add(start, pos - 1, BlockAlignament::ParentBlockWithIndent, BlockFlags::EndMarker);
        }
    }

    // Add fold messages
    auto blocks_len = syntax.blocks.Len();
    LocalString<128> tmp;
    for (auto index = 0u; index < blocks_len; index++) {
        auto block = syntax.blocks[index];
        block.SetFoldMessage(tmp.Format("Tokens: %d", block.GetEndToken().GetIndex() - block.GetStartToken().GetIndex()));
    }
}

void LogFile::PreprocessText(GView::View::LexicalViewer::TextEditor&)
{
    // nothing to do --> there is no pre-processing needed for a log file format
}

void LogFile::GetTokenIDStringRepresentation(uint32 id, AppCUI::Utils::String& str)
{
    switch (id) {
    default:
        str.SetFormat("Unknown: 0x%08X", id);
        break;
    }
}

void LogFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    ParseFile(syntax);
    BuildBlocks(syntax);
}

bool LogFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool LogFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}


LogFile::~LogFile()
{
}
} // namespace GView::Type::Log
