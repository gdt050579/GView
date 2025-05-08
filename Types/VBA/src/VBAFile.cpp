#include <codecvt>
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
    switch (id) {
    case TokenType::None:
        str.Set("Unknown/Error");
        break;
    case TokenType::Unknown:
        str.Set("Unknown");
        break;
    case TokenType::Equal:
        str.Set("Equal Sign ('=')");
        break;
    case TokenType::LeftParen:
        str.Set("Left Parenthesis ('(')");
        break;
    case TokenType::RightParen:
        str.Set("Right Parenthesis (')')");
        break;
    case TokenType::Comma:
        str.Set("Comma (',')");
        break;
    case TokenType::Dot:
        str.Set("Dot ('.')");
        break;
    case TokenType::Underscore:
        str.Set("Underscore ('_')");
        break;
    case TokenType::Ampersand:
        str.Set("Ampersand ('&')");
        break;
    case TokenType::Dollar:
        str.Set("Dollar Sign ('$')");
        break;
    case TokenType::Plus:
        str.Set("Plus Sign ('+')");
        break;
    case TokenType::Minus:
        str.Set("Minus Sign ('-')");
        break;
    case TokenType::Asterisk:
        str.Set("Asterisk ('*')");
        break;
    case TokenType::Slash:
        str.Set("Slash ('/')");
        break;
    case TokenType::LessThan:
        str.Set("Less Than ('<')");
        break;
    case TokenType::GreaterThan:
        str.Set("Greater Than ('>')");
        break;
    case TokenType::Hash:
        str.Set("Hash ('#')");
        break;
    case TokenType::Backslash:
        str.Set("Backslash ('\\')");
        break;
    case TokenType::Colon:
        str.Set("Colon (':')");
        break;
    case TokenType::String:
        str.Set("String");
        break;
    case TokenType::Variable:
        str.Set("Variable");
        break;
    case TokenType::Keyword:
        str.Set("Keyword");
        break;
    case TokenType::Comment:
        str.Set("Comment");
        break;
    case TokenType::AplhaNum:
        str.Set("AplhaNum");
        break;
    case TokenType::VariableRef:
        str.Set("Variable reference");
        break;
    default:
        str.SetFormat("Unknown Token: 0x%08X", id);
        break;
    }
}


uint32 ParseString(GView::View::LexicalViewer::TextParser text, uint32 index)
{
    uint32 end = text.Parse(index + 1, [](char16 c) { return c != '"'; });
    return end + 1;
}

UnicodeStringBuilder KEYWORDS[] = { UnicodeStringBuilder("Attribute"), UnicodeStringBuilder("Sub"),   UnicodeStringBuilder("Private"),
                                    UnicodeStringBuilder("Public"),    UnicodeStringBuilder("As"),    UnicodeStringBuilder("Dim"),
                                    UnicodeStringBuilder("End"),       UnicodeStringBuilder("Const"), UnicodeStringBuilder("ByVal"),
                                    UnicodeStringBuilder("Set"),       UnicodeStringBuilder("While"), UnicodeStringBuilder("Wend"),
                                    UnicodeStringBuilder("If"),        UnicodeStringBuilder("Then") };

UnicodeStringBuilder KEYWORDS2[] = { UnicodeStringBuilder("True"), UnicodeStringBuilder("False") };

const char operators[]                = "=(),._&$+-*/<>#\\:";
constexpr uint32 TokenTypeOperators[] = {
    TokenType::Equal,       // '='
    TokenType::LeftParen,   // '('
    TokenType::RightParen,  // ')'
    TokenType::Comma,       // ','
    TokenType::Dot,         // '.'
    TokenType::Underscore,  // '_'
    TokenType::Ampersand,   // '&'
    TokenType::Dollar,      // '$'
    TokenType::Plus,        // '+'
    TokenType::Minus,       // '-'
    TokenType::Asterisk,    // '*'
    TokenType::Slash,       // '/'
    TokenType::LessThan,    // '<'
    TokenType::GreaterThan, // '>'
    TokenType::Hash,        // '#'
    TokenType::Backslash,   // '\\'
    TokenType::Colon        // ':'
};

void VBAFile::AnalyzeText(GView::View::LexicalViewer::SyntaxManager& syntax)
{
    uint32 start = 0;
    uint32 end   = 0;
    variables.clear();

    TokenAlignament presetAlignament = TokenAlignament::None;

    while (start < syntax.text.Len()) {
        auto c = syntax.text[start];

        if (c == ' ') {
            end = syntax.text.ParseSpace(end, SpaceType::Space);
            if ((uint32) presetAlignament & (uint32) TokenAlignament::StartsOnNewLine) {
                syntax.tokens.Add(TokenType::Unknown, start, end, TokenColor::Word, presetAlignament);
                presetAlignament = TokenAlignament::None;
            }
            start = end;
            continue;
        }

        bool parseSpace = false;
        if (isalpha(c)) {
            uint32 tokenType = TokenType::AplhaNum;
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isalnum(c) || c == '_'; });

            const auto currentTextValue = syntax.text.GetSubString(start, end);
            TokenColor color = TokenColor::Word;
            for (auto& keyword : KEYWORDS) {
                if (currentTextValue == keyword) {
                    color = TokenColor::Keyword;
                    tokenType = TokenType::Keyword;
                    break;
                }
            }

            for (auto& keyword : KEYWORDS2) {
                if (currentTextValue == keyword) {
                    color = TokenColor::Keyword2;
                    tokenType = TokenType::Keyword;
                    break;
                }
            }

            if (tokenType == TokenType::AplhaNum) {
                auto it = variables.find(std::u16string(currentTextValue));
                if (it != variables.end())
                    tokenType = TokenType::VariableRef;
            }

            syntax.tokens.Add(tokenType, start, end, color, presetAlignament);
            parseSpace = true;
        }

        if (isdigit(c)) {
            end = syntax.text.Parse(start, [](char16 c) { return (bool) isdigit(c); });
            syntax.tokens.Add(TokenType::Unknown, start, end, TokenColor::Number, presetAlignament);
            parseSpace = true;
        }

        for (size_t i = 0; i < sizeof(operators) - 1; ++i) {
            if (c == operators[i]) {
                end = start + 1;
                syntax.tokens.Add(TokenTypeOperators[i], start, end, TokenColor::Operator, presetAlignament);
                parseSpace = true;
            }
        }

        if (c == '"') {
            end = ParseString(syntax.text, start);

            bool isVariable = false;
            if (syntax.tokens.GetLastToken().IsValid()) {
                const auto tokenID = syntax.tokens.GetLastToken().GetTypeID(TokenType::None);
                if (tokenID == TokenType::Equal) {
                    auto beforeLast = syntax.tokens.GetLastToken().Precedent();
                    if (beforeLast.IsValid() && beforeLast.GetTypeID(TokenType::None) == TokenType::AplhaNum) {
                        beforeLast.SetTypeID(TokenType::Variable);
                        isVariable = true;
                    }
                }
            }

            syntax.tokens.Add(TokenType::String, start, end, TokenColor::String, presetAlignament);
            if (isVariable) {
                auto lastToken = syntax.tokens.GetLastToken();
                auto variableName = lastToken.Precedent().Precedent().GetText();
                auto variableValue = lastToken.GetText();
                variables[std::u16string(variableName)] = std::u16string(variableValue);
            }
            parseSpace = true;
        }

        if (parseSpace) {
            start = syntax.text.ParseSpace(end, SpaceType::Space);

            if (start > end) {
                presetAlignament = TokenAlignament::AddSpaceBefore;
            } else {
                presetAlignament = TokenAlignament::None;
            }
            continue;
        }

        if (c == '\r' || c == '\n') {
            end              = syntax.text.ParseUntilStartOfNextLine(start);
            presetAlignament = TokenAlignament::StartsOnNewLine;
            start            = end;
            continue;
        }

        if (c == '\t') {
            end   = syntax.text.ParseSpace(end, SpaceType::Tabs);
            start = end;
            continue;
        }

        if (c == '\'') {
            end = syntax.text.ParseUntilEndOfLine(start);
            syntax.tokens.Add(TokenType::Comment, start, end, TokenColor::Comment, presetAlignament | TokenAlignament::NewLineAfter);
            start = syntax.text.ParseUntilStartOfNextLine(end);
            continue;
        }
        break;
    }
}

bool VBAFile::StringToContent(std::u16string_view string, AppCUI::Utils::UnicodeStringBuilder& result)
{
    return TextParser::ExtractContentFromString(string, result, StringFormat::All);
}

bool VBAFile::ContentToString(std::u16string_view content, AppCUI::Utils::UnicodeStringBuilder& result)
{
    NOT_IMPLEMENTED(false);
}

std::string VBAFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    bool isValidName = true;
    std::string name;
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
        name = converter.to_bytes(std::u16string(obj->GetName()));
    } catch (const std::exception&) {
        isValidName = false;
    }

    std::stringstream context;
    context << "{";
    if (isValidName)
        context << "\"Name\": \"" << name << "\",";
    context << "\"ContentSize\": " << obj->GetData().GetSize();
    context << "\n}";
    return context.str();
}
} // namespace GView::Type::VBA
