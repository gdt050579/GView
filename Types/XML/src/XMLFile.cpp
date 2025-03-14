#include "xml.hpp"
#include <nlohmann/json.hpp>
using nlohmann::json;

namespace GView::Type::XML
{
using namespace GView::View::LexicalViewer;

namespace CharType
{
    constexpr uint8 Text     = 0;
    constexpr uint8 Space    = 1;
    constexpr uint8 StartTag = 2;
    constexpr uint8 EndTag   = 3;
    constexpr uint8 Colon    = 4;
    constexpr uint8 Equals   = 5;
    constexpr uint8 Slash    = 6;
    constexpr uint8 Invalid  = 7;
    constexpr uint8 String   = 8;

uint8 XML_Groups_IDs[] = { Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Invalid,  Space,   Space,   Invalid, Invalid,
                               Space,   Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Invalid,  Invalid, Invalid, Invalid, Invalid,
                               Invalid, Invalid, Invalid, Invalid, Invalid, Invalid, Space,   Text,    String,   Invalid, Invalid, Text,    Text,
                               Text,    Invalid, Invalid, Text,    Text,    Invalid, Text,    Text,    Slash,    Text,    Text,    Text,    Text,
                               Text,    Text,    Text,    Text,    Text,    Text,    Colon,   Invalid, StartTag, Equals,  EndTag,  Text,    Invalid,
                               Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,     Text,    Text,    Text,    Text,
                               Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,     Text,    Text,    Text,    Text,
                               Invalid, Invalid, Invalid, Text,    Text,    Invalid, Text,    Text,    Text,     Text,    Text,    Text,    Text,
                               Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,    Text,     Text,    Text,    Text,    Text,
                               Text,    Text,    Text,    Text,    Text,    Text,    Invalid, Text,    Invalid,  Text,    Invalid };


    inline uint32 GetCharType(char16 c)
    {
        if (c < ARRAY_LEN(XML_Groups_IDs))
            return XML_Groups_IDs[c];
        return Invalid;
    }

} // namespace CharType

void XMLFile::Tokenize(uint32 start, uint32 end, const TextParser& text, TokensList& tokenList, BlocksList& blocks)
{
    auto idx = start;

    bool insideText = false;
    auto startText  = 0U;

    while (idx < end) {
        const auto ch   = text[idx];
        const auto type = CharType::GetCharType(ch);

        if (insideText && type != CharType::Text) {
            insideText = false;

            auto tokenColor = TokenColor::Word;
            auto tokenToUse = TokenType::Text;
            if (type == CharType::Colon) {
                tokenToUse = TokenType::AttributeClass;
                tokenColor = TokenColor::Constant;
            }

            tokenList.Add(tokenToUse, startText, idx, tokenColor, TokenDataType::String);
        }

        switch (type) {
        case CharType::Space:
            idx = text.ParseSpace(idx, SpaceType::All);
            break;
        case CharType::Text:
            // text.ParseSameGroupID -- TODO cu GetCharType
            if (!insideText)
                startText = idx;
            insideText = true;
            idx++;
            break;
        case CharType::StartTag:
            tokenList.Add(
                  TokenType::StartTag, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::EndTag:
            tokenList.Add(
                  TokenType::EndTag, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::Colon:
            tokenList.Add(
                  TokenType::Colon, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::Equals:
            tokenList.Add(
                  TokenType::Equals, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::Slash:
            tokenList.Add(
                  TokenType::Slash, idx, idx + 1, TokenColor::Operator, TokenDataType::None, TokenAlignament::None, TokenFlags::DisableSimilaritySearch);
            idx++;
            break;
        case CharType::String: {
            const auto next = text.ParseString(idx, StringFormat::DoubleQuotes);
            tokenList.Add(
                  TokenType::String,
                  idx,
                  next,
                  TokenColor::String,
                  TokenDataType::String,
                  TokenAlignament::AddSpaceAfter | TokenAlignament::AddSpaceBefore,
                  TokenFlags::None);
            idx = next;
            break;
        }
        default:
            const auto next = text.ParseSameGroupID(idx, CharType::GetCharType);
            tokenList.Add(TokenType::ErrorValue, idx, next, TokenColor::Word).SetError("Invalid character sequence");
            idx = next;
            break;
        }
    }

    if (insideText) {
        tokenList.Add(TokenType::Text, startText, idx, TokenColor::String, TokenDataType::String);
    }
}

void XMLFile::Tokenize(const TextParser& text, TokensList& tokenList, BlocksList& blocks)
{
    Tokenize(0, text.Len(), text, tokenList, blocks);
}

void XMLFile::BuildBlocks(SyntaxManager& syntax)
{
    TokenIndexStack blocks;
    bool wasStartTag = false;
    bool wasSlash    = false;

    auto len = syntax.tokens.Len();
    for (auto index = 0U; index < len; index++) {
        const auto typeID = syntax.tokens[index].GetTypeID(TokenType::None);
        if (wasStartTag && typeID != TokenType::Slash) {
            wasStartTag = false;
            blocks.Push(index - 1);
            // syntax.tokens[index-1].SetAlignament(TokenAlignament::IncrementIndentBeforePaint | TokenAlignament::StartsOnNewLine);
        }
        switch (typeID) {
        case TokenType::StartTag:
            wasStartTag = true;
            break;
        case TokenType::Slash:
            if (wasStartTag) {
                wasStartTag = false;
                wasSlash    = true;
            }else {
                blocks.Pop();
                auto token = syntax.tokens[index].Next();
                if (token.IsValid())
                    token.UpdateAlignament(TokenAlignament::NewLineAfter);
            }
            break;
        case TokenType::EndTag:
            if (wasSlash) {
                syntax.blocks.Add(blocks.Pop(), index, BlockAlignament::CurrentToken, BlockFlags::EndMarker | BlockFlags::ManualCollapse);
                wasSlash = false;
            }
            break;
        default:
            break;
        }
    }
}

void XMLFile::IndentSimpleInstructions(TokensList& list, BlocksList& blocks)
{
    auto len = list.Len();
    for (uint32 i = 0; i < len; i++) {
        const auto typeID = list[i].GetTypeID(TokenType::None);
        if (typeID == TokenType::Text && i + 1 < len) {
            const auto nextTokenId = list[i + 1].GetTypeID(TokenType::None);
            if (nextTokenId != TokenType::StartTag && nextTokenId != TokenType::EndTag)
                list[i].UpdateAlignament(TokenAlignament::AddSpaceAfter);
        } else if (typeID == TokenType::Equals)
            list[i].UpdateAlignament(TokenAlignament::AddSpaceAfter);
    }

    len = blocks.Len();
    for (uint32 i = 0; i < len; i++) {
        auto startToken = blocks[i].GetStartToken();
        startToken.UpdateAlignament(TokenAlignament::NewLineBefore);
        while (startToken.IsValid()) {
            const auto tokenType = startToken.GetTypeID(TokenType::None);
            if (tokenType == TokenType::None)
                break;
            if (tokenType == TokenType::EndTag) {
                startToken = startToken.Next();
                if (startToken.IsValid() && startToken.GetTypeID(TokenType::None) != TokenType::None)
                    startToken.UpdateAlignament(TokenAlignament::IncrementIndentBeforePaint | TokenAlignament::StartsOnNewLine);
                break;
            }
            startToken = startToken.Next();
        }

        auto endToken = blocks[i].GetEndToken();
        endToken.UpdateAlignament(TokenAlignament::NewLineAfter);
        while (endToken.IsValid()) {
            const auto tokenType = endToken.GetTypeID(TokenType::None);
            if (tokenType == TokenType::None)
                break;
            if (tokenType == TokenType::StartTag) {
                endToken.UpdateAlignament(
                      TokenAlignament::StartsOnNewLine | TokenAlignament::DecrementIndentBeforePaint, TokenAlignament::IncrementIndentBeforePaint);
                break;
            }
            endToken = endToken.Precedent();
        }
    }
}

XMLFile::XMLFile()
{
}

bool XMLFile::Update()
{
    return true;
}

void XMLFile::GetTokenIDStringRepresentation(uint32 id, String& str)
{
    switch (id & 0xFFFFFFFF) {
    case TokenType::None:
        str.Set("Uknwon/Error");
        break;
    case TokenType::StartTag:
        str.Set("StartTag");
        break;
    case TokenType::EndTag:
        str.Set("EndTag");
        break;
    case TokenType::TagName:
        str.Set("Tag name");
        break;
    case TokenType::Colon:
        str.Set("Colon");
        break;
    case TokenType::Equals:
        str.Set("Equals");
        break;
    case TokenType::Text:
        str.Set("Text");
        break;
    case TokenType::Slash:
        str.Set("Slash");
        break;
    case TokenType::ErrorValue:
        str.Set("ErrorValue");
        break;
    case TokenType::AttributeClass:
        str.Set("Namespace");
        break;
    default:
        str.Set("UNSET VALUE");
        break;
    }
}

void XML::XMLFile::PreprocessText(TextEditor& editor)
{
    const auto magic = editor.Find(0, "<?xml version=", true);
    if (!magic.has_value())
        return;
    const auto magicEnd = editor.Find(magic.value(), "?>");
    if (!magicEnd.has_value())
        return;
    const auto newSeq = editor.Find(magicEnd.value(), "<");
    if (!newSeq.has_value())
        return;
    editor.Delete(0, newSeq.value() - 1);
}

void XML::XMLFile::AnalyzeText(SyntaxManager& syntax)
{
    syntax.tokens.ResetLastTokenID(TokenType::None);
    Tokenize(syntax.text, syntax.tokens, syntax.blocks);
    BuildBlocks(syntax);
    IndentSimpleInstructions(syntax.tokens, syntax.blocks);
}

bool XMLFile::StringToContent(std::u16string_view string, UnicodeStringBuilder& result)
{
    return true;
}

bool XMLFile::ContentToString(std::u16string_view content, UnicodeStringBuilder& result)
{
    return true;
}

std::string XMLFile::GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt)
{
    json context;
    context["Name"]        = obj->GetName();
    context["ContentSize"] = obj->GetData().GetSize();
    return context.dump();
}
} // namespace GView::Type::XML