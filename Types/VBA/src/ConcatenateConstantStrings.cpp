#include "vba.hpp"

namespace GView::Type::VBA::Plugins
{

using namespace GView::View::LexicalViewer;

std::string_view ConcatenateConstantStrings::GetName()
{
    return "Concatenate Constant Strings";
}

std::string_view ConcatenateConstantStrings::GetDescription()
{
    return "Concatenate constant strings";
}

bool ConcatenateConstantStrings::CanBeAppliedOn(const PluginData& data)
{
    for (uint32 i = data.endIndex; i >= data.startIndex + 2; i--) {
        auto token = data.tokens[i];
        if (token.GetTypeID(TokenType::None) != TokenType::String)
            continue;
        auto prevToken     = data.tokens[i - 1];
        auto prevPrevToken = data.tokens[i - 2];
        if (!prevToken.IsValid() || !prevPrevToken.IsValid())
            continue;
        if (prevPrevToken.GetTypeID(TokenType::None) != TokenType::String)
            continue;
        const auto prevTokenType = prevToken.GetTypeID(TokenType::None);
        if (prevTokenType != TokenType::Plus && prevTokenType != TokenType::Ampersand)
            return true;
    }
    return false;
}

PluginAfterActionRequest ConcatenateConstantStrings::Execute(PluginData& data, Reference<Window> parent)
{
    for (uint32 i = data.endIndex; i >= data.startIndex + 2; i--) {
        auto token = data.tokens[i];
        if (token.GetTypeID(TokenType::None) != TokenType::String)
            continue;
        auto prevToken     = data.tokens[i - 1];
        auto prevPrevToken = data.tokens[i - 2];
        if (!prevToken.IsValid() || !prevPrevToken.IsValid())
            continue;
        if (prevPrevToken.GetTypeID(TokenType::None) != TokenType::String)
            continue;
        const auto prevTokenType = prevToken.GetTypeID(TokenType::None);
        if (prevTokenType != TokenType::Plus && prevTokenType != TokenType::Ampersand)
            continue;

        auto firstToken       = prevPrevToken;
        uint32 searchingIndex = i - 3;
        while (searchingIndex >= data.startIndex + 2) {
            auto searchingToken     = data.tokens[searchingIndex];
            auto searchingTokenType = searchingToken.GetTypeID(TokenType::None);
            if (searchingTokenType != TokenType::Plus && searchingTokenType != TokenType::Ampersand)
                break;
            searchingIndex--;
            i--;
            if (searchingIndex < data.startIndex + 2)
                break;
            searchingToken     = data.tokens[searchingIndex];
            searchingTokenType = searchingToken.GetTypeID(TokenType::None);
            if (searchingTokenType != TokenType::String)
                break;
            firstToken = searchingToken;
            searchingIndex--;
            i--;
        }

        UnicodeStringBuilder sb;
        for (uint32 j = firstToken.GetIndex(); j <= token.GetIndex(); j++) {
            auto token = data.tokens[j];
            if (token.GetTypeID(TokenType::None) != TokenType::String)
                continue;
            if (!token.GetText().empty())
                sb.Add(token.GetText());
        }

        CharacterBuffer cb;
        cb.Set(sb.ToStringView());
        for (uint32 j = 1; j < cb.Len() - 1; j++) {
            const auto c = cb.GetBuffer() + j;
            if (c->Code == u'\"') {
                cb.DeleteChar(j);
                j--;
            }
        }
        std::u16string result;
        if (!cb.ToString(result))
            continue;

        auto startOffset = firstToken.GetTokenStartOffset();
        auto endOffset   = token.GetTokenEndOffset();
        if (!startOffset.has_value() || !endOffset.has_value())
            return GView::View::LexicalViewer::PluginAfterActionRequest::None;
        const auto size = endOffset.value() - startOffset.value();
        data.editor.Replace(startOffset.value(), size, result);
    }
    return PluginAfterActionRequest::Rescan;
}

} // namespace GView::Type::VBA::Plugins