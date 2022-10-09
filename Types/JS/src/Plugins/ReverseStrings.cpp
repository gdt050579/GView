#include "js.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view ReverseStrings::GetName()
{
    return "Reverse Strings";
}
std::string_view ReverseStrings::GetDescription()
{
    return "Get an inverted buffer.";
}
bool ReverseStrings::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    for (auto index = data.startIndex; index < data.endIndex; index++)
    {
        if (data.tokens[index].GetTypeID(TokenType::None) == TokenType::String)
        {
            return true;
        }
    }
    return false;
}
GView::View::LexicalViewer::PluginAfterActionRequest ReverseStrings::Execute(GView::View::LexicalViewer::PluginData& data)
{
    for (int32 index = (int32) data.startIndex; index < data.endIndex; index++)
    {
        Token currentToken = data.tokens[index];
        if (currentToken.GetTypeID(TokenType::None) == TokenType::String)
        {
            u16string_view txt = currentToken.GetText();

            std::u16string reversableTxt{ txt };

            std::reverse(reversableTxt.begin(), reversableTxt.end());

            auto startOffset = currentToken.GetTokenStartOffset();
            auto endOffset   = currentToken.GetTokenEndOffset();

            if (!startOffset.has_value() || !endOffset.has_value())
                return GView::View::LexicalViewer::PluginAfterActionRequest::None;
            auto size = endOffset.value() - startOffset.value();

            data.editor.Replace(startOffset.value(), size, reversableTxt);
        }
    }

    return GView::View::LexicalViewer::PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins