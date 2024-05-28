#include "js.hpp"

namespace GView::Type::JS::Plugins
{
using namespace GView::View::LexicalViewer;

std::string_view RemoveComments::GetName()
{
    return "Remove Comments";
}
std::string_view RemoveComments::GetDescription()
{
    return "Remove all comments from the file.";
}
bool RemoveComments::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    // At least one comment must be present
    auto end = std::min<>(data.tokens.Len(), data.endIndex);

    for (auto index = data.startIndex; index < end; index++)
    {
        if (data.tokens[index].GetTypeID(TokenType::None) == TokenType::Comment)
        {
            return true;
        }
    }
    return false;
}
GView::View::LexicalViewer::PluginAfterActionRequest RemoveComments::Execute(GView::View::LexicalViewer::PluginData& data)
{
    auto end   = std::min<>(data.tokens.Len(), data.endIndex);
    auto index = static_cast<int32>(end) - 1;

    while (index >= static_cast<int32>(data.startIndex)) {
        auto token = data.tokens[index];
        if (!token.IsValid())
            break;
        if (token.GetTypeID(TokenType::None) == TokenType::Comment) {
            auto start = token.GetTokenStartOffset();
            auto end   = token.GetTokenEndOffset();
            if ((start.has_value()) && (end.has_value())) {
                data.editor.Replace(start.value(), end.value() - start.value(), " ");
            }
        }
        index--;
    }
    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::JS::Plugins