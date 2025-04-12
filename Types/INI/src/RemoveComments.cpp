#include "ini.hpp"

namespace GView::Type::INI::Plugins
{
    using namespace GView::View::LexicalViewer;
std::string_view RemoveComments::GetName()
{
    return "Remove comments";
}
std::string_view RemoveComments::GetDescription()
{
    return "remove all comments from an ini/toml file";
}
bool RemoveComments::CanBeAppliedOn(const PluginData& data)
{
    // at least one comment must be present
    auto len = std::min<>(data.tokens.Len(), data.endIndex);
    for (auto index=data.startIndex;index<len;index++)
    {
        if (data.tokens[index].GetTypeID(TokenType::Invalid) == TokenType::Comment)
            return true;
    }
    return false;
}
PluginAfterActionRequest RemoveComments::Execute(PluginData& data, Reference<Window> parent)
{
    auto len    = std::min<>(data.tokens.Len(), data.endIndex);    
    int32 index = static_cast<int32>(len) - 1;
    while (index>=static_cast<int32>(data.startIndex))
    {
        auto token = data.tokens[index];
        if (!token.IsValid())
            break;
        if (token.GetTypeID(TokenType::Invalid) == TokenType::Comment)
        {
            auto start = token.GetTokenStartOffset();
            auto end   = token.GetTokenEndOffset();
            if ((start.has_value()) && (end.has_value()))
            {
                data.editor.Delete(start.value(), end.value()-start.value());
            }
            
        }
        index--;
    }
    return PluginAfterActionRequest::Rescan;
}
} // namespace GView::Type::INI::Plugins