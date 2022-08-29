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
    return true;
}
PluginAfterActionRequest RemoveComments::Execute(PluginData& data)
{
    int32 index = static_cast<int32>(data.tokens.Len()) - 1;
    while (index>=0)
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