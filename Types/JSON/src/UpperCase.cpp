#include "json.hpp"
namespace GView::Type::JSON::Plugins
{
std::string_view UpperCase::GetName()
{
    return "KeyToUpperCase";
}
std::string_view UpperCase::GetDescription()
{
    return "Convert all keys to UpperCase";
}
bool UpperCase::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}
GView::View::LexicalViewer::PluginAfterActionRequest UpperCase::Execute(GView::View::LexicalViewer::PluginData& data)
{
    std::u16string tmp;
    for (auto index = data.startIndex; index < data.endIndex; index++)
    {
        auto token = data.tokens[index];
        if (token.GetTypeID(TokenType::invalid) == TokenType::key)
        {
            tmp = token.GetText();
            std::transform(tmp.begin(), tmp.end(), tmp.begin(), [](unsigned char c) { return std::toupper(c); });
            token.SetText(tmp);
        }
    }
    return View::LexicalViewer::PluginAfterActionRequest::Refresh;
}
} // namespace GView::Type::JSON::Plugins
