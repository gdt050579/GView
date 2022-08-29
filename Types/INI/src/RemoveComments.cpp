#include "ini.hpp"

namespace GView::Type::INI::Plugins
{
std::string_view RemoveComments::GetName()
{
    return "Remove comments";
}
std::string_view RemoveComments::GetDescription()
{
    return "remove all comments from an ini/toml file";
}
bool RemoveComments::CanBeAppliedOn(const GView::View::LexicalViewer::PluginData& data)
{
    return true;
}
void RemoveComments::Execute(GView::View::LexicalViewer::PluginData& data)
{
}
} // namespace GView::Type::INI::Plugins