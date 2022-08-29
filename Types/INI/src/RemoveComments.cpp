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
    return PluginAfterActionRequest::None;
}
} // namespace GView::Type::INI::Plugins