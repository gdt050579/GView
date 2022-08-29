#include "ini.hpp"

namespace GView::Type::INI::Plugins
{
    using namespace GView::View::LexicalViewer;
std::string_view Casing::GetName()
{
    return "Change case-ing";
}
std::string_view Casing::GetDescription()
{
    return "Change case-ing for keys and sections";
}
bool Casing::CanBeAppliedOn(const PluginData& data)
{
    return true;
}
PluginAfterActionRequest Casing::Execute(PluginData& data)
{
    return PluginAfterActionRequest::None;
}
} // namespace GView::Type::INI::Plugins