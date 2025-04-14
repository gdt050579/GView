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
    return true;
}

PluginAfterActionRequest ConcatenateConstantStrings::Execute(PluginData& data, Reference<Window> parent)
{
    return PluginAfterActionRequest::None;
}

}