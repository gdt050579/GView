#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

Instance::Instance(const std::string_view& name, Reference<GView::Object> obj, Settings* settings) : name(name), obj(obj), settings(nullptr)
{

}


bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    return true;
}

bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    return true;
}

void Instance::SetCustomPropetyValue(uint32 propertyID)
{
}

bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return true;
}

const vector<Property> Instance::GetPropertiesList()
{
    return vector<Property>();
}

bool Instance::GoTo(uint64 offset)
{
    return true;
}

bool Instance::Select(uint64 offset, uint64 size)
{
    return true;
}

std::string_view Instance::GetName()
{
    return "DissasmView";
}

void Instance::PaintCursorInformation(AppCUI::Graphics::Renderer& renderer, uint32 width, uint32 height)
{
}
