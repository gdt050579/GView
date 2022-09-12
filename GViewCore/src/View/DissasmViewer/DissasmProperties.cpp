#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

constexpr uint32 PROP_ID_ADD_NEW_TYPE     = 1;
constexpr uint32 PROP_ID_DISSASM_LANGUAGE = 2;

bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        value = config.Keys.AddNewType;
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        value = (uint64) (settings->defaultLanguage);
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String& error)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        config.Keys.AddNewType = std::get<Key>(value);
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        settings->defaultLanguage = static_cast<DissasemblyLanguage>(std::get<uint64>(value));
        return true;
    }
    return false;
}
void Instance::SetCustomPropertyValue(uint32 propertyID)
{
}
bool Instance::IsPropertyValueReadOnly(uint32 propertyID)
{
    return false;
    // return propertyID == PROP_ID_DISSASM_LANGUAGE;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { PROP_ID_ADD_NEW_TYPE, "Shortcuts", "Key addind new data type", PropertyType::Key },
        { PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, "x86=1,x64=2,JavaByteCode=3,IL=4" },
    };
}
