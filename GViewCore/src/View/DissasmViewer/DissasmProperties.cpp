#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

constexpr uint32 PROP_ID_ADD_NEW_TYPE          = 1;
constexpr uint32 PROP_ID_DISSASM_LANGUAGE      = 2;
constexpr uint32 PROP_ID_SHOW_FILE_CONTENT     = 3;
constexpr uint32 PROP_ID_SHOW_FILE_CONTENT_KEY = 4;

bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        value = config.AddNewTypeCommand.Key;
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        value = static_cast<uint64>(settings->defaultLanguage);
        return true;
    case PROP_ID_SHOW_FILE_CONTENT:
        value = config.ShowFileContent;
        return true;
    case PROP_ID_SHOW_FILE_CONTENT_KEY:
        value = config.ShowOrHideFileContentCommand.Key;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String&)
{
    switch (propertyID)
    {
    case PROP_ID_ADD_NEW_TYPE:
        config.AddNewTypeCommand.Key = std::get<Key>(value);
        return true;
    case PROP_ID_DISSASM_LANGUAGE:
        settings->defaultLanguage = static_cast<DisassemblyLanguage>(std::get<uint64>(value));
        return true;
    case PROP_ID_SHOW_FILE_CONTENT:
        config.ShowFileContent = std::get<bool>(value);
        return true;
    case PROP_ID_SHOW_FILE_CONTENT_KEY:
        config.ShowOrHideFileContentCommand.Key= std::get<Key>(value);
        return true;
    }
    return false;
}
void Instance::SetCustomPropertyValue(uint32)
{
}
bool Instance::IsPropertyValueReadOnly(uint32)
{
    return false;
    // return propertyID == PROP_ID_DISSASM_LANGUAGE;
}
const vector<Property> Instance::GetPropertiesList()
{
    return {
        { PROP_ID_ADD_NEW_TYPE, "Shortcuts", "Key adding new data type", PropertyType::Key },
        { PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, "x86=1,x64=2,JavaByteCode=3,IL=4" },
        { PROP_ID_SHOW_FILE_CONTENT, "General", "Show file content", PropertyType::Boolean },
        { PROP_ID_SHOW_FILE_CONTENT_KEY, "General", "Show file content key", PropertyType::Key},
    };
}

