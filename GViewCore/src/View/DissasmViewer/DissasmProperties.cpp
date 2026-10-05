#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

enum DissasmProperties : uint32 {
    // Config properties
    CacheSameLocationAsAnalyzedFileConfig,
    DeepScanDissasmOnStartConfig,
    ShowFileContentConfig,
    ShowOnlyDissasmConfig,
};

bool Instance::GetPropertyValue(uint32 propertyID, PropertyValue& value)
{
    switch (propertyID) {
    case ShowFileContentConfig:
        value = config.ShowFileContent;
        return true;
    case ShowOnlyDissasmConfig:
        value = config.ShowOnlyDissasm;
        return true;
    case DeepScanDissasmOnStartConfig:
        value = config.EnableDeepScanDissasmOnStart;
        return true;
    case CacheSameLocationAsAnalyzedFileConfig:
        value = config.CacheSameLocationAsAnalyzedFile;
        return true;
    }
    return false;
}
bool Instance::SetPropertyValue(uint32 propertyID, const PropertyValue& value, String&)
{
    switch (propertyID) {
    case ShowFileContentConfig:
        config.ShowFileContent = std::get<bool>(value);
        return true;
    case ShowOnlyDissasmConfig:
        config.ShowOnlyDissasm = std::get<bool>(value);
        return true;
    case DeepScanDissasmOnStartConfig:
        config.EnableDeepScanDissasmOnStart = std::get<bool>(value);
        return true;
    case CacheSameLocationAsAnalyzedFileConfig:
        config.CacheSameLocationAsAnalyzedFile = std::get<bool>(value);
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
    vector<Property> properties = {
        //{ PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, true, "x86=1,x64=2,JavaByteCode=3,IL=4" },
        { ShowFileContentConfig, "Config", "ShowFileContent", PropertyType::Boolean, true },
        { ShowOnlyDissasmConfig, "Config", "ShowOnlyDissasm", PropertyType::Boolean, true },
        { DeepScanDissasmOnStartConfig, "Config", "DeepScanDissasmOnStart", PropertyType::Boolean, true },
        { CacheSameLocationAsAnalyzedFileConfig, "Config", "CacheSameLocationAsAnalyzedFile", PropertyType::Boolean, true },
    };

    // keys are configured from the "Keyboard shortcuts" window
    return properties;
}
