#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

enum DissasmProperties : uint32 {
    // Config properties
    CacheSameLocationAsAnalyzedFileConfig,
    DeepScanDissasmOnStartConfig,
    ShowFileContentConfig,
    ShowOnlyDissasmConfig,

    // Key properties
    AddOrEditCommentKey,
    AsmExportToFileKey,
    GoToEntrypointKey,
    JumpBackKey,
    JumpForwardKey,
    QueryFunctionNameKey,
    QueryMITRETechniqueKey,
    RemoveCommentKey,
    RenameLabelKey,
    SaveCacheKey,
    ShowKeysKey,
    ShowOnlyDissasmKey
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
    case AddOrEditCommentKey:
        value = Config::AddOrEditCommentCommand.Key;
        return true;
    case AsmExportToFileKey:
        value = Config::AsmExportFileContentCommand.Key;
        return true;
    case GoToEntrypointKey:
        value = Config::GotoEntrypointCommand.Key;
        return true;
    case JumpBackKey:
        value = Config::JumpBackCommand.Key;
        return true;
    case JumpForwardKey:
        value = Config::JumpForwardCommand.Key;
        return true;
    case QueryFunctionNameKey:
        value = Config::CommandQueryFunctionName.Key;
        return true;
    case QueryMITRETechniqueKey:
        value = Config::CommandQueryMITRETechnique.Key;
        return true;
    case RemoveCommentKey:
        value = Config::RemoveCommentCommand.Key;
        return true;
    case RenameLabelKey:
        value = Config::RenameLabelCommand.Key;
        return true;
    case SaveCacheKey:
        value = Config::SaveCacheCommand.Key;
        return true;
    case ShowKeysKey:
        value = Config::ShowKeysWindowCommand.Key;
        return true;
    case ShowOnlyDissasmKey:
        value = Config::ShowOnlyDissasmCommand.Key;
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
    case AddOrEditCommentKey:
        Config::AddOrEditCommentCommand.Key = std::get<Input::Key>(value);
        return true;
    case AsmExportToFileKey:
        Config::AsmExportFileContentCommand.Key = std::get<Input::Key>(value);
        return true;
    case GoToEntrypointKey:
        Config::GotoEntrypointCommand.Key = std::get<Input::Key>(value);
        return true;
    case JumpBackKey:
        Config::JumpBackCommand.Key = std::get<Input::Key>(value);
        return true;
    case JumpForwardKey:
        Config::JumpForwardCommand.Key = std::get<Input::Key>(value);
        return true;
    case QueryFunctionNameKey:
        Config::CommandQueryFunctionName.Key = std::get<Input::Key>(value);
        return true;
    case QueryMITRETechniqueKey:
        Config::CommandQueryMITRETechnique.Key = std::get<Input::Key>(value);
        return true;
    case RemoveCommentKey:
        Config::RemoveCommentCommand.Key = std::get<Input::Key>(value);
        return true;
    case RenameLabelKey:
        Config::RenameLabelCommand.Key = std::get<Input::Key>(value);
        return true;
    case SaveCacheKey:
        Config::SaveCacheCommand.Key = std::get<Input::Key>(value);
        return true;
    case ShowKeysKey:
        Config::ShowKeysWindowCommand.Key = std::get<Input::Key>(value);
        return true;
    case ShowOnlyDissasmKey:
        Config::ShowOnlyDissasmCommand.Key = std::get<Input::Key>(value);
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
        //{ PROP_ID_DISSASM_LANGUAGE, "General", "Dissasm language", PropertyType::List, true, "x86=1,x64=2,JavaByteCode=3,IL=4" },
        { ShowFileContentConfig, "Config", "ShowFileContent", PropertyType::Boolean, true },
        { ShowOnlyDissasmConfig, "Config", "ShowOnlyDissasm", PropertyType::Boolean, true },
        { DeepScanDissasmOnStartConfig, "Config", "DeepScanDissasmOnStart", PropertyType::Boolean, true },
        { CacheSameLocationAsAnalyzedFileConfig, "Config", "CacheSameLocationAsAnalyzedFile", PropertyType::Boolean, true },

        { AddOrEditCommentKey, "Key", "AddOrEditComment", PropertyType::Key, true },
        { AsmExportToFileKey, "Key", "AsmExportToFile", PropertyType::Key, true },
        { GoToEntrypointKey, "Key", "GoToEntrypoint", PropertyType::Key, true },
        { JumpBackKey, "Key", "JumpBack", PropertyType::Key, true },
        { JumpForwardKey, "Key", "JumpForward", PropertyType::Key, true },
        { QueryFunctionNameKey, "Key", "QueryFunctionName", PropertyType::Key, true },
        { QueryMITRETechniqueKey, "Key", "QueryMITRETechnique", PropertyType::Key, true },
        { RemoveCommentKey, "Key", "RemoveComment", PropertyType::Key, true },
        { RenameLabelKey, "Key", "RenameLabel", PropertyType::Key, true },
        { SaveCacheKey, "Key", "SaveCache", PropertyType::Key, true },
        { ShowKeysKey, "Key", "ShowKeys", PropertyType::Key, true },
        { ShowOnlyDissasmKey, "Key", "ShowOnlyDissasm", PropertyType::Key, true },
    };
}
