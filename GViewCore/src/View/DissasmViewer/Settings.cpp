#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define INTERNAL_SETTINGS ((SettingsData*) this->data)

Settings::Settings()
{
    this->data                     = new SettingsData();
    INTERNAL_SETTINGS->availableID = (uint32) InternalDissasmType::UserDefined + 1;
}

void Settings::SetDefaultDissasemblyLanguage(DissamblyLanguage lang)
{
    INTERNAL_SETTINGS->defaultLanguage = lang;
}

void Settings::AddDissasemblyZone(uint64 start, uint64 size, DissamblyLanguage lang)
{
    INTERNAL_SETTINGS->dissasemblyZones[start] = { size, lang };
}

void Settings::AddMemmoryMapping(uint64 address, std::string_view name)
{
    INTERNAL_SETTINGS->memoryMappings[address] = name;
}

void Settings::AddVariable(uint64 offset, std::string_view name, VariableType type)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { (InternalDissasmType) type, name };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}
void Settings::AddArray(uint64 offset, std::string_view name, VariableType type, uint32 count)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::UnidimnsionalArray, name, (uint32) type, count };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}
void Settings::AddBiDiminesionalArray(uint64 offset, std::string_view name, VariableType type, uint32 width, uint32 height)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::BidimensionalArray, name, (uint32) type, width, height };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}

void Settings::AddVariable(uint64 offset, std::string_view name, TypeID type)
{
    auto res = INTERNAL_SETTINGS->userDeginedTypes.find(type);
    if (res == INTERNAL_SETTINGS->userDeginedTypes.end())
    {
        // err;
        return;
    }

    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = res->second;
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}
void Settings::AddArray(uint64 offset, std::string_view name, TypeID type, uint32 count)
{
}
void Settings::AddBiDiminesionalArray(uint64 offset, std::string_view name, TypeID type, uint32 width, uint32 height)
{
}

SettingsData::SettingsData()
{
    defaultLanguage = DissamblyLanguage::Default;
}