#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define INTERNAL_SETTINGS ((SettingsData*) this->data)

Settings::Settings()
{
    this->data = new SettingsData();
    INTERNAL_SETTINGS->availableID = 0;
}

void Settings::SetDefaultDissasemblyLanguage(DissamblyLanguage lang)
{
    INTERNAL_SETTINGS->defaultLanguage = lang;
}

void Settings::ReserverZonesCapacity(uint32 reserved_size)
{
    INTERNAL_SETTINGS->zones.reserve(reserved_size);
}

void Settings::AddDissasemblyZone(uint64 start, uint64 size, DissamblyLanguage lang)
{
    INTERNAL_SETTINGS->zones.emplace_back(start, size, lang);
}

void Settings::AddMemmoryMapping(uint64 address, std::string_view name)
{
    INTERNAL_SETTINGS->memoryMappings[address] = name;
}

void Settings::AddVariable(uint64 offset, std::string_view name, VariableType type)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { (InternalDissasmType) type, name };
}
void Settings::AddArray(uint64 offset, std::string_view name, VariableType type, uint32 count)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::UnidimnsionalArray, name, (uint32) type, count };
}
void Settings::AddBiDiminesionalArray(uint64 offset, std::string_view name, VariableType type, uint32 width, uint32 height)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::BiimensionalArray, name, (uint32) type, width, height };
}

void Settings::AddVariable(uint64 offset, std::string_view name, TypeID type)
{
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