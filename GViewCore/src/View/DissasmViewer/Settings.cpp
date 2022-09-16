#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define INTERNAL_SETTINGS static_cast<SettingsData*>(this->data)

Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetDefaultDisassemblyLanguage(DisassemblyLanguage lang)
{
    INTERNAL_SETTINGS->defaultLanguage = lang;
}

void Settings::AddDisassemblyZone(uint64 zoneStart, uint64 zoneSize, uint64 zoneDissasmStartPoint, DisassemblyLanguage lang)
{
    INTERNAL_SETTINGS->disassemblyZones[zoneStart] = { zoneStart, zoneSize, zoneDissasmStartPoint, lang };
}

void Settings::AddMemoryMapping(uint64 address, std::string_view name)
{
    INTERNAL_SETTINGS->memoryMappings[address] = name;
}

void Settings::AddVariable(uint64 offset, std::string_view name, VariableType type)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { static_cast<InternalDissasmType>(type), name };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}
void Settings::AddArray(uint64 offset, std::string_view name, VariableType type, uint32 count)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::UnidimnsionalArray, name, (uint32) type, count };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}
void Settings::AddBidimensionalArray(uint64 offset, std::string_view name, VariableType type, uint32 width, uint32 height)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::BidimensionalArray, name, (uint32) type, width, height };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}

void Settings::AddVariable(uint64 offset, std::string_view name, TypeID type)
{
    auto res = INTERNAL_SETTINGS->userDesignedTypes.find(type);
    if (res == INTERNAL_SETTINGS->userDesignedTypes.end())
    {
        // err;
        return;
    }

    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = res->second;
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
}

void Settings::AddCollapsibleZone(uint64 offset, uint64 size)
{
    INTERNAL_SETTINGS->collapsibleAndTextZones[offset] = { offset, size, true };
}

void Settings::AddArray(uint64 offset, std::string_view name, TypeID type, uint32 count)
{
}
void Settings::AddBidimensionalArray(uint64 offset, std::string_view name, TypeID type, uint32 width, uint32 height)
{
}

SettingsData::SettingsData()
{
    defaultLanguage = DisassemblyLanguage::Default;
    availableID     = static_cast<uint32>(InternalDissasmType::CustomTypesStartingId);
}
