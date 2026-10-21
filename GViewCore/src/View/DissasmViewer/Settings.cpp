#include "DissasmViewer.hpp"

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;
using GView::View::BufferViewer::OffsetTranslateInterface;

#define INTERNAL_SETTINGS static_cast<SettingsData*>(this->data)
//#define DISSASM_DISABLE_API_CALLS

Settings::Settings()
{
    this->data = new SettingsData();
}

void Settings::SetDefaultDisassemblyLanguage(DisassemblyLanguage lang)
{
    if (lang == DisassemblyLanguage::Default || lang == DisassemblyLanguage::Count)
        lang = DisassemblyLanguage::x86;
    INTERNAL_SETTINGS->defaultLanguage = lang;
}

void Settings::AddDisassemblyZone(uint64 zoneStart, uint64 zoneSize, uint64 zoneDissasmStartPoint, DisassemblyLanguage lang)
{
    if (lang == DisassemblyLanguage::Default || lang == DisassemblyLanguage::Count)
        lang = INTERNAL_SETTINGS->defaultLanguage;
    INTERNAL_SETTINGS->disassemblyZones[zoneStart] = { zoneStart, zoneSize, zoneDissasmStartPoint, lang, {}, false };
}

void Settings::AddDataZone(uint64 zoneStart, uint64 zoneSize, DisassemblyLanguage lang, std::string_view name)
{
    AddDisassemblyZone(zoneStart, zoneSize, NO_ENTRY_POINT, lang, name);
    INTERNAL_SETTINGS->disassemblyZones[zoneStart].isData = true;
}

void Settings::AddDisassemblyZone(uint64 zoneStart, uint64 zoneSize, uint64 zoneDissasmStartPoint, DisassemblyLanguage lang, std::string_view name)
{
    AddDisassemblyZone(zoneStart, zoneSize, zoneDissasmStartPoint, lang);
    INTERNAL_SETTINGS->disassemblyZones[zoneStart].name = std::string(name); // a string_view is not NUL terminated
}

void Settings::AddMemoryMapping(uint64 address, std::string_view name, MemoryMappingType mappingType)
{
#ifndef DISSASM_DISABLE_API_CALLS
    INTERNAL_SETTINGS->memoryMappings.insert({ address, { std::string(name), mappingType } }); // a string_view is not NUL terminated
#endif
}

void Settings::AddFunctionEntry(uint64 fileOffset, std::string_view name, FunctionEntryType type, uint64 size)
{
    auto& entry = INTERNAL_SETTINGS->functionEntries[fileOffset];
    // the same function from several sources: an export keeps its name, the size is kept from the exception data
    const bool isExport = type == FunctionEntryType::Export;
    if (!name.empty() && (entry.name.empty() || (isExport && !entry.isExport))) {
        entry.name     = std::string(name); // a string_view is not NUL terminated
        entry.isExport = isExport;
    }
    if (size > 0)
        entry.size = size;
}

void Settings::AddExceptionScopes(uint64 functionFileOffset, uint8 prologSize, uint8 frameRegister, uint8 frameOffset, const std::vector<ExceptionScope>& scopes)
{
    auto& entry           = INTERNAL_SETTINGS->functionEntries[functionFileOffset];
    entry.exceptionScopes = scopes;
    entry.prologSize      = prologSize;
    entry.frameRegister   = frameRegister;
    entry.frameOffset     = frameOffset;
}

void Settings::AddExceptionFunclets(uint64 functionFileOffset, uint8 prologSize, uint8 frameRegister, uint8 frameOffset, const std::vector<ExceptionFunclet>& funclets)
{
    auto& entry             = INTERNAL_SETTINGS->functionEntries[functionFileOffset];
    entry.exceptionFunclets = funclets;
    entry.prologSize        = prologSize;
    entry.frameRegister     = frameRegister;
    entry.frameOffset       = frameOffset;
}

void Settings::AddFunctionChunk(uint64 chunkFileOffset, uint64 size, uint64 functionFileOffset, uint8 functionPrologSize)
{
    auto& entry      = INTERNAL_SETTINGS->functionEntries[functionFileOffset];
    entry.prologSize = functionPrologSize;
    entry.chunks.emplace_back(chunkFileOffset, size);
}

void Settings::AddInstructionBoundary(uint64 fileOffset)
{
    INTERNAL_SETTINGS->instructionBoundaries.push_back(fileOffset);
}

void Settings::SetGlobalOffsetTable(uint64 address)
{
    INTERNAL_SETTINGS->globalOffsetTable = address;
}

void Settings::AddRelocatedPointer(uint64 fileOffset, uint64 value)
{
    INTERNAL_SETTINGS->relocatedPointers[fileOffset] = value;
}

void Settings::AddChainedFixups(BufferView data, uint64 imageBase)
{
    if (!data.IsValid())
        return;
    INTERNAL_SETTINGS->chainedFixups.assign(data.GetData(), data.GetData() + data.GetLength());
    INTERNAL_SETTINGS->chainedFixupsImageBase = imageBase;
}

void Settings::AddDyldBindInfo(BufferView opcodes, const std::vector<uint64>& segmentAddresses, uint8 pointerSize, uint64 imageBase)
{
    if (!opcodes.IsValid() || opcodes.GetLength() == 0 || (pointerSize != 4 && pointerSize != 8))
        return;
    INTERNAL_SETTINGS->dyldBindInfos.push_back({ std::vector<uint8>(opcodes.GetData(), opcodes.GetData() + opcodes.GetLength()), segmentAddresses, pointerSize, imageBase });
}

void Settings::AddBoundSymbol(uint64 rva, std::string_view name)
{
    if (!name.empty())
        INTERNAL_SETTINGS->boundSymbols[rva] = std::string(name);
}

void Settings::AddUninitializedDataZone(uint64 address, uint64 size, DisassemblyLanguage lang, std::string_view name)
{
    if (size == 0)
        return;
    // a file offset of its own after the end of the file, in the order of the zones (the listing places the zones by their offsets)
    const uint64 index =
          std::count_if(INTERNAL_SETTINGS->disassemblyZones.begin(), INTERNAL_SETTINGS->disassemblyZones.end(), [](const auto& zone) {
              return zone.second.isUninitialized;
          });
    const uint64 fileOffset = DISSASM_UNINITIALIZED_ZONES_BASE + index * DISSASM_UNINITIALIZED_ZONE_SPACE;
    AddDataZone(fileOffset, std::min(size, DISSASM_MAX_UNINITIALIZED_ZONE), lang, name);
    auto& zone           = INTERNAL_SETTINGS->disassemblyZones[fileOffset];
    zone.isUninitialized = true;
    zone.virtualAddress  = address;
}

void Settings::AddDataField(uint64 address, uint32 size, DataFieldType type, std::string_view name)
{
    if (size > 0)
        INTERNAL_SETTINGS->dataFields[address] = { size, type, std::string(name) };
}

void Settings::AddArmCodeMode(uint64 fileOffset, ArmCodeMode mode)
{
    INTERNAL_SETTINGS->armCodeModes[fileOffset] = mode;
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
    if (res == INTERNAL_SETTINGS->userDesignedTypes.end()) {
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

void Settings::SetOffsetTranslationList(std::initializer_list<std::string_view> list, Reference<OffsetTranslateInterface> cbk)
{
    if ((!cbk.IsValid()) || (list.size() == 0))
        return;
    INTERNAL_SETTINGS->offsetTranslateCallback = cbk;
}

void Settings::AddArray(uint64 offset, std::string_view name, TypeID type, uint32 count)
{
}
void Settings::AddBidimensionalArray(uint64 offset, std::string_view name, TypeID type, uint32 width, uint32 height)
{
}

SettingsData::SettingsData()
{
    defaultLanguage              = DisassemblyLanguage::Default;
    availableID                  = static_cast<uint32>(InternalDissasmType::CustomTypesStartingId);
    offsetTranslateCallback      = nullptr;
}

bool Settings::SetName(std::string_view name)
{
    return ((SettingsData*) (this->data))->name.Set(name);
}
