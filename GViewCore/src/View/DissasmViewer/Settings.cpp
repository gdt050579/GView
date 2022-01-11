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
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
    INTERNAL_SETTINGS->collapsed.push_back(false);
}
void Settings::AddArray(uint64 offset, std::string_view name, VariableType type, uint32 count)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::UnidimnsionalArray, name, (uint32) type, count };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
    INTERNAL_SETTINGS->collapsed.push_back(false);
}
void Settings::AddBiDiminesionalArray(uint64 offset, std::string_view name, VariableType type, uint32 width, uint32 height)
{
    INTERNAL_SETTINGS->dissasmTypeMapped[offset] = { InternalDissasmType::BiimensionalArray, name, (uint32) type, width, height };
    INTERNAL_SETTINGS->offsetsToSearch.push_back(offset);
    INTERNAL_SETTINGS->collapsed.push_back(false);
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
    INTERNAL_SETTINGS->collapsed.push_back(false);
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

bool DissasmType::ToBuffer(char* outBuffer, uint32 outBufferSize, BufferView& inputBuffer, bool isCollapsed, int subType) const
{
    uint32 typeSize    = 0;
    bool isSignedValue = false;
    outBuffer[0]       = '\0';
    int written        = 0;

    switch (primaryType)
    {
    case GView::View::DissasmViewer::InternalDissasmType::UInt8:
        typeSize      = 1;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt16:
        typeSize      = 2;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt32:
        typeSize      = 4;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UInt64:
        typeSize      = 8;
        isSignedValue = false;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int8:
        typeSize      = 1;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int16:
        typeSize      = 2;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int32:
        typeSize      = 4;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Int64:
        typeSize      = 8;
        isSignedValue = true;
        break;
    case GView::View::DissasmViewer::InternalDissasmType::AsciiZ:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Utf16Z:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::Utf32Z:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UnidimnsionalArray:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::BiimensionalArray:
        break;
    case GView::View::DissasmViewer::InternalDissasmType::UserDefined:
        if (isCollapsed)
        {
            written = snprintf(outBuffer, outBufferSize - 1, "Structure %s", name.data());
        }
        else
        {
            if (subType == -1)
                written = snprintf(outBuffer, outBufferSize - 1, "Structure %s", name.data());
            else if (subType < 0 || subType > this->internalTypes.size())
            {
                // err
            }
            else
            {
                return this->internalTypes[subType].ToBuffer(outBuffer, outBufferSize, inputBuffer, isCollapsed, subType);
            }
        }
        break;
    default:
        return false;
    }

    if (typeSize > 0)
    {
        char buffer[9];
        memset(buffer, '\0', 9);
        for (uint32 i = 0; i < typeSize; i++)
            buffer[i] = inputBuffer[i]; // TODO: add check

        if (isSignedValue)
        {
            int64 value = *(int64*) buffer;
            written     = snprintf(outBuffer, outBufferSize - 1, "%s: %lli", name.data(), value);
        }
        else
        {
            uint64 value = *(uint64*) buffer;
            written      = snprintf(outBuffer, outBufferSize - 1, "%s: %llu", name.data(), value);
        }
    }

    if (written == 0)
        return false;

    while (written < outBufferSize)
        outBuffer[written++] = ' ';

    return true;
}