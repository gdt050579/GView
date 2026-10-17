#include "DissasmViewer.hpp"
#include <cassert>

using namespace GView::View::DissasmViewer;
using namespace AppCUI::Input;

#define INTERNAL_SETTINGS ((SettingsData*) this->data)

const std::map<std::string_view, InternalDissasmType> types = { { "UInt8", InternalDissasmType::UInt8 },
                                                                { "UInt16", InternalDissasmType::UInt16 },
                                                                { "UInt32", InternalDissasmType::UInt32 },
                                                                { "UInt64", InternalDissasmType::UInt64 },
                                                                { "Int8", InternalDissasmType::Int8 },
                                                                { "Int16", InternalDissasmType::Int16 },
                                                                { "Int32", InternalDissasmType::Int32 },
                                                                { "Int64", InternalDissasmType::Int64 },
                                                                { "OneArray", InternalDissasmType::UnidimnsionalArray },
                                                                { "BiArray", InternalDissasmType::BidimensionalArray } };

TypeID Settings::AddType(std::string_view name, std::string_view definition)
{
    uint32& availableValue = INTERNAL_SETTINGS->availableID;

    DissasmStructureType userType{ InternalDissasmType::UserDefined, name, 0, 0, 0 };

    char* newBuffer = new char[definition.size() + 1];
    memcpy(newBuffer, definition.data(), definition.size());
    newBuffer[definition.size()] = '\0';

    std::deque<char*> localBuffersToDelete;
    localBuffersToDelete.push_back(newBuffer);

    char* start     = newBuffer;
    const char* end = newBuffer + definition.size();

    constexpr uint32 buffer_size = 128;
    char buffer[buffer_size];
    const char* startingNamePtr = start;
    uint32 size                 = 0;
    uint32 arraySizes           = 0;
    DissasmStructureType newType{};

    while (start < end)
    {
        if (*start == ' ')
        {
            *start       = '\0';
            buffer[size] = '\0';
            auto it      = types.find(buffer);
            if (it != types.end())
            {
                newType.primaryType = static_cast<InternalDissasmType>(it->second);
            }
            else
            {
                for (auto entry_buffer : localBuffersToDelete)
                    delete[] entry_buffer;
                return TypeIDError;
            }
            size            = 0;
            startingNamePtr = start + 1;
        }
        else if (*start == '[')
        {
            *start = '\0';
            size   = 0;
            arraySizes++;
        }
        else if (*start == ']')
        {
            buffer[size] = '\0';
            *start       = '\0';
            auto res     = Number::ToUInt32(buffer);
            if (!res.has_value())
            {
                for (auto entry_buffer : localBuffersToDelete)
                    delete[] entry_buffer;
                return TypeIDError;
            }
            else
            {
                if (arraySizes == 1)
                {
                    newType.secondaryType = static_cast<uint32>(newType.primaryType);
                    newType.primaryType   = InternalDissasmType::UnidimnsionalArray;
                    newType.width         = res.value();
                }
                else // bi-dimensional TODO -> possible even more dimensions
                {
                    newType.primaryType = InternalDissasmType::BidimensionalArray;
                    newType.height      = res.value();
                }
            }
        }
        else if (*start == ';')
        {
            arraySizes   = 0;
            *start       = '\0';
            buffer[size] = '\0';
            newType.name = startingNamePtr;

            if (newType.primaryType == InternalDissasmType::UnidimnsionalArray)
            {
                // every cell name is "[index]" plus its terminator: the indexes have a variable number of digits
                size_t cellNamesSize = 1; // a 0 width array still has its terminator
                for (uint32 i = 0; i < newType.width; i++)
                    cellNamesSize += static_cast<size_t>(snprintf(nullptr, 0, "[%u]", i)) + 1u;
                char* arrayCellNames = new char[cellNamesSize];
                localBuffersToDelete.push_back(arrayCellNames);
                char* cellOffset = arrayCellNames;
                *cellOffset      = '\0';

                for (uint32 i = 0; i < newType.width; i++)
                {
                    const size_t remainingSize = cellNamesSize - static_cast<size_t>(cellOffset - arrayCellNames);
                    int res                    = snprintf(cellOffset, remainingSize, "[%u]", i);
                    if (res < 0 || static_cast<size_t>(res) >= remainingSize)
                    {
                        for (auto entry_buffer : localBuffersToDelete)
                            delete[] entry_buffer;
                        return TypeIDError;
                    }

                    auto& internal       = newType.internalTypes.emplace_back();
                    internal.primaryType = static_cast<InternalDissasmType>(newType.secondaryType);
                    internal.name        = cellOffset;
                    cellOffset += res + 1;
                }
            }

            size = 0;
            userType.internalTypes.push_back(newType);
            newType = DissasmStructureType{};
        }
        else if (*start == '\n' || *start == '\r')
        {
            size = 0;
        }
        else
        {
            buffer[size++] = *start;
            if (size >= buffer_size) // capping to buffer_size current string
                size = buffer_size - 1;
        }
        start++;
    }

    for (auto entry_buffer : localBuffersToDelete)
        INTERNAL_SETTINGS->buffersToDelete.push_back(entry_buffer);

    INTERNAL_SETTINGS->userDesignedTypes[availableValue] = userType;
    return availableValue++;
}

uint32 DissasmStructureType::GetExpandedSize() const
{
    uint32 result = 1;
    for (const auto& child : this->internalTypes)
        result += child.GetExpandedSize();
    return result;
}

// UInt8, UInt16, UInt32, UInt64 then Int8, Int16, Int32, Int64 (VariableType has the same values): 1, 2, 4, 8 bytes
static uint64 GetPrimitiveTypeByteSize(uint32 type)
{
    if (type <= static_cast<uint32>(InternalDissasmType::Int64))
        return 1ull << (type % 4u);
    return 0; // AsciiZ, Utf16Z, Utf32Z: the size depends on the data
}

uint64 DissasmStructureType::GetByteSize() const
{
    switch (primaryType)
    {
    case InternalDissasmType::UInt8:
    case InternalDissasmType::UInt16:
    case InternalDissasmType::UInt32:
    case InternalDissasmType::UInt64:
    case InternalDissasmType::Int8:
    case InternalDissasmType::Int16:
    case InternalDissasmType::Int32:
    case InternalDissasmType::Int64:
        return GetPrimitiveTypeByteSize(static_cast<uint32>(primaryType));
    case InternalDissasmType::UnidimnsionalArray:
        if (internalTypes.empty()) // Settings::AddArray: only the cell type and the count
            return static_cast<uint64>(width) * GetPrimitiveTypeByteSize(secondaryType);
        break; // the cells (Settings::AddType)
    case InternalDissasmType::BidimensionalArray:
        return static_cast<uint64>(width) * height * GetPrimitiveTypeByteSize(secondaryType);
    case InternalDissasmType::UserDefined:
        break; // the fields
    default:
        return 0;
    }

    uint64 result = 0;
    for (const auto& child : this->internalTypes)
        result += child.GetByteSize();
    return result;
}
