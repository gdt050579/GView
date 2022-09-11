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

    DissasmType userType{ InternalDissasmType::UserDefined, name, 0, 0, 0, {} };

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
    DissasmType newType{};

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
                assert(newType.width < 100); // TODO: fix for more numbers
                char* arrayCellNames = new char[5u * newType.width];
                localBuffersToDelete.push_back(arrayCellNames);
                char* cellOffset = arrayCellNames;
                *cellOffset      = '\0';

                for (uint32 i = 0; i < newType.width; i++)
                {
                    int res = snprintf(cellOffset, 5, "[%u]", i);
                    if (res < 0)
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
            newType = DissasmType{};
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

    INTERNAL_SETTINGS->userDeginedTypes[availableValue] = userType;
    return availableValue++;
}

uint32 DissasmType::GetExpandedSize() const
{
    uint32 result = 1;
    for (const auto& child : this->internalTypes)
        result += child.GetExpandedSize();
    return result;
}