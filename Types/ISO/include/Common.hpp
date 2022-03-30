#pragma once

#include "GView.hpp"

#include <array>

namespace GView::Type::ISO
{
#define GET_ENUM_NAME(x) (std::string_view(#x).substr(std::string_view(#x).find_last_of(":") + 1))

enum class Identifier
{
    ECMA_119            = 0,
    ECMA_167            = 1, // ECMA-167 has a different identifier for nearly each volume descriptor.
    ECMA_167_PREVIOUS   = 2, // ECMA-167 Edition 2
    ECMA_167_EXTENDED   = 3,
    ECMA_167_BOOT       = 4,
    ECMO_167_TERMINATOR = 5,
    ECMA_168            = 6,
    UNKNOWN             = 7
};

// clang-format off
static const std::array<std::string_view, 7> signatures
{
    "CD001", // ECMA_119
    "NSR03", // ECMA_167
    "NSR02", // ECMA_167_PREVIOUS
    "BEA01", // ECMA_167_EXTENDED
    "BOOT2", // ECMA_167_BOOT
    "TEA01", // ECMO_167_TERMINATOR
    "CDW02"  // ECMA_168
};
// clang-format on

enum class SectorType : uint8
{
    BootRecord    = 0,
    Primary       = 1,
    Supplementary = 2,
    Partition     = 3,
    SetTerminator = 255
};

static const std::string_view GetSectorTypeName(SectorType sectorType)
{
    switch (sectorType)
    {
    case SectorType::BootRecord:
        return GET_ENUM_NAME(SectorType::BootRecord);
    case SectorType::Primary:
        return GET_ENUM_NAME(SectorType::Primary);
    case SectorType::Supplementary:
        return GET_ENUM_NAME(SectorType::Supplementary);
    case SectorType::Partition:
        return GET_ENUM_NAME(SectorType::Partition);
    case SectorType::SetTerminator:
        return GET_ENUM_NAME(SectorType::SetTerminator);
    default:
        return "UNKNOWN";
    }
}

struct int32_LSB_MSB
{
    int32 LSB;
    int32 MSB;
};

struct int16_LSB_MSB
{
    int16 LSB;
    int16 MSB;
};
} // namespace GView::Type::ISO
