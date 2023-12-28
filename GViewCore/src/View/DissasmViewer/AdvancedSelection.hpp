#pragma once

#include "DissasmDataTypes.hpp"

#include <array>
#include <vector>

namespace GView
{
namespace View
{
    namespace DissasmViewer
    {
        using Utils::INVALID_OFFSET;

        using ZoneStorage = std::vector<char16>;
        struct AdvancedSelectionZone
        {
            LinePosition start, end, originalPoint;
            bool is_alt_selected;
            // TODO: improve the content storage
            // TODO: maybe release the storage if allocated huge chunk
            ZoneStorage content;
        };

        class AdvancedSelection
        {
            static constexpr uint32 MAX_SELECTION_ZONES = 4;
            std::array<AdvancedSelectionZone, MAX_SELECTION_ZONES> zones;
            static constexpr LinePosition INVALID_LINE_POSITION = { static_cast<uint32>(INVALID_OFFSET), static_cast<uint32>(INVALID_OFFSET) };

          public:
            AdvancedSelection();
            void Clear();
            bool Clear(uint32 index);
            inline constexpr bool HasSelection(uint32 index) const
            {
                if (index < MAX_SELECTION_ZONES)
                    return zones[index].start != INVALID_LINE_POSITION;
                return false;
            }
            inline constexpr bool HasAnySelection() const
            {
                for (uint32 index = 0; index < MAX_SELECTION_ZONES; index++)
                    if (zones[index].start != INVALID_LINE_POSITION)
                        return true;
                return false;
            }
            inline constexpr uint32 GetCount() const
            {
                return MAX_SELECTION_ZONES;
            }
            inline LinePosition GetSelectionStart(uint32 index) const
            {
                if (index < MAX_SELECTION_ZONES)
                    return zones[index].start;
                return INVALID_LINE_POSITION;
            }
            inline LinePosition GetSelectionEnd(uint32 index) const
            {
                if (index < MAX_SELECTION_ZONES)
                    return zones[index].end;
                return INVALID_LINE_POSITION;
            }

            ZoneStorage* GetStorage(uint32 index)
            {
                if (index < MAX_SELECTION_ZONES && zones[index].start != INVALID_LINE_POSITION)
                    return &zones[index].content;
                return nullptr;
            }

            bool IsAltPressed(uint32 index) const
            {
                if (index < MAX_SELECTION_ZONES)
                    return zones[index].is_alt_selected;
                return false;
            }

            bool UpdateSelection(uint32 index, LinePosition position, bool ctrl_down, bool alt_down);
            int BeginSelection(LinePosition position, bool ctrl_down, bool alt_down);
            void ClearStorages();
        };
    } // namespace DissasmViewer
} // namespace View
} // namespace GView