#pragma once
// msi.hpp
// Minimal portable MSI wrapper declarations for GView plugin.
// - Very small: only basic validation and heuristics
// - No Windows APIs

#include "GView.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <map>

namespace GView
{
namespace Type
{
    namespace MSI
    {
        // Minimal CFB / MSI helper (interface only; small heuristic implementation in MSIFile.cpp)
        class CFBHelper
        {
          public:
            // Construct from raw buffer
            CFBHelper(const uint8_t* data, size_t size);

            // Quick signature check (CFB magic)
            static bool HasCFBSignature(const uint8_t* data, size_t size);

            // Heuristic: find common stream names (ASCII and SummaryInformation with 0x05 prefix)
            std::vector<std::string> FindLikelyStreamNames() const;

            // Heuristic: search for ASCII/UTF-16 occurrences of a key name
            bool ContainsNameASCII(const std::string& name) const;
            bool ContainsNameUTF16(const std::string& name) const;

          private:
            const uint8_t* data_;
            size_t size_;
        };

        // GView Type wrapper (keeps parsed small state)
        class MSIFile : public TypeInterface
        {
          public:
            MSIFile();
            virtual ~MSIFile();

            // Parse / populate internal minimal structures from the buffer
            bool UpdateFromBuffer(const AppCUI::Utils::BufferView& buf);

            // Basic accessors
            bool IsValid() const;
            const std::vector<std::string>& GetStreams() const;
            const std::map<std::string, std::string>& GetMetadata() const;

            // TypeInterface overrides (minimal)
            std::string_view GetTypeName() override;
            void RunCommand(std::string_view) override;
            bool UpdateKeys(KeyboardControlsInterface* interface) override;

            // Selection zone interface for buffer viewer
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;
            uint32 GetSelectionZonesCount() override;
            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");
                return selectionZoneInterface->GetSelectionZone(index);
            }

            GView::Utils::JsonBuilderInterface* GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;

          private:
            bool valid_;
            std::vector<std::string> streams_;
            std::map<std::string, std::string> metadata_;
        };

    } // namespace MSI
} // namespace Type
} // namespace GView
