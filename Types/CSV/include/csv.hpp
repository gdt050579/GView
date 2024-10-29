#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace CSV
    {
        namespace Panels
        {
            enum class IDs : unsigned char
            {
                Information = 0,
            };
        };

        class CSVFile : public TypeInterface
        {
          private:
            bool hasHeader{ false };
            unsigned int columnsNo{ 0 };
            unsigned int rowsNo{ 0 };
            char separator[2]{""};

            uint64_t panelsMask{ 0 };

          public:
            Reference<GView::Object> obj; // should not be here


          public:
            CSVFile();
            virtual ~CSVFile() = default;

            std::string_view GetTypeName() override;
            void RunCommand(std::string_view) override
            {
            }
            bool UpdateKeys(KeyboardControlsInterface* interface) override
            {
                return true;
            }
            bool Update(Reference<GView::Object> obj);
            bool HasPanel(Panels::IDs id);
            void UpdateBufferViewZones(GView::View::BufferViewer::Settings& settings);
            void UpdateGrid(GView::View::GridViewer::Settings& settings);

          public:
            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

            uint32 GetSelectionZonesCount() override
            {
                CHECK(selectionZoneInterface.IsValid(), 0, "");
                return selectionZoneInterface->GetSelectionZonesCount();
            }

            TypeInterface::SelectionZone GetSelectionZone(uint32 index) override
            {
                static auto d = TypeInterface::SelectionZone{ 0, 0 };
                CHECK(selectionZoneInterface.IsValid(), d, "");
                CHECK(index < selectionZoneInterface->GetSelectionZonesCount(), d, "");

                return selectionZoneInterface->GetSelectionZone(index);
            }

            std::string GetSmartAssistantContext(const std::string_view& prompt, std::string_view displayPrompt) override;
        };

        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
              private:
                Reference<GView::Type::CSV::CSVFile> csv;
                Reference<AppCUI::Controls::ListView> general;

              public:
                Information(Reference<GView::Type::CSV::CSVFile> csv);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override;

              private:
                void UpdateGeneralInformation();
                void RecomputePanelsPositions();
            };
        }; // namespace Panels
    }      // namespace CSV
} // namespace Type
} // namespace GView
