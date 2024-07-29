#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace PDF
    {
#pragma pack(push, 2)

        constexpr uint8_t PDF_MAGIC[] = "%PDF-";

        struct Header {
            char identifier[5]; // %PDF-
            uint8 version_1; // 1
            uint8 point; // . 
            uint8 version_N; // N = [0,7]
        };

#pragma pack(pop) // Back to default packing

        class PDFFile : public TypeInterface //, public View::ContainerViewer::EnumerateInterface, public View::ContainerViewer::OpenItemInterface
        {
          public:
            Header header{};

            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

          public:
            PDFFile();
            virtual ~PDFFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "PDF";
            }
            void RunCommand(std::string_view) override
            {
            }

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

        };
        namespace Panels
        {
            class Information : public AppCUI::Controls::TabPage
            {
                Reference<GView::Type::PDF::PDFFile> pdf;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::PDF::PDFFile> pdf);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        } // namespace Panels
    }     // namespace PDF
} // namespace Type
} // namespace GView