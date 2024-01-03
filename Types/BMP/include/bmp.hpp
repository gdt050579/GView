#pragma once

#include "GView.hpp"

namespace GView
{
namespace Type
{
    namespace BMP
    {
#pragma pack(push, 2)
        constexpr uint16 BITMAP_WINDOWS_MAGIC             = 0x4D42;
        constexpr uint32 BITMAP_COMPRESSION_METHID_BI_RGB = 0;

        struct Header
        {
            uint16 magic;
            uint32 size;
            uint16 reserved_1;
            uint16 reserved_2;
            uint32 pixelOffset;
        };
        struct InfoHeader
        {
            uint32 sizeOfHeader;
            uint32 width;
            uint32 height;
            uint16 colorPlanes;
            uint16 bitsPerPixel;
            uint32 comppresionMethod;
            uint32 imageSize;
            uint32 horizontalResolution;
            uint32 verticalResolution;
            uint32 numberOfColors;
            uint32 numberOfImportantColors;
        };

#pragma pack(pop) // Back to 4 byte packing.

        class BMPFile : public TypeInterface, public View::ImageViewer::LoadImageInterface
        {
          public:
            Header header{};
            InfoHeader infoHeader{};

            Reference<GView::Utils::SelectionZoneInterface> selectionZoneInterface;

          public:
            BMPFile();
            virtual ~BMPFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "BMP";
            }
            void RunCommand(std::string_view) override
            {
            }

            bool LoadImageToObject(Image& img, uint32 index) override;

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
                Reference<GView::Type::BMP::BMPFile> bmp;
                Reference<AppCUI::Controls::ListView> general;
                Reference<AppCUI::Controls::ListView> issues;

                void UpdateGeneralInformation();
                void UpdateIssues();
                void RecomputePanelsPositions();

              public:
                Information(Reference<GView::Type::BMP::BMPFile> bmp);

                void Update();
                virtual void OnAfterResize(int newWidth, int newHeight) override
                {
                    RecomputePanelsPositions();
                }
            };
        }; // namespace Panels
    }      // namespace BMP
} // namespace Type
} // namespace GView
