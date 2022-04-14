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
            Reference<GView::Utils::DataCache> file;
            Header header;
            InfoHeader infoHeader;
            

          public:
            BMPFile(Reference<GView::Utils::DataCache> file);
            virtual ~BMPFile()
            {
            }

            bool Update();

            std::string_view GetTypeName() override
            {
                return "BMP";
            }

            bool LoadImageToObject(Image& img, uint32 index) override;
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
